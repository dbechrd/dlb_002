#scope_module

ChannelPacketData :: struct {
    Flags :: enum_flags u8 {
        Initialized;
        BlockMessage;
        FailedToSerialize;
    }

    MessageData :: struct {
        messages: [] *Message;
    }

    BlockData :: struct {
        message: *BlockMessage;
        fragmentData: *u8;
        messageId: u16;
        fragmentId: u16;
        fragmentSize: u16;
        numFragments: u16;
        messageType: int;
    };

    channelIndex: u16;
    flags: Flags;
    union :: {
        message: MessageData;
        block: BlockData;
    };
};

channel_packet_data_init :: (packetData: *ChannelPacketData) {
    packetData.flags &= .Initialized;
}

channel_packet_data_free :: (packetData: *ChannelPacketData, messageFactory: *MessageFactory) {
    assert(packetData.flags & .Initialized);

    if packetData.flags & .BlockMessage {
        if packetData.block.message {
            message_factory_release_message(messageFactory, packetData.block.message);
            packetData.block.message = null;
        }
        free(packetData.block.fragmentData);
    } else {
        for packetData.message.messages {
            if it != null {
                message_factory_release_message(messageFactory, it);
            }
        }
        array_reset(*packetData.message.messages);
    }
}

channel_packet_data_serialize :: (packetData: *ChannelPacketData, stream: *Stream, messageFactory: *MessageFactory, channelConfigs: ChannelConfig[MaxChannels], numChannels: int) -> bool {
    assert(packetData.flags & .Initialized);

    #if YOJIMBO_DEBUG_MESSAGE_BUDGET {
        startBits := stream_get_bits_processed(stream);
    }

    if numChannels > 1 {
        serialize_int(stream, packetData.channelIndex, 0, numChannels - 1);
    } else {
        // TODO(dlb)[cleanup]: This should always be true in Jai.
        assert(packetData.channelIndex == 0);
    }

    channelConfig := channelConfigs[channelIndex];

    blockMessage: bool;
    serialize_bool(stream, blockMessage);

    if blockMessage {
        packetData.flags &= .BlockMessage;

        if channelConfig.disableBlocks {
            return false;
        }

        if !serialize_block_fragment(stream, messageFactory, block, channelConfig) {
            return false;
        }
    } else {
        if channelConfig.type == {
            case .ReliableOrdered;
                if !serialize_ordered_messages(stream, messageFactory, message.numMessages, message.messages, channelConfig.maxMessagesPerPacket) {
                    packetData.flags &= .FailedToSerialize;
                    return true;
                }
            case .UnreliableUnordered;
                if !serialize_unordered_messages(stream, messageFactory, message.numMessages, message.messages, channelConfig.maxMessagesPerPacket, channelConfig.maxBlockSize) {
                    packetData.flags &= .FailedToSerialize;
                    return true;
                }
        }

        #if YOJIMBO_DEBUG_MESSAGE_BUDGET {
            if channelConfig.packetBudget > 0 {
                assert(stream_get_bits_processed(stream) - startBits <= channelConfig.packetBudget * 8);
            }
        }
    }

    return true;
}

#scope_file

serialize_messages :: ($ordered: bool, stream: *Stream, messageFactory: *MessageFactory, numMessages: *int, messages: *[] *Message, maxMessagesPerPacket: int, maxBlockSize: int) -> bool {
    maxMessageType := message_factory_get_num_types(messageFactory) - 1;

    hasMessages := stream.isWriting && numMessages.* != null;

    serialize_bool(stream, hasMessages);

    if hasMessages {
        serialize_int(stream, numMessages.*, 1, maxMessagesPerPacket);

        messageTypes: [] int = NewArray(numMessages.*, int,, temp);
        #if ordered {
            messageIds: [] u16 = NewArray(numMessages.*, u16,, temp);
        }

        if stream::isWriting {
            assert(messages != null);

            for 0..numMessages.*-1 {
                assert(messages.*[it] != null);
                messageTypes[it] = message_get_type(messages[it]);
                #if ordered {
                    messageIds[it] = message_get_id(messages[it]);
                }
            }
        } else {
            messages.* = NewArray(numMessages.*, *Message);
        }

        #if ordered {
            serialize_bits(stream, messageIds[0], 16);
            for 1..numMessages.*-1 {
                serialize_sequence_relative(stream, messageIds[it-1], messageIds[it]);
            }
        }

        for 0..numMessages.*-1 {
            if maxMessageType > 0 {
                serialize_int(stream, messageTypes[it], 0, maxMessageType);
            }

            if stream.isReading {
                messages.*[it] = message_factory_create_message(messageFactory, messageTypes[it]);

                if messages.*[it] == null {
                    yojimbo_log(.ERROR, "error: failed to create message of type %d (serialize_messages[ordered = %]\n", messageTypes[it], ordered);
                    return false;
                }

                #if ordered {
                    message_set_id(messages.*[it], messageIds[it]);
                }
            }

            assert(messages.*[it] != null);

            if !message_serialize_internal(messages.*[it], stream) {
                yojimbo_log(.ERROR, "error: failed to serialize message of type %d (serialize_messages[ordered = %])\n", messageTypes[it], ordered);
                return false;
            }

            #if !ordered {
                if message_is_block_message(messages.*[it]) {
                    blockMessage := cast(*BlockMessage) messages.*[it];
                    if !serialize_message_block(stream, messageFactory, blockMessage, maxBlockSize) {
                        yojimbo_log(.ERROR, "error: failed to serialize unordered block message (serialize_messages)\n");
                        return false;
                    }
                }
            }
        }
    }

    return true;
}

serialize_block_fragment :: ( Stream & stream, messageFactory: *MessageFactory, block: *ChannelPacketData.BlockData, channelConfig: *ChannelConfig) -> bool {
    maxMessageType := message_factory_get_num_types(messageFactory) - 1;

    if stream.isReading {
        block.message = null;
        block.fragmentData = null;
    }

    serialize_bits(stream, block.messageId, 16);

    max_fragments_per_block := channel_config_get_max_fragments_per_block(channelConfig);
    if max_fragments_per_block > 1 {
        serialize_int(stream, block.numFragments, 1, max_fragments_per_block);
    } else {
        if stream.isReading {
            block.numFragments = 1;
        }
    }

    if block.numFragments > 1 {
        serialize_int(stream, block.fragmentId, 0, block.numFragments - 1);
    } else {
        if stream.isReading {
            block.fragmentId = 0;
        }
    }

    serialize_int(stream, block.fragmentSize, 1, channelConfig.blockFragmentSize);

    if stream.isReading {
        block.fragmentData = NewArray(block.fragmentSize, u8);

        if block.fragmentData.data == null {
            yojimbo_log(.ERROR, "error: failed to serialize block fragment (serialize_block_fragment)\n");
            return false;
        }
    }

    serialize_bytes(stream, block.fragmentData, block.fragmentSize);

    if block.fragmentId == 0 {
        // block message

        if maxMessageType > 0 {
            serialize_int(stream, block.messageType, 0, maxMessageType);
        } else {
            block.messageType = 0;
        }

        if stream.isReading {
            message := message_factory_create_message(messageFactory, block.messageType);

            if message == null {
                yojimbo_log(.ERROR, "error: failed to create block message type %d (serialize_block_fragment)\n", block.messageType);
                return false;
            }

            if !message_is_block_message(message) {
                yojimbo_log(.ERROR, "error: received block fragment attached to non-block message (serialize_block_fragment)\n");
                return false;
            }

            block.message = cast(*BlockMessage) message;
        }

        assert(block.message != null);

        if !block_message_serialize_internal(block.message, stream) {
            yojimbo_log(.ERROR, "error: failed to serialize block message of type %d (serialize_block_fragment)\n", block.messageType);
            return false;
        }
    }

    return true;
}