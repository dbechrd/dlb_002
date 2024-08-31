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
        message: *Message;
        fragmentData: *u8;  // TODO(dlb): fragmentData: [] u8 and get rid of `fragmentSize`
        messageId: u16;
        fragmentId: u16;
        fragmentSize: u16;
        numFragments: u16;
        messageType: int;
    }

    channelIndex: u16;
    flags: Flags;
    union {
        message: MessageData;
        block: BlockData;
    }
};

channel_packet_data_init :: (packetData: *ChannelPacketData) {
    packetData.flags &= .Initialized;
}

channel_packet_data_free :: (packetData: *ChannelPacketData, messageFactory: *MessageFactory) {
    assert(packetData.flags & .Initialized);

    if packetData.flags & .BlockMessage {
        if packetData.block.message {
            free(packetData.block.message);
            packetData.block.message = null;
        }
        free(packetData.block.fragmentData);
    } else {
        for packetData.message.messages {
            if it != null {
                free(messageFactory, it);
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
                if !serialize_ordered_messages(stream, messageFactory, *message.messages, channelConfig.maxMessagesPerPacket) {
                    packetData.flags &= .FailedToSerialize;
                    return true;
                }
            case .UnreliableUnordered;
                if !serialize_unordered_messages(stream, messageFactory, *message.messages, channelConfig.maxMessagesPerPacket, channelConfig.maxBlockSize) {
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

serialize_ordered_messages :: #bake_arguments serialize_messages(ordered = true, maxBlockSize = 0);
serialize_unordered_messages :: #bake_arguments serialize_messages(ordered = false);

// NOTE: maxBlockSize is unused for ordered messages
serialize_messages :: (stream: *Stream, messageFactory: *MessageFactory, messages: *[] *Message, maxMessagesPerPacket: int, maxBlockSize: int, $ordered: bool) -> bool {
    hasMessages := stream.isWriting && messages.count > 0;
    serialize_bool(stream, hasMessages);
    if !hasMessages {
        return true;
    }

    messageCount := messages.count;
    serialize_int(stream, messageCount, 1, maxMessagesPerPacket);
    if stream.isReading {
        messages.* = NewArray(messageCount, *Message);
    }

    messageTypes: [] int = NewArray(messages.count, int,, temp);
    #if ordered {
        messageIds: [] u16 = NewArray(messages.count, u16,, temp);
    }

    if stream.isWriting {
        for 0..messages.count-1 {
            assert(messages.*[it] != null);
            messageTypes[it] = messages[it].type;
            #if ordered {
                messageIds[it] = messages[it].id;
            }
        }
    }

    #if ordered {
        serialize_bits(stream, messageIds[0], 16);
        for 1..messages.count-1 {
            serialize_sequence_relative(stream, messageIds[it-1], messageIds[it]);
        }
    }

    for 0..messages.count-1 {
        maxMessageType := messageFactory.messageTypes.count - 1;
        serialize_int(stream, messageTypes[it], 0, maxMessageType);

        if stream.isReading {
            messages.*[it] = message_factory_create_message(messageFactory, messageTypes[it]);

            if messages.*[it] == null {
                yojimbo_log(.ERROR, "error: failed to create message of type %d (serialize_messages[ordered = %]\n", messageTypes[it], ordered);
                return false;
            }

            #if ordered {
                messages.*[it].id = messageIds[it];
            }
        }

        assert(messages.*[it] != null);

        if !message_factory.serialize(stream, messages.*[it]) {
            yojimbo_log(.ERROR, "error: failed to serialize message of type %d (serialize_messages[ordered = %])\n", messageTypes[it], ordered);
            return false;
        }

        #if !ordered {
            if !serialize_message_block(stream, messageFactory, messages.*[it], maxBlockSize) {
                yojimbo_log(.ERROR, "error: failed to serialize unordered block message (serialize_messages)\n");
                return false;
            }
        }
    }
}

serialize_block_fragment :: (stream: *Stream, messageFactory: *MessageFactory, block: *ChannelPacketData.BlockData, channelConfig: *ChannelConfig) -> bool {
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

        maxMessageType := messageFactory.messageTypes.count - 1;
        serialize_int(stream, block.messageType, 0, maxMessageType);

        if stream.isReading {
            block.message = message_factory_create_message(messageFactory, block.messageType);
        }

        assert(block.message != null);

        if !block_message_serialize_internal(block.message, stream) {
            yojimbo_log(.ERROR, "error: failed to serialize block message of type %d (serialize_block_fragment)\n", block.messageType);
            return false;
        }
    }

    return true;
}