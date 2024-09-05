#scope_module

ConnectionErrorLevel :: enum {
    None;                 // No error. All is well.
    ChannelError;         // A channel is in an error state.
    ReadPacketFailed;     // Failed to read packet. Received an invalid packet?
}

/*
Sends and receives messages across a set of user defined channels.
*/
Connection :: struct {
    messageFactory   : *MessageFactory;         // Message factory for creating and destroying messages.
    connectionConfig : ConnectionConfig;        // Connection configuration.
    errorLevel       : ConnectionErrorLevel;    // The connection error level.
    channels         : [MaxChannels] *Channel;  // Array of connection channels. Effective array size is connectionConfig.numChannels.
};

ConnectionPacket :: struct {
    channelEntries : [] ChannelPacketData;
}

connection_packet_free :: (using connectionPacket: *ConnectionPacket) {
    for 0..channelEntries.count-1 {
        channel_packet_data_free(it);
    }
    array_reset(*channelEntries);
}

connection_packet_allocate_channel_data :: (using connectionPacket: *ConnectionPacket, numEntries: int) {
    assert(numEntries > 0);
    assert(numEntries <= MaxChannels);

    channelEntries = NewArray(numEntries, channelPacketData);
}

connection_packet_serialize :: (using connectionPacket: *ConnectionPacket, stream: *$S, messageFactory: *MessageFactory, connectionConfig: *ConnectionConfig) -> bool {
    serialize_int(stream, channelEntries.count, 0, connectionConfig.numChannels);
    #if YOJIMBO_DEBUG_MESSAGE_BUDGET {
        assert(stream_get_bits_processed(stream) <= ConservativePacketHeaderBits);
    }
    if channelEntries.count > 0 {
        if stream.isReading {
            connection_packet_allocate_channel_data(connectionPacket, channelEntries.count);
            // TODO(dlb): What is the point of this? Why would this flag ever be set here?
            for channelEntries {
                assert(!(it.flags & .FailedToSerialize));
            }
        }
        for channelEntries {
            assert(!(it.flags & .FailedToSerialize));
            if !channel_packet_data_serialize(it, stream, messageFactory, connectionConfig.channel, connectionConfig.numChannels) {
                yojimbo_log(.ERROR, "error: failed to serialize channel %\n", i);
                return false;
            }
        }
    }
    return true;
}

// ------------------------------------------------------------------------------

connection_init :: (using connection: *Connection, _messageFactory: *MessageFactory, _connectionConfig: *ConnectionConfig, time: Apollo_Time) {
    assert(_connectionConfig.numChannels >= 1);
    assert(_connectionConfig.numChannels <= MaxChannels);

    messageFactory = _messageFactory;
    connectionConfig = _connectionConfig.*;

    for 0..connectionConfig.numChannels-1 {
        if #complete connectionConfig.channel[it].type == {
            case .ReliableOrdered;
                channels[it] = New(ReliableOrderedChannel);
                reliable_ordered_channel_init(channels[it], messageFactory, connectionConfig.channel[it], it, time);
            case .UnreliableUnordered;
                channels[it] = New(UnreliableUnorderedChannel);
                unreliable_unordered_channel_init(channels[it], messageFactory, connectionConfig.channel[it], it, time);
        }
    }
}

connection_free :: (using connection: *Connection) {
    connection_reset(connection);
    for 0..connectionConfig.numChannels-1 {
        free(channels[it]);
    }
}

connection_reset :: (using connection: *Connection) {
    errorLevel = .None;
    for 0..connectionConfig.numChannels-1 {
        channel_reset(channels[it]);
    }
}

connection_can_send_message :: (using connection: *Connection, channelIndex: int) -> bool {
    assert(channelIndex >= 0);
    assert(channelIndex < connectionConfig.numChannels);

    return channel_can_send_message(channels[channelIndex]);
}

connection_has_messages_to_send :: (using connection: *Connection, channelIndex: int) -> bool {
    assert(channelIndex >= 0);
    assert(channelIndex < connectionConfig.numChannels);

    return channel_has_messages_to_send(channels[channelIndex]);
}

connection_send_message :: (using connection: *Connection, channelIndex: int, message: *Message) {
    assert(channelIndex >= 0);
    assert(channelIndex < connectionConfig.numChannels);

    return channel_send_message(channels[channelIndex], message);
}

connection_receive_message :: (using connection: *Connection, channelIndex: int) -> *Message {
    assert(channelIndex >= 0);
    assert(channelIndex < connectionConfig.numChannels);

    return channel_receive_message(channels[channelIndex]);
}

// TODO(dlb): Use multiple return values to replace packetBytes OUT param
connection_generate_packet :: (using connection: *Connection, packetSequence: u16, packetData: [] u8, packetBytes: *int) -> bool {
    // NOTE(dlb): This was a static function in the C++ version, I'm not sure why. We could probably inline this logic.
    connection_write_packet :: (using connection: *Connection, packet: *ConnectionPacket, buffer: [] u8) -> int {
        stream: WriteStream;
        stream_init(*stream, buffer);

        if !connection_packet_serialize(packet, *stream, messageFactory, *connectionConfig) {
            yojimbo_log(.ERROR, "error: serialize connection packet failed (write packet)\n");
            return 0;
        }

        stream_flush(*stream);
        bytes := stream_get_bytes_processed(*stream);
        return bytes;
    }

    packet: ConnectionPacket;

    if connectionConfig.numChannels > 0 {
        numChannelsWithData := 0;
        channelHasData: [MaxChannels] bool;
        channelData: [MaxChannels] ChannelPacketData;

        availableBits := packetData.count * 8 - ConservativePacketHeaderBits;

        for 0..connectionConfig.numChannels-1 {
            packetDataBits := channel_generate_packet_data(channels[channelIndex], *channelData[channelIndex], packetSequence, availableBits);
            if packetDataBits > 0 {
                availableBits -= ConservativeChannelHeaderBits;
                availableBits -= packetDataBits;
                channelHasData[channelIndex] = true;
                numChannelsWithData += 1;
            }
        }

        if numChannelsWithData > 0 {
            connection_packet_allocate_channel_data(packet, numChannelsWithData);
            entryCount := 0;
            for 0..connectionConfig.numChannels-1 {
                if channelHasData[it] {
                    packet.channelEntries[entryCount] = channelData[it];
                    entryCount += 1;
                }
            }
        }
    }

    packetBytes.* = connection_write_packet(connection, packet, packetData);
    return true;
}

connection_process_packet :: (using connection: *Connection, packetSequence: u16, packetData: [] u8) -> bool {
     // NOTE(dlb): This was a static function in the C++ version, I'm not sure why. We could probably inline this logic.
    connection_read_packet :: (using connection: *Connection, packet: *ConnectionPacket, buffer: [] u8) -> bool {
        stream: ReadStream;
        stream_init(*stream, buffer);

        if !connection_packet_serialize(packet, *stream, messageFactory, *connectionConfig) {
            yojimbo_log(.ERROR, "error: serialize connection packet failed (read packet)\n");
            return false;
        }
        return true;
    }

    if errorLevel != .None {
        yojimbo_log(.VERBOSE, "failed to read packet because connection is in error state\n");
        return false;
    }

    packet: ConnectionPacket;

    if !connection_read_packet(connection, *packet, packetData) {
        yojimbo_log(.ERROR, "error: failed to read packet\n");
        errorLevel = .ReadPacketFailed;
        return false;
    }

    for * packet.channelEntries {
        assert(it.channelIndex >= 0 );
        assert(it.channelIndex <= m_connectionConfig.numChannels );
        channel_process_packet_data(channels[it.channelIndex], it, packetSequence);
        if channels[it.channelIndex].errorLevel != .None {
            yojimbo_log(.VERBOSE, "failed to read packet because channel % is in error state\n", it.channelIndex);
            return false;
        }
    }

    return true;
}

connection_process_acks :: (using connection: *Connection, acks: [] u16) {
    for ack: acks {
        for channelIndex: 0..connectionConfig.numChannels-1 {
            channel_process_ack(channels[channelIndex], ack);
        }
    }
}

connection_advance_time :: (using connection: *Connection, time: Apollo_Time) {
    for 0..connectionConfig.numChannels-1 {
        channel_advance_time(channels[it], time);

        if channels[it].errorLevel != .None {
            errorLevel = .ChannelError;
            return;
        }
    }
}