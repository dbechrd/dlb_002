#scope_module

/*
Configures connection properties and the set of channels for sending and receiving messages.
Specifies the maximum packet size to generate, and the number of message channels, and the per-channel configuration data. See ChannelConfig for details.
Typically configured as part of a ClientServerConfig which is passed into Client and Server constructors.
*/
ConnectionConfig :: struct {
    numChannels   : int                         = 1;         // Number of message channels in [1,MaxChannels]. Each message channel must have a corresponding configuration below.
    maxPacketSize : int                         = 8 * 1024;  // The maximum size of packets generated to transmit messages between client and server (bytes).
    channel       : [MaxChannels] ChannelConfig;             // Per-channel configuration. See ChannelConfig for details.
}

ConnectionErrorLevel :: enum {
    None = 0,             // No error. All is well.
    ChannelError,         // A channel is in an error state.
    MessageFactoryError,  // The message factory is in an error state.
    ReadPacketFailure,    // Failed to read packet. Received an invalid packet?
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
    messageFactory : *MessageFactory;
    channelEntries : [] ChannelPacketData;
}

connection_packet_free(using connectionPacket: *ConnectionPacket) {
    if messageFactory {
        for 0..channelEntries.count-1 {
            channel_packet_data_free(it, messageFactory);
        }
        array_reset(*channelEntries);
        messageFactory = null;
    }
}

connection_packet_allocate_channel_data :: (using connectionPacket: *ConnectionPacket, msgFactory: *MessageFactory, numEntries: int) {
    assert(numEntries > 0);
    assert(numEntries <= MaxChannels);

    messageFactory = msgFactory;
    channelEntries = NewArray(numEntries, channelPacketData);
}

connection_packet_serialize :: (using connectionPacket: *ConnectionPacket, stream: *$S, messageFactory: *MessageFactory, connectionConfig: *ConnectionConfig) -> bool {
    serialize_int(stream, channelEntries.count, 0, connectionConfig.numChannels);
    #if YOJIMBO_DEBUG_MESSAGE_BUDGET {
        assert(stream_get_bits_processed(stream) <= ConservativePacketHeaderBits);
    }
    if channelEntries.count > 0 {
        if stream.isReading {
            connection_packet_allocate_channel_data(connectionPacket, messageFactory, channelEntries.count);
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
                UnreliableUnorderedChannel
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

static int WritePacket( void * context,
                        MessageFactory & messageFactory,
                        const ConnectionConfig & connectionConfig,
                        ConnectionPacket & packet,
                        uint8_t * buffer,
                        int bufferSize )
{
    WriteStream stream( buffer, bufferSize );

    stream.SetContext( context );

    stream.SetAllocator( &messageFactory.GetAllocator() );

    if ( !packet.SerializeInternal( stream, messageFactory, connectionConfig ) )
    {
        yojimbo_printf( YOJIMBO_LOG_LEVEL_ERROR, "error: serialize connection packet failed (write packet)\n" );
        return 0;
    }

    stream.Flush();

    return stream.GetBytesProcessed();
}

bool Connection::GeneratePacket( void * context, uint16_t packetSequence, uint8_t * packetData, int maxPacketBytes, int & packetBytes )
{
    ConnectionPacket packet;

    if ( m_connectionConfig.numChannels > 0 )
    {
        int numChannelsWithData = 0;
        bool channelHasData[MaxChannels];
        memset( channelHasData, 0, sizeof( channelHasData ) );
        ChannelPacketData channelData[MaxChannels];

        int availableBits = maxPacketBytes * 8 - ConservativePacketHeaderBits;

        for ( int channelIndex = 0; channelIndex < m_connectionConfig.numChannels; ++channelIndex )
        {
            int packetDataBits = channels[channelIndex]->GetPacketData( context, channelData[channelIndex], packetSequence, availableBits );
            if ( packetDataBits > 0 )
            {
                availableBits -= ConservativeChannelHeaderBits;
                availableBits -= packetDataBits;
                channelHasData[channelIndex] = true;
                numChannelsWithData++;
            }
        }

        if ( numChannelsWithData > 0 )
        {
            if ( !packet.AllocateChannelData( *m_messageFactory, numChannelsWithData ) )
            {
                yojimbo_printf( YOJIMBO_LOG_LEVEL_ERROR, "error: failed to allocate channel data\n" );
                return false;
            }

            int index = 0;

            for ( int channelIndex = 0; channelIndex < m_connectionConfig.numChannels; ++channelIndex )
            {
                if ( channelHasData[channelIndex] )
                {
                    memcpy( &packet.channelEntries[index], &channelData[channelIndex], sizeof( ChannelPacketData ) );
                    index++;
                }
            }
        }
    }

    packetBytes = WritePacket( context, *m_messageFactory, m_connectionConfig, packet, packetData, maxPacketBytes );

    return true;
}

static bool ReadPacket( void * context,
                        MessageFactory & messageFactory,
                        const ConnectionConfig & connectionConfig,
                        ConnectionPacket & packet,
                        const uint8_t * buffer,
                        int bufferSize )
{
    assert(buffer );
    assert(bufferSize > 0 );

    ReadStream stream( buffer, bufferSize );

    stream.SetContext( context );

    stream.SetAllocator( &messageFactory.GetAllocator() );

    if ( !packet.SerializeInternal( stream, messageFactory, connectionConfig ) )
    {
        yojimbo_printf( YOJIMBO_LOG_LEVEL_ERROR, "error: serialize connection packet failed (read packet)\n" );
        return false;
    }

    return true;
}

bool Connection::ProcessPacket( void * context, uint16_t packetSequence, const uint8_t * packetData, int packetBytes )
{
    if ( m_errorLevel != CONNECTION_ERROR_NONE )
    {
        yojimbo_printf( YOJIMBO_LOG_LEVEL_DEBUG, "failed to read packet because connection is in error state\n" );
        return false;
    }

    ConnectionPacket packet;

    if ( !ReadPacket( context, *m_messageFactory, m_connectionConfig, packet, packetData, packetBytes ) )
    {
        yojimbo_printf( YOJIMBO_LOG_LEVEL_ERROR, "error: failed to read packet\n" );
        m_errorLevel = CONNECTION_ERROR_READ_PACKET_FAILED;
        return false;
    }

    for ( int i = 0; i < packet.numChannelEntries; ++i )
    {
        const int channelIndex = packet.channelEntries[i].channelIndex;
        assert(channelIndex >= 0 );
        assert(channelIndex <= m_connectionConfig.numChannels );
        channels[channelIndex]->ProcessPacketData( packet.channelEntries[i], packetSequence );
        if ( channels[channelIndex]->GetErrorLevel() != CHANNEL_ERROR_NONE )
        {
            yojimbo_printf( YOJIMBO_LOG_LEVEL_DEBUG, "failed to read packet because channel %d is in error state\n", channelIndex );
            return false;
        }
    }

    return true;
}

void Connection::ProcessAcks( const uint16_t * acks, int numAcks )
{
    for ( int i = 0; i < numAcks; ++i )
    {
        for ( int channelIndex = 0; channelIndex < m_connectionConfig.numChannels; ++channelIndex )
        {
            channels[channelIndex]->ProcessAck( acks[i] );
        }
    }
}

void Connection::AdvanceTime( double time )
{
    for ( int i = 0; i < m_connectionConfig.numChannels; ++i )
    {
        channels[i]->AdvanceTime( time );

        if ( channels[i]->GetErrorLevel() != CHANNEL_ERROR_NONE )
        {
            m_errorLevel = CONNECTION_ERROR_CHANNEL;
            return;
        }
    }
    if ( m_allocator->GetErrorLevel() != ALLOCATOR_ERROR_NONE )
    {
        m_errorLevel = CONNECTION_ERROR_ALLOCATOR;
        return;
    }
    if ( m_messageFactory->GetErrorLevel() != .None )
    {
        m_errorLevel = CONNECTION_ERROR_MESSAGE_FACTORY;
        return;
    }
}