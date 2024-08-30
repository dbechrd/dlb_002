#scope_module

/**
    Messages sent across this channel are not guaranteed to arrive, and may be received in a different order than they were sent.
    This channel type is best used for time critical data like snapshots and object state.
    */

class UnreliableUnorderedChannel : public Channel
{
public:
    #as using base: Channel;
    base.config.type = .UnreliableUnordered;

    /**
        Reliable ordered channel constructor.
        @param allocator The allocator to use.
        @param messageFactory Message factory for creating and destroying messages.
        @param config The configuration for this channel.
        @param channelIndex The channel index in [0,numChannels-1].
        */

    UnreliableUnorderedChannel( Allocator & allocator, MessageFactory & messageFactory, const ChannelConfig & config, int channelIndex, double time );

    /**
        Unreliable unordered channel destructor.
        Any messages still in the send or receive queues will be released.
        */

    ~UnreliableUnorderedChannel();

    void Reset();

    bool CanSendMessage() const;

    bool HasMessagesToSend() const;

    void SendMessage( Message * message, void *context );

    Message * ReceiveMessage();

    void AdvanceTime( double time );

    int GetPacketData( void *context, ChannelPacketData & packetData, uint16_t packetSequence, int availableBits );

    void ProcessPacketData( const ChannelPacketData & packetData, uint16_t packetSequence );

    void ProcessAck( uint16_t ack );

protected:

    Queue<Message*> * m_messageSendQueue;                   ///< Message send queue.
    Queue<Message*> * m_messageReceiveQueue;                ///< Message receive queue.

private:

    UnreliableUnorderedChannel( const UnreliableUnorderedChannel & other );

    UnreliableUnorderedChannel & operator = ( const UnreliableUnorderedChannel & other );
};



/**
    Messages sent across this channel are not guaranteed to arrive, and may be received in a different order than they were sent.
    This channel type is best used for time critical data like snapshots and object state.
    */

class UnreliableUnorderedChannel : public Channel
{
public:

    /**
        Reliable ordered channel constructor.
        @param allocator The allocator to use.
        @param messageFactory Message factory for creating and destroying messages.
        @param config The configuration for this channel.
        @param channelIndex The channel index in [0,numChannels-1].
        */

    UnreliableUnorderedChannel( Allocator & allocator, MessageFactory & messageFactory, const ChannelConfig & config, int channelIndex, double time );

    /**
        Unreliable unordered channel destructor.
        Any messages still in the send or receive queues will be released.
        */

    ~UnreliableUnorderedChannel();

    void Reset();

    bool CanSendMessage() const;

    bool HasMessagesToSend() const;

    void SendMessage( Message * message, void *context );

    Message * ReceiveMessage();

    void AdvanceTime( double time );

    int GetPacketData( void *context, ChannelPacketData & packetData, uint16_t packetSequence, int availableBits );

    void ProcessPacketData( const ChannelPacketData & packetData, uint16_t packetSequence );

    void ProcessAck( uint16_t ack );

protected:

    Queue<Message*> * m_messageSendQueue;                   ///< Message send queue.
    Queue<Message*> * m_messageReceiveQueue;                ///< Message receive queue.

private:

    UnreliableUnorderedChannel( const UnreliableUnorderedChannel & other );

    UnreliableUnorderedChannel & operator = ( const UnreliableUnorderedChannel & other );
};


UnreliableUnorderedChannel::UnreliableUnorderedChannel( Allocator & allocator,
                                                        MessageFactory & messageFactory,
                                                        const ChannelConfig & config,
                                                        int channelIndex,
                                                        double time )
    : Channel( allocator,
                messageFactory,
                config,
                channelIndex,
                time )
{
    yojimbo_assert( config.type == CHANNEL_TYPE_UNRELIABLE_UNORDERED );
    m_messageSendQueue = YOJIMBO_NEW( *m_allocator, Queue<Message*>, *m_allocator, m_config.messageSendQueueSize );
    m_messageReceiveQueue = YOJIMBO_NEW( *m_allocator, Queue<Message*>, *m_allocator, m_config.messageReceiveQueueSize );
    Reset();
}

UnreliableUnorderedChannel::~UnreliableUnorderedChannel()
{
    Reset();
    YOJIMBO_DELETE( *m_allocator, Queue<Message*>, m_messageSendQueue );
    YOJIMBO_DELETE( *m_allocator, Queue<Message*>, m_messageReceiveQueue );
}

void UnreliableUnorderedChannel::Reset()
{
    SetErrorLevel( CHANNEL_ERROR_NONE );

    for ( int i = 0; i < m_messageSendQueue->GetNumEntries(); ++i )
        m_messageFactory->ReleaseMessage( (*m_messageSendQueue)[i] );

    for ( int i = 0; i < m_messageReceiveQueue->GetNumEntries(); ++i )
        m_messageFactory->ReleaseMessage( (*m_messageReceiveQueue)[i] );

    m_messageSendQueue->Clear();
    m_messageReceiveQueue->Clear();

    ResetCounters();
}

bool UnreliableUnorderedChannel::CanSendMessage() const
{
    yojimbo_assert( m_messageSendQueue );
    return !m_messageSendQueue->IsFull();
}

bool UnreliableUnorderedChannel::HasMessagesToSend() const
{
    yojimbo_assert( m_messageSendQueue );
    return !m_messageSendQueue->IsEmpty();
}

void UnreliableUnorderedChannel::SendMessage( Message * message, void *context )
{
    yojimbo_assert( message );
    yojimbo_assert( CanSendMessage() );
    (void)context;

    if ( GetErrorLevel() != CHANNEL_ERROR_NONE )
    {
        m_messageFactory->ReleaseMessage( message );
        return;
    }

    if ( !CanSendMessage() )
    {
        SetErrorLevel( CHANNEL_ERROR_SEND_QUEUE_FULL );
        m_messageFactory->ReleaseMessage( message );
        return;
    }

    assert(message.blockData.count <= m_config.maxBlockSize);

    m_messageSendQueue->Push( message );

    m_counters[CHANNEL_COUNTER_MESSAGES_SENT]++;
}

Message * UnreliableUnorderedChannel::ReceiveMessage()
{
    if ( GetErrorLevel() != CHANNEL_ERROR_NONE )
        return NULL;

    if ( m_messageReceiveQueue->IsEmpty() )
        return NULL;

    m_counters[CHANNEL_COUNTER_MESSAGES_RECEIVED]++;

    return m_messageReceiveQueue->Pop();
}

void UnreliableUnorderedChannel::AdvanceTime( double time )
{
    (void) time;
}

int UnreliableUnorderedChannel::GetPacketData( void *ctx, ChannelPacketData & packetData, uint16_t packetSequence, int availableBits )
{
    (void) packetSequence;

    if ( m_messageSendQueue->IsEmpty() )
        return 0;

    if ( m_config.packetBudget > 0 )
        availableBits = yojimbo_min( m_config.packetBudget * 8, availableBits );

    const int giveUpBits = 4 * 8;

    const int messageTypeBits = bits_required( 0, m_messageFactory->GetNumTypes() - 1 );

    int usedBits = ConservativeMessageHeaderBits;
    int numMessages = 0;
    Message ** messages = (Message**) alloca( sizeof( Message* ) * m_config.maxMessagesPerPacket );

    while ( true )
    {
        if ( m_messageSendQueue->IsEmpty() )
            break;

        if ( availableBits - usedBits < giveUpBits )
            break;

        if ( numMessages == m_config.maxMessagesPerPacket )
            break;

        Message * message = m_messageSendQueue->Pop();

        yojimbo_assert( message );

        MeasureStream measureStream;
        measureStream.SetContext( ctx );
        measureStream.SetAllocator( &m_messageFactory->GetAllocator() );
        message->SerializeInternal( measureStream );

        serialize_message_block(measureStream, *m_messageFactory, message, m_config.maxBlockSize);

        const int messageBits = messageTypeBits + measureStream.GetBitsProcessed();

        if ( usedBits + messageBits > availableBits )
        {
            m_messageFactory->ReleaseMessage( message );
            continue;
        }

        usedBits += messageBits;

        yojimbo_assert( usedBits <= availableBits );

        messages[numMessages++] = message;
    }

    if ( numMessages == 0 )
        return 0;

    Allocator & allocator = m_messageFactory->GetAllocator();

    packetData.Initialize();
    packetData.channelIndex = GetChannelIndex();
    packetData.message.numMessages = numMessages;
    packetData.message.messages = (Message**) YOJIMBO_ALLOCATE( allocator, sizeof( Message* ) * numMessages );
    for ( int i = 0; i < numMessages; ++i )
    {
        packetData.message.messages[i] = messages[i];
    }

    return usedBits;
}

void UnreliableUnorderedChannel::ProcessPacketData( const ChannelPacketData & packetData, uint16_t packetSequence )
{
    if ( m_errorLevel != CHANNEL_ERROR_NONE )
        return;

    if ( packetData.messageFailedToSerialize )
    {
        SetErrorLevel( CHANNEL_ERROR_FAILED_TO_SERIALIZE );
        return;
    }

    for ( int i = 0; i < (int) packetData.message.numMessages; ++i )
    {
        Message * message = packetData.message.messages[i];
        yojimbo_assert( message );
        message->SetId( packetSequence );
        if ( !m_messageReceiveQueue->IsFull() )
        {
            m_messageFactory->AcquireMessage( message );
            m_messageReceiveQueue->Push( message );
        }
    }
}

void UnreliableUnorderedChannel::ProcessAck( uint16_t ack )
{
    (void) ack;
}