#scope_module

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
