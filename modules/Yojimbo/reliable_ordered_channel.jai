#scope_module

/**
    Messages sent across this channel are guaranteed to arrive in the order they were sent.
    This channel type is best used for control messages and RPCs.
    Messages sent over this channel are included in connection packets until one of those packets is acked. Messages are acked individually and remain in the send queue until acked.
    Blocks attached to messages sent over this channel are split up into fragments. Each fragment of the block is included in a connection packet until one of those packets are acked. Eventually, all fragments are received on the other side, and block is reassembled and attached to the message.
    Only one message block may be in flight over the network at any time, so blocks stall out message delivery slightly. Therefore, only use blocks for large data that won't fit inside a single connection packet where you actually need the channel to split it up into fragments. If your block fits inside a packet, just serialize it inside your message serialize via serialize_bytes instead.
    */

class ReliableOrderedChannel : public Channel
{
public:
    #as using base: Channel;
    base.config.type = .ReliableOrdered;

    /**
        Reliable ordered channel constructor.
        @param allocator The allocator to use.
        @param messageFactory Message factory for creating and destroying messages.
        @param config The configuration for this channel.
        @param channelIndex The channel index in [0,numChannels-1].
        */

    ReliableOrderedChannel( Allocator & allocator, MessageFactory & messageFactory, const ChannelConfig & config, int channelIndex, double time );

    /**
        Reliable ordered channel destructor.
        Any messages still in the send or receive queues will be released.
        */

    ~ReliableOrderedChannel();

    void Reset();

    bool CanSendMessage() const;

    void SendMessage( Message * message, void *context );

    Message * ReceiveMessage();

    void AdvanceTime( double time );

    int GetPacketData( void *context, ChannelPacketData & packetData, uint16_t packetSequence, int availableBits );

    void ProcessPacketData( const ChannelPacketData & packetData, uint16_t packetSequence );

    void ProcessAck( uint16_t ack );

    /**
        Are there any unacked messages in the send queue?
        Messages are acked individually and remain in the send queue until acked.
        @returns True if there is at least one unacked message in the send queue.
        */

    bool HasMessagesToSend() const;

    /**
        Get messages to include in a packet.
        Messages are measured to see how many bits they take, and only messages that fit within the channel packet budget will be included. See ChannelConfig::packetBudget.
        Takes care not to send messages too rapidly by respecting ChannelConfig::messageResendTime for each message, and to only include messages that that the receiver is able to buffer in their receive queue. In other words, won't run ahead of the receiver.
        @param messageIds Array of message ids to be filled [out]. Fills up to ChannelConfig::maxMessagesPerPacket messages, make sure your array is at least this size.
        @param numMessageIds The number of message ids written to the array.
        @param remainingPacketBits Number of bits remaining in the packet. Considers this as a hard limit when determining how many messages can fit into the packet.
        @returns Estimate of the number of bits required to serialize the messages (upper bound).
        @see GetMessagePacketData
        */

    int GetMessagesToSend( uint16_t * messageIds, int & numMessageIds, int remainingPacketBits, void *context );

    /**
        Fill channel packet data with messages.
        This is the payload function to fill packet data while sending regular messages (without blocks attached).
        Messages have references added to them when they are added to the packet. They also have a reference while they are stored in a send or receive queue. Messages are cleaned up when they are no longer in a queue, and no longer referenced by any packets.
        @param packetData The packet data to fill [out]
        @param messageIds Array of message ids identifying which messages to add to the packet from the message send queue.
        @param numMessageIds The number of message ids in the array.
        @see GetMessagesToSend
        */

    void GetMessagePacketData( ChannelPacketData & packetData, const uint16_t * messageIds, int numMessageIds );

    /**
        Add a packet entry for the set of messages included in a packet.
        This lets us look up the set of messages that were included in that packet later on when it is acked, so we can ack those messages individually.
        @param messageIds The set of message ids that were included in the packet.
        @param numMessageIds The number of message ids in the array.
        @param sequence The sequence number of the connection packet the messages were included in.
        */

    void AddMessagePacketEntry( const uint16_t * messageIds, int numMessageIds, uint16_t sequence );

    /**
        Process messages included in a packet.
        Any messages that have not already been received are added to the message receive queue. Messages that are added to the receive queue have a reference added. See Message::AddRef.
        @param numMessages The number of messages to process.
        @param messages Array of pointers to messages.
        */

    void ProcessPacketMessages( int numMessages, Message ** messages );

    /**
        Track the oldest unacked message id in the send queue.
        Because messages are acked individually, the send queue is not a true queue and may have holes.
        Because of this it is necessary to periodically walk forward from the previous oldest unacked message id, to find the current oldest unacked message id.
        This lets us know our starting point for considering messages to include in the next packet we send.
        @see GetMessagesToSend
        */

    void UpdateOldestUnackedMessageId();

    /**
        True if we are currently sending a block message.
        Block messages are treated differently to regular messages.
        Regular messages are small so we try to fit as many into the packet we can. See ReliableChannelData::GetMessagesToSend.
        Blocks attached to block messages are usually larger than the maximum packet size or channel budget, so they are split up fragments.
        While in the mode of sending a block message, each channel packet data generated has exactly one fragment from the current block in it. Fragments keep getting included in packets until all fragments of that block are acked.
        @returns True if currently sending a block message over the network, false otherwise.
        @see BlockMessage
        @see GetFragmentToSend
        */

    bool SendingBlockMessage();

    /**
        Get the next block fragment to send.
        The next block fragment is selected by scanning left to right over the set of fragments in the block, skipping over any fragments that have already been acked or have been sent within ChannelConfig::fragmentResendTime.
        @param messageId The id of the message that the block is attached to [out].
        @param fragmentId The id of the fragment to send [out].
        @param fragmentBytes The size of the fragment in bytes.
        @param numFragments The total number of fragments in this block.
        @param messageType The type of message the block is attached to. See MessageFactory.
        @returns Pointer to the fragment data.
        */

    uint8_t * GetFragmentToSend( uint16_t & messageId, uint16_t & fragmentId, int & fragmentBytes, int & numFragments, int & messageType );

    /**
        Fill the packet data with block and fragment data.
        This is the payload function that fills the channel packet data while we are sending a block message.
        @param packetData The packet data to fill [out]
        @param messageId The id of the message that the block is attached to.
        @param fragmentId The id of the block fragment being sent.
        @param fragmentData The fragment data.
        @param fragmentSize The size of the fragment data (bytes).
        @param numFragments The number of fragments in the block.
        @param messageType The type of message the block is attached to.
        @returns An estimate of the number of bits required to serialize the block message and fragment data (upper bound).
        */

    int GetFragmentPacketData( ChannelPacketData & packetData,
                                uint16_t messageId,
                                uint16_t fragmentId,
                                uint8_t * fragmentData,
                                int fragmentSize,
                                int numFragments,
                                int messageType );

    /**
        Adds a packet entry for the fragment.
        This lets us look up the fragment that was in the packet later on when it is acked, so we can ack that block fragment.
        @param messageId The message id that the block was attached to.
        @param fragmentId The fragment id.
        @param sequence The sequence number of the packet the fragment was included in.
        */

    void AddFragmentPacketEntry( uint16_t messageId, uint16_t fragmentId, uint16_t sequence );

    /**
        Process a packet fragment.
        The fragment is added to the set of received fragments for the block. When all packet fragments are received, that block is reconstructed, attached to the block message and added to the message receive queue.
        @param messageType The type of the message this block fragment is attached to. This is used to make sure this message type actually allows blocks to be attached to it.
        @param messageId The id of the message the block fragment belongs to.
        @param numFragments The number of fragments in the block.
        @param fragmentId The id of the fragment in [0,numFragments-1].
        @param fragmentData The fragment data.
        @param fragmentBytes The size of the fragment data in bytes.
        @param blockMessage Pointer to the block message. Passed this in only with the first fragment (0), pass NULL for all other fragments.
        */

    void ProcessPacketFragment( int messageType,
                                uint16_t messageId,
                                int numFragments,
                                uint16_t fragmentId,
                                const uint8_t * fragmentData,
                                int fragmentBytes,
                                BlockMessage * blockMessage );

protected:

    /*
    An entry in the send queue of the reliable-ordered channel.
    Messages stay into the send queue until acked. Each message is acked individually, so there can be "holes" in the message send queue.
    */
    MessageSendQueueEntry :: struct {
        message      : *Message;     // Pointer to the message. When inserted in the send queue the message has one reference. It is released when the message is acked and removed from the send queue.
        timeLastSent : Apollo_Time;  // The time the message was last sent. Used to implement ChannelConfig::messageResendTime.
        measuredBits : u32;          // The number of bits the message takes up in a bit stream.
    };

    /*
    An entry in the receive queue of the reliable-ordered channel.
    */
    MessageReceiveQueueEntry :: struct {
        message: *Message;  // The message pointer. Has at a reference count of at least 1 while in the receive queue. Ownership of the message is passed back to the caller when the message is dequeued.
    };

    /*
    Maps packet level acks to messages and fragments for the reliable-ordered channel.
    */
    struct SentPacketEntry
    {
        double timeSent;                                                            ///< The time the packet was sent. Used to estimate round trip time.
        uint16_t * messageIds;                                                      ///< Pointer to an array of message ids. Dynamically allocated because the user can configure the maximum number of messages in a packet per-channel with ChannelConfig::maxMessagesPerPacket.
        uint32_t numMessageIds : 16;                                                ///< The number of message ids in in the array.
        uint32_t acked : 1;                                                         ///< 1 if this packet has been acked.
        uint64_t block : 1;                                                         ///< 1 if this packet contains a fragment of a block message.
        uint64_t blockMessageId : 16;                                               ///< The block message id. Valid only if "block" is 1.
        uint64_t blockFragmentId : 16;                                              ///< The block fragment id. Valid only if "block" is 1.
    };

    /*
    Internal state for a block being sent across the reliable ordered channel.
    Stores the block data and tracks which fragments have been acked. The block send completes when all fragments have been acked.
    IMPORTANT: Although there can be multiple block messages in the message send and receive queues, only one data block can be in flights over the wire at a time.
    */
    struct SendBlockData
    {
        SendBlockData( Allocator & allocator, int maxFragmentsPerBlock )
        {
            m_allocator = &allocator;
            ackedFragment = YOJIMBO_NEW( allocator, BitArray, allocator, maxFragmentsPerBlock );
            fragmentSendTime = (double*) YOJIMBO_ALLOCATE( allocator, sizeof( double) * maxFragmentsPerBlock );
            yojimbo_assert( ackedFragment );
            yojimbo_assert( fragmentSendTime );
            Reset();
        }

        ~SendBlockData()
        {
            YOJIMBO_DELETE( *m_allocator, BitArray, ackedFragment );
            YOJIMBO_FREE( *m_allocator, fragmentSendTime );
        }

        void Reset()
        {
            active = false;
            numFragments = 0;
            numAckedFragments = 0;
            blockMessageId = 0;
            blockSize = 0;
        }

        bool active;                                                                ///< True if we are currently sending a block.
        int blockSize;                                                              ///< The size of the block (bytes).
        int numFragments;                                                           ///< Number of fragments in the block being sent.
        int numAckedFragments;                                                      ///< Number of acked fragments in the block being sent.
        uint16_t blockMessageId;                                                    ///< The message id the block is attached to.
        BitArray * ackedFragment;                                                   ///< Has fragment n been received?
        double * fragmentSendTime;                                                  ///< Last time fragment was sent.

    private:

        Allocator * m_allocator;                                                    ///< Allocator used to create the block data.

        SendBlockData( const SendBlockData & other );

        SendBlockData & operator = ( const SendBlockData & other );
    };

    /**
        Internal state for a block being received across the reliable ordered channel.
        Stores the fragments received over the network for the block, and completes once all fragments have been received.
        IMPORTANT: Although there can be multiple block messages in the message send and receive queues, only one data block can be in flight over the wire at a time.
        */

    struct ReceiveBlockData
    {
        ReceiveBlockData( Allocator & allocator, int maxBlockSize, int maxFragmentsPerBlock )
        {
            m_allocator = &allocator;
            receivedFragment = YOJIMBO_NEW( allocator, BitArray, allocator, maxFragmentsPerBlock );
            blockData = (uint8_t*) YOJIMBO_ALLOCATE( allocator, maxBlockSize );
            yojimbo_assert( receivedFragment && blockData );
            blockMessage = NULL;
            Reset();
        }

        ~ReceiveBlockData()
        {
            YOJIMBO_DELETE( *m_allocator, BitArray, receivedFragment );
            YOJIMBO_FREE( *m_allocator, blockData );
        }

        void Reset()
        {
            active = false;
            numFragments = 0;
            numReceivedFragments = 0;
            messageId = 0;
            messageType = 0;
            blockSize = 0;
        }

        bool active;                                                                ///< True if we are currently receiving a block.
        int numFragments;                                                           ///< The number of fragments in this block
        int numReceivedFragments;                                                   ///< The number of fragments received.
        uint16_t messageId;                                                         ///< The message id corresponding to the block.
        int messageType;                                                            ///< Message type of the block being received.
        uint32_t blockSize;                                                         ///< Block size in bytes.
        BitArray * receivedFragment;                                                ///< Has fragment n been received?
        uint8_t * blockData;                                                        ///< Block data for receive.
        BlockMessage * blockMessage;                                                ///< Block message (sent with fragment 0).

    private:

        Allocator * m_allocator;                                                    ///< Allocator used to free the data on shutdown.

        ReceiveBlockData( const ReceiveBlockData & other );

        ReceiveBlockData & operator = ( const ReceiveBlockData & other );
    };

private:

    uint16_t m_sendMessageId;                                                       ///< Id of the next message to be added to the send queue.
    uint16_t m_receiveMessageId;                                                    ///< Id of the next message to be added to the receive queue.
    uint16_t m_oldestUnackedMessageId;                                              ///< Id of the oldest unacked message in the send queue.
    SequenceBuffer<SentPacketEntry> * m_sentPackets;                                ///< Stores information per sent connection packet about messages and block data included in each packet. Used to walk from connection packet level acks to message and data block fragment level acks.
    SequenceBuffer<MessageSendQueueEntry> * m_messageSendQueue;                     ///< Message send queue.
    SequenceBuffer<MessageReceiveQueueEntry> * m_messageReceiveQueue;               ///< Message receive queue.
    uint16_t * m_sentPacketMessageIds;                                              ///< Array of n message ids per sent connection packet. Allows the maximum number of messages per-packet to be allocated dynamically.
    SendBlockData * m_sendBlock;                                                    ///< Data about the block being currently sent.
    ReceiveBlockData * m_receiveBlock;                                              ///< Data about the block being currently received.

private:

    ReliableOrderedChannel( const ReliableOrderedChannel & other );

    ReliableOrderedChannel & operator = ( const ReliableOrderedChannel & other );
};

ReliableOrderedChannel::ReliableOrderedChannel( Allocator & allocator, MessageFactory & messageFactory, const ChannelConfig & config, int channelIndex, double time )
    : Channel( allocator, messageFactory, config, channelIndex, time )
{
    yojimbo_assert( config.type == CHANNEL_TYPE_RELIABLE_ORDERED );

    yojimbo_assert( ( 65536 % config.sentPacketBufferSize ) == 0 );
    yojimbo_assert( ( 65536 % config.messageSendQueueSize ) == 0 );
    yojimbo_assert( ( 65536 % config.messageReceiveQueueSize ) == 0 );

    m_sentPackets = YOJIMBO_NEW( *m_allocator, SequenceBuffer<SentPacketEntry>, *m_allocator, m_config.sentPacketBufferSize );
    m_messageSendQueue = YOJIMBO_NEW( *m_allocator, SequenceBuffer<MessageSendQueueEntry>, *m_allocator, m_config.messageSendQueueSize );
    m_messageReceiveQueue = YOJIMBO_NEW( *m_allocator, SequenceBuffer<MessageReceiveQueueEntry>, *m_allocator, m_config.messageReceiveQueueSize );
    m_sentPacketMessageIds = (uint16_t*) YOJIMBO_ALLOCATE( *m_allocator, sizeof( uint16_t ) * m_config.maxMessagesPerPacket * m_config.sentPacketBufferSize );

    if ( !config.disableBlocks )
    {
        m_sendBlock = YOJIMBO_NEW( *m_allocator, SendBlockData, *m_allocator, m_config.GetMaxFragmentsPerBlock() );
        m_receiveBlock = YOJIMBO_NEW( *m_allocator, ReceiveBlockData, *m_allocator, m_config.maxBlockSize, m_config.GetMaxFragmentsPerBlock() );
    }
    else
    {
        m_sendBlock = NULL;
        m_receiveBlock = NULL;
    }

    Reset();
}

ReliableOrderedChannel::~ReliableOrderedChannel()
{
    Reset();

    YOJIMBO_DELETE( *m_allocator, SendBlockData, m_sendBlock );
    YOJIMBO_DELETE( *m_allocator, ReceiveBlockData, m_receiveBlock );
    YOJIMBO_DELETE( *m_allocator, SequenceBuffer<SentPacketEntry>, m_sentPackets );
    YOJIMBO_DELETE( *m_allocator, SequenceBuffer<MessageSendQueueEntry>, m_messageSendQueue );
    YOJIMBO_DELETE( *m_allocator, SequenceBuffer<MessageReceiveQueueEntry>, m_messageReceiveQueue );

    YOJIMBO_FREE( *m_allocator, m_sentPacketMessageIds );

    m_sentPacketMessageIds = NULL;
}

void ReliableOrderedChannel::Reset()
{
    SetErrorLevel( CHANNEL_ERROR_NONE );

    m_sendMessageId = 0;
    m_receiveMessageId = 0;
    m_oldestUnackedMessageId = 0;

    for ( int i = 0; i < m_messageSendQueue->GetSize(); ++i )
    {
        MessageSendQueueEntry * entry = m_messageSendQueue->GetAtIndex( i );
        if ( entry && entry->message )
            m_messageFactory->ReleaseMessage( entry->message );
    }

    for ( int i = 0; i < m_messageReceiveQueue->GetSize(); ++i )
    {
        MessageReceiveQueueEntry * entry = m_messageReceiveQueue->GetAtIndex( i );
        if ( entry && entry->message )
            m_messageFactory->ReleaseMessage( entry->message );
    }

    m_sentPackets->Reset();
    m_messageSendQueue->Reset();
    m_messageReceiveQueue->Reset();

    if ( m_sendBlock )
    {
        m_sendBlock->Reset();
    }

    if ( m_receiveBlock )
    {
        m_receiveBlock->Reset();
        if ( m_receiveBlock->blockMessage )
        {
            m_messageFactory->ReleaseMessage( m_receiveBlock->blockMessage );
            m_receiveBlock->blockMessage = NULL;
        }
    }

    ResetCounters();
}

#undef SendMessage

bool ReliableOrderedChannel::CanSendMessage() const
{
    yojimbo_assert( m_messageSendQueue );
    return m_messageSendQueue->Available( m_sendMessageId );
}

void ReliableOrderedChannel::SendMessage( Message * message, void *context )
{
    yojimbo_assert( message );

    yojimbo_assert( CanSendMessage() );

    if ( GetErrorLevel() != CHANNEL_ERROR_NONE )
    {
        m_messageFactory->ReleaseMessage( message );
        return;
    }

    if ( !CanSendMessage() )
    {
        // Increase your send queue size!
        SetErrorLevel( CHANNEL_ERROR_SEND_QUEUE_FULL );
        m_messageFactory->ReleaseMessage( message );
        return;
    }

    message->SetId( m_sendMessageId );

    MessageSendQueueEntry * entry = m_messageSendQueue->Insert( m_sendMessageId );

    yojimbo_assert( entry );

    entry->block = message->IsBlockMessage();
    entry->message = message;
    entry->measuredBits = 0;
    entry->timeLastSent = -1.0;

    assert(message.blockData.count <= m_config.maxBlockSize);

    MeasureStream measureStream;
    measureStream.SetContext( context );
    measureStream.SetAllocator( &m_messageFactory->GetAllocator() );
    message->SerializeInternal( measureStream );
    entry->measuredBits = measureStream.GetBitsProcessed();
    m_counters[CHANNEL_COUNTER_MESSAGES_SENT]++;
    m_sendMessageId++;
}

Message * ReliableOrderedChannel::ReceiveMessage()
{
    if ( GetErrorLevel() != CHANNEL_ERROR_NONE )
        return NULL;

    MessageReceiveQueueEntry * entry = m_messageReceiveQueue->Find( m_receiveMessageId );
    if ( !entry )
        return NULL;

    Message * message = entry->message;
    yojimbo_assert( message );
    yojimbo_assert( message->GetId() == m_receiveMessageId );
    m_messageReceiveQueue->Remove( m_receiveMessageId );
    m_counters[CHANNEL_COUNTER_MESSAGES_RECEIVED]++;
    m_receiveMessageId++;

    return message;
}

void ReliableOrderedChannel::AdvanceTime( double time )
{
    m_time = time;
}

int ReliableOrderedChannel::GetPacketData( void *context, ChannelPacketData & packetData, uint16_t packetSequence, int availableBits )
{
    if ( !HasMessagesToSend() )
        return 0;

    if ( SendingBlockMessage() )
    {
        if (m_config.blockFragmentSize * 8 > availableBits)
            return 0;

        uint16_t messageId;
        uint16_t fragmentId;
        int fragmentBytes;
        int numFragments;
        int messageType;

        uint8_t * fragmentData = GetFragmentToSend( messageId, fragmentId, fragmentBytes, numFragments, messageType );

        if ( fragmentData )
        {
            const int fragmentBits = GetFragmentPacketData( packetData, messageId, fragmentId, fragmentData, fragmentBytes, numFragments, messageType );
            AddFragmentPacketEntry( messageId, fragmentId, packetSequence );
            return fragmentBits;
        }
    }
    else
    {
        int numMessageIds = 0;
        uint16_t * messageIds = (uint16_t*) alloca( m_config.maxMessagesPerPacket * sizeof( uint16_t ) );
        const int messageBits = GetMessagesToSend( messageIds, numMessageIds, availableBits, context );

        if ( numMessageIds > 0 )
        {
            GetMessagePacketData( packetData, messageIds, numMessageIds );
            AddMessagePacketEntry( messageIds, numMessageIds, packetSequence );
            return messageBits;
        }
    }

    return 0;
}

bool ReliableOrderedChannel::HasMessagesToSend() const
{
    return m_oldestUnackedMessageId != m_sendMessageId;
}

int ReliableOrderedChannel::GetMessagesToSend( uint16_t * messageIds, int & numMessageIds, int availableBits, void *context )
{
    yojimbo_assert( HasMessagesToSend() );

    numMessageIds = 0;

    if ( m_config.packetBudget > 0 )
        availableBits = yojimbo_min( m_config.packetBudget * 8, availableBits );

    const int giveUpBits = 4 * 8;
    const int messageTypeBits = bits_required( 0, m_messageFactory->GetNumTypes() - 1 );
    const int messageLimit = yojimbo_min( m_config.messageSendQueueSize, m_config.messageReceiveQueueSize );
    uint16_t previousMessageId = 0;
    int usedBits = ConservativeMessageHeaderBits;
    int giveUpCounter = 0;
#ifdef YOJIMBO_DEBUG
    const int maxBits = availableBits;
#endif // YOJIMBO_DEBUG

    for ( int i = 0; i < messageLimit; ++i )
    {
        if ( availableBits - usedBits < giveUpBits )
            break;

        if ( giveUpCounter > m_config.messageSendQueueSize )
            break;

        uint16_t messageId = m_oldestUnackedMessageId + i;
        MessageSendQueueEntry * entry = m_messageSendQueue->Find( messageId );
        if ( !entry )
            continue;

        if ( entry->block )
            break;

        // Increase your max packet size!
        yojimbo_assert( entry->measuredBits <= uint32_t(maxBits) );

        if ( entry->timeLastSent + m_config.messageResendTime <= m_time && availableBits >= (int) entry->measuredBits )
        {
            int messageBits = entry->measuredBits + messageTypeBits;

            if ( numMessageIds == 0 )
            {
                messageBits += 16;
            }
            else
            {
                MeasureStream stream;
                stream.SetContext( context );
                stream.SetAllocator( &m_messageFactory->GetAllocator() );
                serialize_sequence_relative( stream, previousMessageId, messageId );
                messageBits += stream.GetBitsProcessed();
            }

            if ( usedBits + messageBits > availableBits )
            {
                giveUpCounter++;
                continue;
            }

            usedBits += messageBits;
            messageIds[numMessageIds++] = messageId;
            previousMessageId = messageId;
            entry->timeLastSent = m_time;
        }

        if ( numMessageIds == m_config.maxMessagesPerPacket )
            break;
    }

    return usedBits;
}

void ReliableOrderedChannel::GetMessagePacketData( ChannelPacketData & packetData, const uint16_t * messageIds, int numMessageIds )
{
    yojimbo_assert( messageIds );

    packetData.Initialize();
    packetData.channelIndex = GetChannelIndex();
    packetData.message.numMessages = numMessageIds;

    if ( numMessageIds == 0 )
        return;

    packetData.message.messages = (Message**) YOJIMBO_ALLOCATE( m_messageFactory->GetAllocator(), sizeof( Message* ) * numMessageIds );

    for ( int i = 0; i < numMessageIds; ++i )
    {
        MessageSendQueueEntry * entry = m_messageSendQueue->Find( messageIds[i] );
        yojimbo_assert( entry );
        yojimbo_assert( entry->message );
        yojimbo_assert( entry->message->GetRefCount() > 0 );
        packetData.message.messages[i] = entry->message;
        m_messageFactory->AcquireMessage( packetData.message.messages[i] );
    }
}

void ReliableOrderedChannel::AddMessagePacketEntry( const uint16_t * messageIds, int numMessageIds, uint16_t sequence )
{
    SentPacketEntry * sentPacket = m_sentPackets->Insert( sequence, true );
    yojimbo_assert( sentPacket );
    if ( sentPacket )
    {
        sentPacket->acked = 0;
        sentPacket->block = 0;
        sentPacket->timeSent = m_time;
        sentPacket->messageIds = &m_sentPacketMessageIds[ ( sequence % m_config.sentPacketBufferSize ) * m_config.maxMessagesPerPacket ];
        sentPacket->numMessageIds = numMessageIds;
        for ( int i = 0; i < numMessageIds; ++i )
        {
            sentPacket->messageIds[i] = messageIds[i];
        }
    }
}

void ReliableOrderedChannel::ProcessPacketMessages( int numMessages, Message ** messages )
{
    const uint16_t minMessageId = m_receiveMessageId;
    const uint16_t maxMessageId = m_receiveMessageId + m_config.messageReceiveQueueSize - 1;

    for ( int i = 0; i < (int) numMessages; ++i )
    {
        Message * message = messages[i];

        yojimbo_assert( message );

        const uint16_t messageId = message->GetId();

        if ( yojimbo_sequence_less_than( messageId, minMessageId ) )
            continue;

        if ( yojimbo_sequence_greater_than( messageId, maxMessageId ) )
        {
            // Did you forget to dequeue messages on the receiver?
            yojimbo_printf( YOJIMBO_LOG_LEVEL_ERROR, "sequence overflow: %d vs. [%d,%d]\n", messageId, minMessageId, maxMessageId );
            SetErrorLevel( CHANNEL_ERROR_DESYNC );
            return;
        }

        if ( m_messageReceiveQueue->Find( messageId ) )
            continue;

        yojimbo_assert( !m_messageReceiveQueue->GetAtIndex( m_messageReceiveQueue->GetIndex( messageId ) ) );

        MessageReceiveQueueEntry * entry = m_messageReceiveQueue->Insert( messageId );
        if ( !entry )
        {
            // For some reason we can't insert the message in the receive queue
            SetErrorLevel( CHANNEL_ERROR_DESYNC );
            return;
        }

        entry->message = message;

        m_messageFactory->AcquireMessage( message );
    }
}

void ReliableOrderedChannel::ProcessPacketData( const ChannelPacketData & packetData, uint16_t packetSequence )
{
    if ( m_errorLevel != CHANNEL_ERROR_NONE )
        return;

    if ( packetData.messageFailedToSerialize )
    {
        // A message failed to serialize read for some reason, eg. mismatched read/write.
        SetErrorLevel( CHANNEL_ERROR_FAILED_TO_SERIALIZE );
        return;
    }

    (void)packetSequence;

    if ( packetData.blockMessage )
    {
        ProcessPacketFragment( packetData.block.messageType,
                                packetData.block.messageId,
                                packetData.block.numFragments,
                                packetData.block.fragmentId,
                                packetData.block.fragmentData,
                                packetData.block.fragmentSize,
                                packetData.block.message );
    }
    else
    {
        ProcessPacketMessages( packetData.message.numMessages, packetData.message.messages );
    }
}

void ReliableOrderedChannel::ProcessAck( uint16_t ack )
{
    SentPacketEntry * sentPacketEntry = m_sentPackets->Find( ack );
    if ( !sentPacketEntry )
        return;

    yojimbo_assert( !sentPacketEntry->acked );

    for ( int i = 0; i < (int) sentPacketEntry->numMessageIds; ++i )
    {
        const uint16_t messageId = sentPacketEntry->messageIds[i];
        MessageSendQueueEntry * sendQueueEntry = m_messageSendQueue->Find( messageId );
        if ( sendQueueEntry )
        {
            yojimbo_assert( sendQueueEntry->message );
            yojimbo_assert( sendQueueEntry->message->GetId() == messageId );
            m_messageFactory->ReleaseMessage( sendQueueEntry->message );
            m_messageSendQueue->Remove( messageId );
            UpdateOldestUnackedMessageId();
        }
    }

    if ( !m_config.disableBlocks && sentPacketEntry->block && m_sendBlock->active && m_sendBlock->blockMessageId == sentPacketEntry->blockMessageId )
    {
        const int messageId = sentPacketEntry->blockMessageId;
        const int fragmentId = sentPacketEntry->blockFragmentId;

        if ( !m_sendBlock->ackedFragment->GetBit( fragmentId ) )
        {
            m_sendBlock->ackedFragment->SetBit( fragmentId );
            m_sendBlock->numAckedFragments++;
            if ( m_sendBlock->numAckedFragments == m_sendBlock->numFragments )
            {
                m_sendBlock->active = false;
                MessageSendQueueEntry * sendQueueEntry = m_messageSendQueue->Find( messageId );
                yojimbo_assert( sendQueueEntry );
                m_messageFactory->ReleaseMessage( sendQueueEntry->message );
                m_messageSendQueue->Remove( messageId );
                UpdateOldestUnackedMessageId();
            }
        }
    }
}

void ReliableOrderedChannel::UpdateOldestUnackedMessageId()
{
    const uint16_t stopMessageId = m_messageSendQueue->GetSequence();

    while ( true )
    {
        if ( m_oldestUnackedMessageId == stopMessageId || m_messageSendQueue->Find( m_oldestUnackedMessageId ) )
        {
            break;
        }
        ++m_oldestUnackedMessageId;
    }

    yojimbo_assert( !yojimbo_sequence_greater_than( m_oldestUnackedMessageId, stopMessageId ) );
}

bool ReliableOrderedChannel::SendingBlockMessage()
{
    yojimbo_assert( HasMessagesToSend() );

    MessageSendQueueEntry * entry = m_messageSendQueue->Find( m_oldestUnackedMessageId );

    return ifx entry then entry.message.blockData.count > 0 else false;
}

uint8_t * ReliableOrderedChannel::GetFragmentToSend( uint16_t & messageId, uint16_t & fragmentId, int & fragmentBytes, int & numFragments, int & messageType )
{
    MessageSendQueueEntry * entry = m_messageSendQueue->Find( m_oldestUnackedMessageId );

    yojimbo_assert( entry );
    yojimbo_assert( entry->block );

    BlockMessage * blockMessage = (BlockMessage*) entry->message;

    yojimbo_assert( blockMessage );

    messageId = blockMessage->GetId();

    const int blockSize = blockMessage->GetBlockSize();

    if ( !m_sendBlock->active )
    {
        // start sending this block

        m_sendBlock->active = true;
        m_sendBlock->blockSize = blockSize;
        m_sendBlock->blockMessageId = messageId;
        m_sendBlock->numFragments = (int) ceil( blockSize / float( m_config.blockFragmentSize ) );
        m_sendBlock->numAckedFragments = 0;

        const int MaxFragmentsPerBlock = m_config.GetMaxFragmentsPerBlock();

        yojimbo_assert( m_sendBlock->numFragments > 0 );
        yojimbo_assert( m_sendBlock->numFragments <= MaxFragmentsPerBlock );

        m_sendBlock->ackedFragment->Clear();

        for ( int i = 0; i < MaxFragmentsPerBlock; ++i )
            m_sendBlock->fragmentSendTime[i] = -1.0;
    }

    numFragments = m_sendBlock->numFragments;

    // find the next fragment to send (there may not be one)

    fragmentId = 0xFFFF;

    for ( int i = 0; i < m_sendBlock->numFragments; ++i )
    {
        if ( !m_sendBlock->ackedFragment->GetBit( i ) && m_sendBlock->fragmentSendTime[i] + m_config.blockFragmentResendTime < m_time )
        {
            fragmentId = uint16_t( i );
            break;
        }
    }

    if ( fragmentId == 0xFFFF )
        return NULL;

    // allocate and return a copy of the fragment data

    messageType = blockMessage->GetType();

    fragmentBytes = m_config.blockFragmentSize;

    const int fragmentRemainder = blockSize % m_config.blockFragmentSize;

    if ( fragmentRemainder && fragmentId == m_sendBlock->numFragments - 1 )
        fragmentBytes = fragmentRemainder;

    uint8_t * fragmentData = (uint8_t*) YOJIMBO_ALLOCATE( m_messageFactory->GetAllocator(), fragmentBytes );

    if ( fragmentData )
    {
        memcpy( fragmentData, blockMessage->GetBlockData() + fragmentId * m_config.blockFragmentSize, fragmentBytes );

        m_sendBlock->fragmentSendTime[fragmentId] = m_time;
    }

    return fragmentData;
}

int ReliableOrderedChannel::GetFragmentPacketData( ChannelPacketData & packetData,
                                                    uint16_t messageId,
                                                    uint16_t fragmentId,
                                                    uint8_t * fragmentData,
                                                    int fragmentSize,
                                                    int numFragments,
                                                    int messageType )
{
    packetData.Initialize();

    packetData.channelIndex = GetChannelIndex();

    packetData.blockMessage = 1;

    packetData.block.fragmentData = fragmentData;
    packetData.block.messageId = messageId;
    packetData.block.fragmentId = fragmentId;
    packetData.block.fragmentSize = fragmentSize;
    packetData.block.numFragments = numFragments;
    packetData.block.messageType = messageType;

    const int messageTypeBits = bits_required( 0, m_messageFactory->GetNumTypes() - 1 );

    int fragmentBits = ConservativeFragmentHeaderBits + fragmentSize * 8;

    if ( fragmentId == 0 )
    {
        MessageSendQueueEntry * entry = m_messageSendQueue->Find( packetData.block.messageId );

        yojimbo_assert( entry );
        yojimbo_assert( entry->message );

        packetData.block.message = (BlockMessage*) entry->message;

        m_messageFactory->AcquireMessage( packetData.block.message );

        fragmentBits += entry->measuredBits + messageTypeBits;
    }
    else
    {
        packetData.block.message = NULL;
    }

    return fragmentBits;
}

void ReliableOrderedChannel::AddFragmentPacketEntry( uint16_t messageId, uint16_t fragmentId, uint16_t sequence )
{
    SentPacketEntry * sentPacket = m_sentPackets->Insert( sequence, true );
    yojimbo_assert( sentPacket );
    if ( sentPacket )
    {
        sentPacket->numMessageIds = 0;
        sentPacket->messageIds = NULL;
        sentPacket->timeSent = m_time;
        sentPacket->acked = 0;
        sentPacket->block = 1;
        sentPacket->blockMessageId = messageId;
        sentPacket->blockFragmentId = fragmentId;
    }
}

void ReliableOrderedChannel::ProcessPacketFragment( int messageType,
                                                    uint16_t messageId,
                                                    int numFragments,
                                                    uint16_t fragmentId,
                                                    const uint8_t * fragmentData,
                                                    int fragmentBytes,
                                                    BlockMessage * blockMessage )
{
    yojimbo_assert( !m_config.disableBlocks );

    if ( fragmentData )
    {
        const uint16_t expectedMessageId = m_messageReceiveQueue->GetSequence();
        if ( messageId != expectedMessageId )
            return;

        // start receiving a new block

        if ( !m_receiveBlock->active )
        {
            yojimbo_assert( numFragments >= 0 );
            yojimbo_assert( numFragments <= m_config.GetMaxFragmentsPerBlock() );

            m_receiveBlock->active = true;
            m_receiveBlock->numFragments = numFragments;
            m_receiveBlock->numReceivedFragments = 0;
            m_receiveBlock->messageId = messageId;
            m_receiveBlock->blockSize = 0;
            m_receiveBlock->receivedFragment->Clear();
        }

        // validate fragment

        if ( fragmentId >= m_receiveBlock->numFragments )
        {
            // The fragment id is out of range.
            SetErrorLevel( CHANNEL_ERROR_DESYNC );
            return;
        }

        if ( numFragments != m_receiveBlock->numFragments )
        {
            // The number of fragments is out of range.
            SetErrorLevel( CHANNEL_ERROR_DESYNC );
            return;
        }

        // receive the fragment

        if ( !m_receiveBlock->receivedFragment->GetBit( fragmentId ) )
        {
            m_receiveBlock->receivedFragment->SetBit( fragmentId );

            memcpy( m_receiveBlock->blockData + fragmentId * m_config.blockFragmentSize, fragmentData, fragmentBytes );

            if ( fragmentId == 0 )
            {
                m_receiveBlock->messageType = messageType;
            }

            if ( fragmentId == m_receiveBlock->numFragments - 1 )
            {
                m_receiveBlock->blockSize = ( m_receiveBlock->numFragments - 1 ) * m_config.blockFragmentSize + fragmentBytes;

                if ( m_receiveBlock->blockSize > (uint32_t) m_config.maxBlockSize )
                {
                    // The block size is outside range
                    SetErrorLevel( CHANNEL_ERROR_DESYNC );
                    return;
                }
            }

            m_receiveBlock->numReceivedFragments++;

            if ( fragmentId == 0 )
            {
                // save block message (sent with fragment 0)
                m_receiveBlock->blockMessage = blockMessage;
                m_messageFactory->AcquireMessage( m_receiveBlock->blockMessage );
            }

            if ( m_receiveBlock->numReceivedFragments == m_receiveBlock->numFragments )
            {
                // finished receiving block

                if ( m_messageReceiveQueue->GetAtIndex( m_messageReceiveQueue->GetIndex( messageId ) ) )
                {
                    // Did you forget to dequeue messages on the receiver?
                    SetErrorLevel( CHANNEL_ERROR_DESYNC );
                    return;
                }

                blockMessage = m_receiveBlock->blockMessage;

                yojimbo_assert( blockMessage );

                uint8_t * blockData = (uint8_t*) YOJIMBO_ALLOCATE( m_messageFactory->GetAllocator(), m_receiveBlock->blockSize );

                if ( !blockData )
                {
                    // Not enough memory to allocate block data
                    SetErrorLevel( CHANNEL_ERROR_OUT_OF_MEMORY );
                    return;
                }

                memcpy( blockData, m_receiveBlock->blockData, m_receiveBlock->blockSize );

                blockMessage->AttachBlock( m_messageFactory->GetAllocator(), blockData, m_receiveBlock->blockSize );

                blockMessage->SetId( messageId );

                MessageReceiveQueueEntry * entry = m_messageReceiveQueue->Insert( messageId );
                yojimbo_assert( entry );
                entry->message = blockMessage;
                m_receiveBlock->active = false;
                m_receiveBlock->blockMessage = NULL;
            }
        }
    }
}

#scope_file

#import "Bit_Array";
