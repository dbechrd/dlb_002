#scope_module

/*
Messages sent across this channel are guaranteed to arrive in the order they were sent.
This channel type is best used for control messages and RPCs.
Messages sent over this channel are included in connection packets until one of those packets is acked. Messages are acked individually and remain in the send queue until acked.
Blocks attached to messages sent over this channel are split up into fragments. Each fragment of the block is included in a connection packet until one of those packets are acked. Eventually, all fragments are received on the other side, and block is reassembled and attached to the message.
Only one message block may be in flight over the network at any time, so blocks stall out message delivery slightly. Therefore, only use blocks for large data that won't fit inside a single connection packet where you actually need the channel to split it up into fragments. If your block fits inside a packet, just serialize it inside your message serialize via serialize_bytes instead.
*/
ReliableOrderedChannel :: struct {
    #as using base: Channel;

    sendMessageId          : u16;                                       // Id of the next message to be added to the send queue.
    receiveMessageId       : u16;                                       // Id of the next message to be added to the receive queue.
    oldestUnackedMessageId : u16;                                       // Id of the oldest unacked message in the send queue.
    sentPackets            : SequenceBuffer(SentPacketEntry);           // Stores information per sent connection packet about messages and block data included in each packet. Used to walk from connection packet level acks to message and data block fragment level acks.
    messageSendQueue       : SequenceBuffer(MessageSendQueueEntry);     // Message send queue.
    messageReceiveQueue    : SequenceBuffer(MessageReceiveQueueEntry);  // Message receive queue.
    sentPacketMessageIds   : [] u16;                                    // Array of n message ids per sent connection packet. Allows the maximum number of messages per-packet to be allocated dynamically.
    sendBlock              : *SendBlockData;                            // Data about the block being currently sent.
    receiveBlock           : *ReceiveBlockData;                         // Data about the block being currently received.
};

/*
Reliable ordered channel constructor.
@param allocator The allocator to use.
@param messageFactory Message factory for creating and destroying messages.
@param config The configuration for this channel.
@param channelIndex The channel index in [0,numChannels-1].
*/
channel_init :: (using channel: *ReliableOrderedChannel, messageFactory: *MessageFactory, config: ChannelConfig, channelIndex: int, time: Apollo_Time) {
    assert(config.type == .ReliableOrdered);
    channel_init(base, messageFactory, config, channelIndex, time);

    assert((65536 % config.sentPacketBufferSize) == 0);
    assert((65536 % config.messageSendQueueSize) == 0);
    assert((65536 % config.messageReceiveQueueSize) == 0);

    sequence_buffer_init(*sentPackets, config.sentPacketBufferSize);
    sequence_buffer_init(*messageSendQueue, config.messageSendQueueSize);
    sequence_buffer_init(*messageReceiveQueue, config.messageReceiveQueueSize);
    sentPacketMessageIds = NewArray(config.maxMessagesPerPacket * config.sentPacketBufferSize, u16);

    if !config.disableBlocks {
        maxFragmentsPerBlock := channel_config_get_max_fragments_per_block(config);
        sendBlock = New(SendBlockData);
        send_block_data_init(sendBlock, maxFragmentsPerBlock);
        receiveBlock = New(ReceiveBlockData);
        receive_block_data_init(receiveBlock, config.maxBlockSize, maxFragmentsPerBlock);
    }

    // This seems pointless, everything is zero'd by default in Jai.
    //channel_reset(channel);
}

/*
Reliable ordered channel destructor.
Any messages still in the send or receive queues will be released.
*/
channel_free :: (using channel: *ReliableOrderedChannel) {
    // TODO(dlb)[perf]: most of this is wasted effort.. lots of zero'ing
    channel_reset(channel);

    sequence_buffer_free(sentPackets);
    sequence_buffer_free(messageSendQueue);
    sequence_buffer_free(messageReceiveQueue);
    array_free(sentPacketMessageIds);

    send_block_data_free((sendBlock);
    free(sendBlock);
    receive_block_data_free(receiveBlock);
    free(receiveBlock);
}

channel_reset :: (using channel: *ReliableOrderedChannel) {
    errorLevel = .None;

    sendMessageId = 0;
    receiveMessageId = 0;
    oldestUnackedMessageId = 0;

    for 0..sequence_buffer_get_capacity(*messageSendQueue)-1 {
        entry = sequence_buffer_get_at_index(*messageSendQueue, it);
        if entry != null && entry.message != null {
            free(entry.message);
        }
    }

    for 0..sequence_buffer_get_capacity(*messageReceiveQueue)-1 {
        entry = sequence_buffer_get_at_index(*messageReceiveQueue, it);
        if entry != null && entry.message != null {
            free(entry.message);
        }
    }

    sequence_buffer_reset(*sentPackets);
    sequence_buffer_reset(*messageSendQueue);
    sequence_buffer_reset(*messageReceiveQueue);

    if sendBlock != null {
        send_block_data_reset(sendBlock);
    }

    if receiveBlock != null {
        receive_block_data_reset(receiveBlock);
    }

    channel_reset_counters(channel);
}

channel_can_send_message :: (using channel: *ReliableOrderedChannel) -> bool {
    return sequence_buffer_available(*messageSendQueue, sendMessageId);
}

channel_send_message :: (using channel: *ReliableOrderedChannel, message: *Message) {
    assert(message != null);
    assert(channel_can_send_message(channel));

    if errorLevel != .None {
        free(message);
        return;
    }

    if !channel_can_send_message(channel) {
        // Increase your send queue size!
        errorLevel = .SendQueueFull;
        free(message);
        return;
    }

    message.id = sendMessageId;

    entry := sequence_buffer_insert(messageSendQueue, sendMessageId);
    assert(entry != null);

    // Overwrite any previous values because sequence buffer entries get reused
    entry = .{ message = message };

    assert(message.blockData.count <= config.maxBlockSize);

    measureStream: MeasureStream;
    messageFactory.serializeRouter(measureStream, message);
    entry.measuredBits = stream_get_bits_processed(*measureStream);
    counters[ChannelCounter.MessagesSent] += 1;
    sendMessageId += 1;
}

channel_receive_message :: (using channel: *ReliableOrderedChannel) -> *Message {
    if errorLevel != .None {
        return null;
    }

    entry := sequence_buffer_find(*messageReceiveQueue, receiveMessageId);
    if entry == null {
        return null;
    }

    message := entry.message;
    assert(message != null);
    assert(message.id == receiveMessageId);
    sequence_buffer_remove(*messageReceiveQueue, receiveMessageId);
    counters[ChannelCounter.MessagesReceived] += 1;
    receiveMessageId += 1;

    return message;
}

channel_advance_time :: (using channel: *ReliableOrderedChannel, _time: Apollo_Time) {
    time = _time;
}

channel_generate_packet_data :: (using channel: *ReliableOrderedChannel, packetData: *ChannelPacketData, packetSequence: u16, availableBits: int) {
    if !channel_has_messages_to_send(channel) {
        return 0;
    }

    if channel_sending_block_message(channel) {
        if config.blockFragmentSize * 8 > availableBits {
            return 0;
        }

        messageId: u16;
        fragmentId: u16;
        fragmentBytes: int;
        numFragments: int;
        messageType: int;

        fragmentData := GetFragmentToSend( messageId, fragmentId, fragmentBytes, numFragments, messageType );

        if fragmentData != null {
            //////////////// continue here /////////////////
            fragmentBits := GetFragmentPacketData( packetData, messageId, fragmentId, fragmentData, fragmentBytes, numFragments, messageType );
            AddFragmentPacketEntry( messageId, fragmentId, packetSequence );
            return fragmentBits;
        }
    } else {
        numMessageIds := 0;
        messageIds := NewArray(config.maxMessagesPerPacket, u16,, temp);
        //////////////// continue here /////////////////
        messageBits := GetMessagesToSend( messageIds, numMessageIds, availableBits, context );

        if numMessageIds > 0 {
            GetMessagePacketData( packetData, messageIds, numMessageIds );
            AddMessagePacketEntry( messageIds, numMessageIds, packetSequence );
            return messageBits;
        }
    }

    return 0;
}

/*
Are there any unacked messages in the send queue?
Messages are acked individually and remain in the send queue until acked.
@returns True if there is at least one unacked message in the send queue.
*/
channel_has_messages_to_send :: (using channel: *ReliableOrderedChannel) -> bool {
    return oldestUnackedMessageId != sendMessageId;
}

/*
Get messages to include in a packet.
Messages are measured to see how many bits they take, and only messages that fit within the channel packet budget will be included. See ChannelConfig::packetBudget.
Takes care not to send messages too rapidly by respecting ChannelConfig::messageResendTime for each message, and to only include messages that that the receiver is able to buffer in their receive queue. In other words, won't run ahead of the receiver.
@param messageIds Array of message ids to be filled [out]. Fills up to ChannelConfig::maxMessagesPerPacket messages, make sure your array is at least this size.
@param numMessageIds The number of message ids written to the array.
@param remainingPacketBits Number of bits remaining in the packet. Considers this as a hard limit when determining how many messages can fit into the packet.
@returns Estimate of the number of bits required to serialize the messages (upper bound).
@see GetMessagePacketData
*/
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

/*
Fill channel packet data with messages.
This is the payload function to fill packet data while sending regular messages (without blocks attached).
Messages have references added to them when they are added to the packet. They also have a reference while they are stored in a send or receive queue. Messages are cleaned up when they are no longer in a queue, and no longer referenced by any packets.
@param packetData The packet data to fill [out]
@param messageIds Array of message ids identifying which messages to add to the packet from the message send queue.
@param numMessageIds The number of message ids in the array.
@see GetMessagesToSend
*/
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

/*
Add a packet entry for the set of messages included in a packet.
This lets us look up the set of messages that were included in that packet later on when it is acked, so we can ack those messages individually.
@param messageIds The set of message ids that were included in the packet.
@param numMessageIds The number of message ids in the array.
@param sequence The sequence number of the connection packet the messages were included in.
*/
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

/*
Process messages included in a packet.
Any messages that have not already been received are added to the message receive queue. Messages that are added to the receive queue have a reference added. See Message::AddRef.
@param numMessages The number of messages to process.
@param messages Array of pointers to messages.
*/
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

/*
Track the oldest unacked message id in the send queue.
Because messages are acked individually, the send queue is not a true queue and may have holes.
Because of this it is necessary to periodically walk forward from the previous oldest unacked message id, to find the current oldest unacked message id.
This lets us know our starting point for considering messages to include in the next packet we send.
@see GetMessagesToSend
*/
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

/*
True if we are currently sending a block message.
Block messages are treated differently to regular messages.
Regular messages are small so we try to fit as many into the packet we can. See ReliableChannelData::GetMessagesToSend.
Blocks attached to block messages are usually larger than the maximum packet size or channel budget, so they are split up fragments.
While in the mode of sending a block message, each channel packet data generated has exactly one fragment from the current block in it. Fragments keep getting included in packets until all fragments of that block are acked.
@returns True if currently sending a block message over the network, false otherwise.
@see BlockMessage
@see GetFragmentToSend
*/
channel_sending_block_message :: (using channel: *ReliableOrderedChannel) -> bool {
    assert(channel_has_messages_to_send(channel));

    entry := sequence_buffer_find(*messageSendQueue, oldestUnackedMessageId);
    return ifx entry != null then entry.message.blockData.count > 0 else false;
}

/*
Get the next block fragment to send.
The next block fragment is selected by scanning left to right over the set of fragments in the block, skipping over any fragments that have already been acked or have been sent within ChannelConfig::fragmentResendTime.
@param messageId The id of the message that the block is attached to [out].
@param fragmentId The id of the fragment to send [out].
@param fragmentBytes The size of the fragment in bytes.
@param numFragments The total number of fragments in this block.
@param messageType The type of message the block is attached to. See MessageFactory.
@returns Pointer to the fragment data.
*/
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

/*
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

/*
Adds a packet entry for the fragment.
This lets us look up the fragment that was in the packet later on when it is acked, so we can ack that block fragment.
@param messageId The message id that the block was attached to.
@param fragmentId The fragment id.
@param sequence The sequence number of the packet the fragment was included in.
*/
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

/*
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
SentPacketEntry :: struct {
    timeSent        : Apollo_Time;  // The time the packet was sent. Used to estimate round trip time.
    messageIds      : *u16;         // Pointer to sub-array of ReliableOrderedChannel.sentPacketMessageIds (do not alloc/free this here!). Dynamically allocated because the user can configure the maximum number of messages in a packet per-channel with ChannelConfig::maxMessagesPerPacket.
    numMessageIds   : u16;          // The number of message ids in the array.
    acked           : bool;         // true if this packet has been acked.
    block           : bool;         // true if this packet contains a fragment of a block message.
    blockMessageId  : u16;          // The block message id. Valid only if "block" is true.
    blockFragmentId : u16;          // The block fragment id. Valid only if "block" is true.
};

/*
Internal state for a block being sent across the reliable ordered channel.
Stores the block data and tracks which fragments have been acked. The block send completes when all fragments have been acked.
IMPORTANT: Although there can be multiple block messages in the message send and receive queues, only one data block can be in flights over the wire at a time.
*/
SendBlockData :: struct {
    active            : bool;            // True if we are currently sending a block.
    blockSize         : int;             // The size of the block (bytes).
    numFragments      : int;             // Number of fragments in the block being sent.
    numAckedFragments : int;             // Number of acked fragments in the block being sent.
    blockMessageId    : u16;             // The message id the block is attached to.
    ackedFragment     : BitArray;        // Has fragment n been received?
    fragmentSendTime  : [] Apollo_Time;  // Last time fragment was sent.
};

send_block_data_init :: (using sendBlockData: *SendBlockData, maxFragmentsPerBlock: int) {
    init_bit_array(*ackedFragment, maxFragmentsPerBlock);
    fragmentSendTime = NewArray(maxFragmentsPerBlock, Apollo_Time);
}

send_block_data_free :: (using sendBlockData: *SendBlockData) {
    deinit(*ackedFragment);
    array_free(fragmentSendTime);
}

send_block_data_reset :: (using sendBlockData: *SendBlockData) {
    active = false;
    blockSize = 0;
    numFragments = 0;
    numAckedFragments = 0;
    blockMessageId = 0;

    // Original code doesn't clear these, maybe it's not necessary? Should we do it anyway to make debugging easier?
    //clear_all_bits(*ackedFragment);
    //array_zero(fragmentSendTime);
}

/*
Internal state for a block being received across the reliable ordered channel.
Stores the fragments received over the network for the block, and completes once all fragments have been received.
IMPORTANT: Although there can be multiple block messages in the message send and receive queues, only one data block can be in flight over the wire at a time.
*/
ReceiveBlockData :: struct {
    active               : bool;           // True if we are currently receiving a block.
    numFragments         : int;            // The number of fragments in this block
    numReceivedFragments : int;            // The number of fragments received.
    messageId            : u16;            // The message id corresponding to the block.
    messageType          : int;            // Message type of the block being received.
    blockSize            : u32;            // Block size in bytes.
    receivedFragment     : BitArray;       // Has fragment n been received?
    blockData            : [] u8;          // Block data for receive.
    blockMessage         : *BlockMessage;  // Block message (sent with fragment 0).
};

receive_block_data_init :: (using receiveBlockData: *ReceiveBlockData, maxBlockSize: int, maxFragmentsPerBlock: int) {
    init_bit_array(*receivedFragment, maxFragmentsPerBlock);
    blockData = NewArray(maxBlockSize, u8);
}

receive_block_data_free :: (using receiveBlockData: *ReceiveBlockData) {
    deinit(*receivedFragment);
    array_free(blockData);
}

receive_block_data_reset :: (using receiveBlockData: *ReceiveBlockData) {
    active = false;
    numFragments = 0;
    numReceivedFragments = 0;
    messageId = 0;
    messageType = 0;
    blockSize = 0;

    // Original code doesn't clear these, maybe it's not necessary? Should we do it anyway to make debugging easier?
    //clear_all_bits(*receivedFragment);
    //array_zero(blockData);

    if blockMessage != null{
        free(blockMessage);
        blockMessage = null;
    }
}
