#scope_module

/*
Messages sent across this channel are not guaranteed to arrive, and may be received in a different order than they were sent.
This channel type is best used for time critical data like snapshots and object state.
*/
UnreliableUnorderedChannel :: struct {
    #as using base: Channel;

    messageSendQueue    : Queue(*Message);
    messageReceiveQueue : Queue(*Message);
}

/**
Reliable ordered channel constructor.
@param allocator The allocator to use.
@param messageFactory Message factory for creating and destroying messages.
@param config The configuration for this channel.
@param channelIndex The channel index in [0,numChannels-1].
*/
channel_init :: (using channel: *UnreliableUnorderedChannel, messageFactory: *MessageFactory, config: ChannelConfig, channelIndex: int, time: Apollo_Time) {
    assert(config.type == .UnreliableUnordered);

    channel_init(*base, messageFactory, config, channelIndex, time);
    queue_init(*messageSendQueue, config.messageSendQueueSize);
    queue_init(*messageReceiveQueue, config.messageReceiveQueueSize);
    channel_reset(channel);
}

/*
Unreliable unordered channel destructor.
Any messages still in the send or receive queues will be released.
*/
channel_free :: (using channel: *UnreliableUnorderedChannel) {
    channel_reset(channel);
}

channel_reset :: (using channel: *UnreliableUnorderedChannel) {
    errorLevel = .None;

    for 0..messageSendQueue.count-1 {
        free(messageSendQueue[it]);
    }

    for 0..messageReceiveQueue.count-1 {
        free(messageReceiveQueue[it]);
    }

    queue_clear(*messageSendQueue);
    queue_clear(*messageReceiveQueue);

    channel_reset_counters(channel);
}

channel_can_send_message :: (using channel: *UnreliableUnorderedChannel) -> bool {
    return !queue_full(*messageSendQueue);
}

channel_has_messages_to_send :: (using channel: *UnreliableUnorderedChannel) -> bool {
    return !queue_empty(*messageSendQueue);
}

channel_send_message :: (using channel: *UnreliableUnorderedChannel, message: *Message) {
    assert(message != null);
    assert(channel_can_send_message(channel));

    if errorLevel != .None {
        free(message);
        return;
    }

    if !channel_can_send_message(channel) {
        errorLevel = .SendQueueFull;
        free(message);
        return;
    }

    assert(message.blockData.count <= config.maxBlockSize);

    queue_push(*messageSendQueue, message);

    counters[ChannelCounter.MessagesSent] += 1;
}

channel_receive_message :: (using channel: *UnreliableUnorderedChannel) -> *Message {
    if errorLevel != .None {
        return null;
    }

    if queue_empty(*messageReceiveQueue) {
        return null;
    }

    counters[ChannelCounter.MessagesReceived] += 1;

    return queue_pop(*messageReceiveQueue);
}

channel_advance_time :: (using channel: *UnreliableUnorderedChannel, time: Apollo_Time) {
    // intentionally does nothing for unreliable channels
}

channel_generate_packet_data :: (using channel: *UnreliableUnorderedChannel, packetData: *ChannelPacketData, packetSequence: u16, availableBits: int) -> int {
    if queue_empty(*messageSendQueue) {
        return 0;
    }

    budgetedBits := availableBits;
    if config.packetBudget > 0 {
        budgetedBits = min(config.packetBudget * 8, availableBits);
    }

    giveUpBits := 4 * 8;

    assert(messageFactory.messages.count > 0);
    messageTypeBits := bits_required(0, cast(u64) messageFactory.messages.count - 1);

    usedBits := ConservativeMessageHeaderBits;
    numMessages = 0;
    messages := NewArray(config.maxMessagesPerPacket, *Message,, temp);

    while true {
        if queue_empty(*messageSendQueue) {
            break;
        }
        if budgetedBits - usedBits < giveUpBits {
            break;
        }
        if numMessages == config.maxMessagesPerPacket {
            break;
        }

        message := queue_pop(*messageSendQueue);
        assert(message != null);

        measureStream: MeasureStream;
        messageFactory.serializeRouter(measureStream, message);
        serialize_message_block(measureStream, message, config.maxBlockSize);

        messageBits := messageTypeBits + stream_get_bits_processed(measureStream);

        if usedBits + messageBits > budgetedBits {
            free(message);
            continue;
        }

        usedBits += messageBits;

        assert(usedBits <= budgetedBits);

        messages[numMessages] = message;
        numMessages += 1;
    }

    if numMessages == 0 {
        return 0;
    }

    packetData.channelIndex = channelIndex;
    packetData.message.numMessages = numMessages;
    packetData.message.messages = NewArray(numMessages, *Message);
    for 0..numMessages-1 {
        packetData.message.messages[it] = messages[it];
    }

    return usedBits;
}

channel_process_packet_data :: (channel: *UnreliableUnorderedChannel, packetData: ChannelPacketData, packetSequence: u16) {
    if errorLevel != .None {
        return;
    }

    if packetData.flags & .FailedToSerialize {
        errorLevel = .FailedToDeserialize;
        return;
    }

    for 0..packetData.message.numMessages-1 {
        message := packetData.message.messages[it];
        assert(message != null);
        message.id = packetSequence;
        if !queue_full(*messageReceiveQueue) {
            queue_push(*messageReceiveQueue, message);
        }
        // TODO(dlb): Else??? We should probably log a warning or something when queue is full.
    }
}

channel_process_ack :: (channel: *UnreliableUnorderedChannel, ack: u16) {
    // intentionally does nothing for unreliable channels
}