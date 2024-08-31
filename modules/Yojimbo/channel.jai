#scope_module

// If the channel gets into an error state, it sets an error state on the corresponding connection. See yojimbo::CONNECTION_ERROR_CHANNEL.
// This way if any channel on a client/server connection gets into a bad state, that client is automatically kicked from the server.
ChannelErrorLevel :: enum {
    None;                 // All is well.
    Desync;               // The connection protocol has desynced and cannot recover. The client should be disconnected.
    SendQueueFull;        // The user tried to send a message but the send queue was full. This will assert out in development, but in production it sets this error on the channel.
    BlocksDisabled;       // The channel received a packet containing data for blocks, but this channel is configured to disable blocks. See ChannelConfig::disableBlocks.
    FailedToDeserialize;  // Deserialize failed for a message sent to this channel. Check your message serialize functions, one of them is returning false when reading. This can also be caused by mismatched read/write logic.
    OutOfMemory;          // The channel tried to allocate some memory but couldn't.
};

// Channel counters provide insight into the number of times an action was performed by a channel.
// They are intended for use in a telemetry system, eg. reported to some backend logging system to track behavior in a production environment.
ChannelCounter :: enum {
    MessagesSent;      // Number of messages sent over this channel.
    MessagesReceived;  // Number of messages received over this channel.
    Count;             // The number of channel counters.
};

// Common functionality shared across all channel types.
Channel :: struct {
    config         : ChannelConfig;               // Channel configuration data.
    channelIndex   : m_channelIndex;              // The channel index in [0,numChannels-1].
    time           : Apollo_Time;                 // The current time.
    errorLevel     : ChannelErrorLevel;           // The channel error level.
    messageFactory : *MessageFactory;             // Message factory for creating and destroying messages.
    counters       : [ChannelCounter.Count] u64;  // Counters for unit testing, stats etc.
};

channel_init :: (channel: *Channel, messageFactory: *MessageFactory, config: ChannelConfig, channelIndex: int, time: Apollo_Time) {
    assert(channelIndex >= 0);
    assert(channelIndex < MaxChannels);

    channel.messageFactory = messageFactory;
    channel.config = config;
    channel.channelIndex = channelIndex;
    channel.time = time;
}

channel_destroy :: (channel: *Channel) {

}

channel_reset :: (channel: *Channel) {

}

channel_can_send_message :: (channel: *Channel) -> bool {

}

channel_has_messages_to_send :: (channel: *Channel) -> bool {

}

// Queue a message for send
channel_send_message :: (channel: *Channel) {

}

// Pops the next message off the receive queue if one is available.
// @returns A pointer to the received message, NULL if there are no messages to receive. The caller owns the message object returned by this function and is responsible for releasing it via Message::Release.
channel_receive_message :: (channel: *Channel) {

}

// Advance channel time
// Called by connection_advance_time for each channel configured on the connection.
channel_advance_time :: (channel: *Channel, time: Apollo_Time) {

}

// Get channel packet data for this channel.
// @param packetData The channel packet data to be filled [out]
// @param packetSequence The sequence number of the packet being generated.
// @param availableBits The maximum number of bits of packet data the channel is allowed to write.
// @returns The number of bits of packet data written by the channel.
// @see ConnectionPacket
// @see Connection::GeneratePacket
channel_get_packet_data :: (channel: *Channel, ctx: *void, packetData: *ChannelPacketData, packetSequence: u16, availableBits: int) {

}

// Process packet data included in a connection packet.
// @param packetData The channel packet data to process.
// @param packetSequence The sequence number of the connection packet that contains the channel packet data.
// @see ConnectionPacket
// @see Connection::ProcessPacket
channel_process_packet_data :: (channel: *Channel, packetData: *ChannelPacketData, packetSequence: u16) {

}

// Process a connection packet ack.
// Depending on the channel type:
//     1. Acks messages and block fragments so they stop being included in outgoing connection packets (reliable-ordered channel),
//     2. Does nothing at all (unreliable-unordered).
// @param sequence The sequence number of the connection packet that was acked.
channel_process_ack :: (channel: *Channel, sequence: u16) {

}

// Gets the channel index.
// @returns The channel index in [0,numChannels-1].
channel_get_index :: (channel: *Channel) -> int {
    return channel.channelIndex;
}

// Get the channel error level.
// @returns The channel error level.
channel_get_error_level :: (channel: *Channel) -> ChannelErrorLevel {
    return channel.errorLevel;
}

// Set the channel error level.
// All errors go through this function to make debug logging easier.
channel_set_error_level :: (channel: *Channel, errorLevel: ChannelErrorLevel) {
    if errorLevel != channel.errorLevel && errorLevel != .None {
        yojimbo_log(.ERROR, "channel went into error state: %s\n", errorLevel);
    }
    channel.errorLevel = errorLevel;
}

// Get a counter value.
// @param index The index of the counter to retrieve. See ChannelCounters.
// @returns The value of the counter.
// @see ResetCounters
channel_get_counter :: (channel: *Channel, counter: ChannelCounter) -> u64 {
    return channel.counters[counter];
}

// Resets all counter values to zero.
channel_reset_counters :: (channel: *Channel) {
    array_zero(channel.counters);
}
