#scope_module

/*
Common functionality across all server implementations.
*/
BaseServer :: struct {
    config               : ClientServerConfig;                 // Base client/server config.
    time                 : Apollo_Time;                        // Current server time in seconds.
    maxClients           : int;                                // Maximum number of clients supported.
    running              : bool;                               // True if server is currently running, eg. after "Start" is called, before "Stop".
    clientMessageFactory : [MaxClients] *MessageFactory;       // Array of per-client message factories. This silos message allocations per-client slot.
    clientConnection     : [MaxClients] *Connection;           // Array of per-client connection classes. This is how messages are exchanged with clients.
    clientEndpoint       : [MaxClients] *reliable_endpoint_t;  // Array of per-client reliable endpoints.
    networkSimulator     : *NetworkSimulator;                  // The network simulator used to simulate packet loss, latency, jitter etc. Optional.
    packetBuffer         : [] u8;                              // Buffer used when writing packets.

    // callbacks for packet read/write
    transmitPacketFunction : TransmitPacketFunction;
    processPacketFunction  : ProcessPacketFunction;
};

server_init :: (using server: *BaseServer, _config: ClientServerConfig, _time: Apollo_Time) {
    config = _config;
    time = _time;
}

server_free :: (using server: *BaseServer) {
    // IMPORTANT: Please stop the server before destroying it!
    assert(!running);
}

// TODO(dlb): It seems weird to me that we pass `time` to server_init instead of to server_start. Perhaps
// we could consider refactoring that later. For now, it's parity with the C++ version.
server_start :: (using server: *BaseServer, _maxClients: int) {
    server_stop(server);
    running = true;
    maxClients = _maxClients;
    if config.networkSimulator {
        networkSimulator = New(NetworkSimulator);
        network_simulator_init(networkSimulator, config.maxSimulatorPackets, time);
    }
    for 0..maxClients-1 {
        clientMessageFactory[it] = New(MessageFactory);
        clientConnection[it] = New(Connection);
        connection_init(clientConnection[it], clientMessageFactory[it], config, time);

        reliable_config: reliable_config_t;
        reliable_config.name = "server endpoint";
        reliable_config.context = cast(*void) server;
        reliable_config.id = it;
        reliable_config.max_packet_size = config.maxPacketSize;
        reliable_config.fragment_above = config.fragmentPacketsAbove;
        reliable_config.max_fragments = client_server_config_get_max_packet_fragments(*config);
        reliable_config.fragment_size = config.packetFragmentSize;
        reliable_config.ack_buffer_size = config.ackedPacketsBufferSize;
        reliable_config.received_packets_buffer_size = config.receivedPacketsBufferSize;
        reliable_config.fragment_reassembly_buffer_size = config.packetReassemblyBufferSize;
        reliable_config.rtt_smoothing_factor = config.rttSmoothingFactor;
        reliable_config.transmit_packet_function = transmitPacketFunction;
        reliable_config.process_packet_function = processPacketFunction;

        clientEndpoint[it] = reliable_endpoint_create(*reliable_config, time);
        reliable_endpoint_reset(clientEndpoint[it]);
    }
    packetBuffer = New(config.maxPacketSize, u8);
}

server_stop :: (using server: *BaseServer) {
    if !running {
        return;
    }

    array_reset(*packetBuffer);
    if networkSimulator != null {
        free(networkSimulator);
    }
    for 0..maxClients-1 {
        reliable_endpoint_destroy(clientEndpoint[it]);
        clientEndpoint[it] = NULL;

        free(clientConnection[it]);
        free(clientMessageFactory[it]);
    }
    maxClients = 0;
    running = false;
}

server_advance_time :: (using server: *BaseServer, _time: Apollo_Time) {
    time = _time;
    if !running {
        return;
    }

    for 0..maxClients-1 {
        connection_advance_time(clientConnection[it], time);
        if clientConnection[it].errorLevel != .None {
            yojimbo_log(.ERROR, "client % connection is in error state. disconnecting client\n", it);
            server_disconnect_client(server, it);
            continue;
        }
        reliable_endpoint_update(clientEndpoint[it], time);
        acks := reliable_endpoint_get_acks(clientEndpoint[it]);
        connection_process_acks(clientConnection[it], acks);
        reliable_endpoint_clear_acks(clientEndpoint[it]);
    }
    if networkSimulator != null {
        network_simulator_advance_time(networkSimulator, time);
    }
}

server_create_message :: (using server: *BaseServer, clientIndex: int, type: int) -> *Message {
    assert(clientIndex >= 0);
    assert(clientIndex < maxClients);
    assert(clientMessageFactory[clientIndex] != null);

    return message_factory_create_message(clientMessageFactory[clientIndex], type);
}

// TODO(dlb)[cleanup]: Idk who's using this, but beat them with a stick until they stop, then remove this.
server_allocate_block :: (server: *BaseServer, clientIndex: int, bytes: int) {
    assert(false, "Just call NewArray() you fool.");
}

// TODO(dlb)[cleanup]: Idk who's using this, but beat them with a stick until they stop, then remove this.
server_attack_block_to_message :: (server: *BaseServer, clientIndex: int, message: *Message, blockData: [] u8) {
    assert(false, "Just attach it to message.blockData yourself you fool.");
}

// TODO(dlb)[cleanup]: Idk who's using this, but beat them with a stick until they stop, then remove this.
server_free_block :: (server: *BaseServer, clientIndex: int, block: *u8) {
    assert(false, "Just call free() you fool.");
}

// TODO(dlb)[cleanup]: Idk who's using this, but beat them with a stick until they stop, then remove this.
server_release_message :: (using server: *BaseServer, message: *Message) {
    assert(false, "Just call free() you fool.");
}

server_get_network_info :: (using server: *BaseServer, clientIndex: int, info: *NetworkInfo) {
    assert(false, "Call this on the subtype");
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// TODO(dlb)[cleanup]: These are all really pointless wrappers.. Delete all this OOP shit.
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
server_can_send_message :: (using server: *BaseServer, clientIndex: int, channelIndex: int) -> bool {
    assert(clientIndex >= 0);
    assert(clientIndex < maxClients);
    assert(clientConnection[clientIndex] != null);

    connection_can_send_message(clientConnection[clientIndex], channelIndex);
}

server_has_messages_to_send :: (using server: *BaseServer, clientIndex: int, channelIndex: int) -> bool {
    assert(clientIndex >= 0);
    assert(clientIndex < maxClients);
    assert(clientConnection[clientIndex] != null);

    connection_has_messages_to_send(clientConnection[clientIndex], channelIndex);
}

server_send_message :: (using server: *BaseServer, clientIndex: int, channelIndex: int, message: *Message) {
    assert(clientIndex >= 0);
    assert(clientIndex < maxClients);
    assert(clientConnection[clientIndex] != null);

    connection_send_message(clientConnection[clientIndex], channelIndex, message);
}

server_send_message :: (using server: *BaseServer, clientIndex: int, channelIndex: int) -> *Message {
    assert(clientIndex >= 0);
    assert(clientIndex < maxClients);
    assert(clientConnection[clientIndex] != null);

    connection_receive_message(clientConnection[clientIndex], channelIndex);
}

server_reset_client :: (using server: *BaseServer, clientIndex: int) {
    assert(clientIndex >= 0);
    assert(clientIndex < maxClients);
    assert(clientConnection[clientIndex] != null);

    connection_reset(clientConnection[clientIndex]);
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
