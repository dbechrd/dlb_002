#scope_module

/*
Server implementation.
*/
Server :: struct {
    #as using base: BaseServer;

    netServer    : *netcode_server_t;
    address      : Address;             // original address passed to ctor
    boundAddress : Address;             // address after socket bind, eg. valid port
    privateKey   : [KeyBytes] u8;

    /*
    Override this to get a callback when a client connects on the server.
    */
    onClientConnected :: #type (server: *Server, clientIndex: int);

    /*
    Override this to get a callback when a client disconnects from the server.
    */
    onClientDisconnected :: #type (server: *Server, clientIndex: int);

    /*
    Override this callback to process packets sent from client to server over loopback.
    @param clientIndex The client index in range [0,maxClients-1]
    @param packetData The packet data (raw) to be sent to the server.
    @param packetBytes The number of packet bytes in the server.
    @param packetSequence The sequence number of the packet.
    @see Server::ConnectLoopbackClient
    */
    onServerSendLoopbackPacket :: #type (server: *Server, clientIndex: int, packetData: [] u8, packetSequence: u64);

};

server_init :: (using server: *Server, _privateKey: [KeyBytes] u8, _address: Address, _config: ClientServerConfig, _time: Apollo_Time) {
    server_init(base, _config, _time);
    assert(KeyBytes == NETCODE_KEY_BYTES);
    privateKey = _privateKey;  //memcpy( m_privateKey, privateKey, NETCODE_KEY_BYTES ); do we need this?
    address = _address;
    boundAddress = _address;
    transmitPacketFunction = server_transmit_packet_function;
    processPacketFunction = server_process_packet_function;
}

server_free :: (using server: *Server) {
    // IMPORTANT: Please stop the server before destroying it!
    assert(server == null);
}

server_start :: (using server: *Server, _maxClients: int) {
    if running {
        server_stop(server);
    }

    server_start(base, _maxClients);

    addressString := address_to_string(address);

    netcodeConfig: netcode_server_config_t;
    netcodeConfig.protocol_id = config.protocolId;
    netcodeConfig.private_key = privateKey;  // memcpy(netcodeConfig.private_key, privateKey, NETCODE_KEY_BYTES); do we need this?
    netcodeConfig.callback_context = cast(*void) server;
    netcodeConfig.connect_disconnect_callback = server_connect_disconnect_callback;
    netcodeConfig.send_loopback_packet_callback = server_send_loopback_packet_callback;

    netServer = netcode_server_create(addressString, *netcodeConfig, time);

    if netServer == null {
        server_stop(server);
        return;
    }

    netcode_server_start(netServer, maxClients);
    boundAddress.port = netcode_server_get_port(netServer);
}

server_stop :: (using server: *Server) {
    if netServer != null {
        boundAddress = address;
        netcode_server_stop(netServer);
        netcode_server_destroy(netServer);
        netServer = null;
    }
    server_stop(base);
}

server_disconnect_client :: (using server: *Server, clientIndex: int) {
    assert(netServer != null);

    netcode_server_disconnect_client(netServer, clientIndex);
    server_reset_client(server, clientIndex);
}

server_disconnect_all_clients :: (using server: *Server) {
    assert(netServer != null);

    netcode_server_disconnect_all_clients(netServer);
    for 0..maxClients-1 {
        server_reset_client(server, it);
    }
}

server_send_packets :: (using server: *Server) {
    if netServer != null {
        0..maxClients-1 {
            if server_is_client_connected(it) {
                packetData := packetBuffer;
                packetBytes: int;
                packetSequence := reliable_endpoint_next_packet_sequence(clientEndpoint(it));
                if connection_generate_packet(clientConnection[it], packetSequence, packetData, *packetBytes) {
                    reliable_endpoint_send_packet(clientEndpoint(it), .{ packetBytes, packetData });
                }
            }
        }
    }
}

server_receive_packets :: (using server: *Server) {
    if netServer != null {
        for 0..maxClients-1 {
            while true {
                packetBytes: int;
                packetSequence: u64;
                packetData := netcode_server_receive_packet(netServer, it, *packetBytes, *packetSequence);
                if packetData.count == 0 {
                    break;
                }

                reliable_endpoint_receive_packet(clientEndpoint[it], .{ packetBytes, packetData });
                netcode_server_free_packet(netServer, packetData);
            }
        }
    }
}

server_advance_time :: (using server: *Server, _time: Apollo_Time) {
    if netServer != null {
        netcode_server_update(netServer, _time);
    }
    server_advance_time(base, _time);
    if networkSimulator != null && network_simulator_is_active(networkSimulator) {
        packetData := NewArray(config.maxSimulatorPackets, [] u8,, temp);
        to := NewArray(config.maxSimulatorPackets, int);
        numPackets := network_simulator_receive_packets(networkSimulator, config.maxSimulatorPackets, packetData, to);
        for 0..numPackets-1 {
            netcode_server_send_packet(netServer, to[it], packetData[it]);
            array_free(packetData[it]);
        }
    }
}

server_is_client_connected :: (using server: *Server, clientIndex: int) {
    return netcode_server_client_connected(netServer, clientIndex) != 0;
}

server_get_client_id :: (using server: *Server, clientIndex: int) -> u64 {
    return netcode_server_client_id(netServer, clientIndex);
}

// dafuq this for? should it return *u8 or [] u8?
server_get_client_user_data :: (using server: *Server, clientIndex: int) -> [] u8 {
    return netcode_server_client_user_data(netServer, clientIndex);
}

server_get_client_address :: (using server: *Server, clientIndex: int) -> *netcode_address_t {
    return netcode_server_client_address(netServer, clientIndex);
}

server_get_num_connected_clients :: () -> int {
    return netcode_server_num_connected_clients(netServer);
}

server_connect_loopback_client :: (using server: *Server, clientIndex: int, clientId: u64, userData: [] u8) {
    netcode_server_connect_loopback_client(netServer, clientIndex, clientId, userData);
}

server_disconnect_loopback_client :: (using server: *Server, clientIndex: int) {
    netcode_server_disconnect_loopback_client(netServer, clientIndex);
}

server_is_loopback_client :: (using server: *Server, clientIndex: int) -> bool {
    return netcode_server_client_loopback(netServer, clientIndex) != 0;
}

server_process_loopback_client :: (using server: *Server, clientIndex: int, packetData: [] u8, packetSequence: u64) {
    netcode_server_process_loopback_packet(netServer, clientIndex, packetData, packetBytes, packetSequence);
}

server_get_network_info :: (using server: *Server, clientIndex: int, info: *NetworkInfo) {
    assert(running);
    assert(clientIndex >= 0);
    assert(clientIndex < maxClients);

    if server_is_client_connected(server, clientIndex) {
        assert(clientEndpoint[clientIndex] != null);

        counters := reliable_endpoint_counters(clientEndpoint[clientIndex]);
        info.numPacketsSent = counters[RELIABLE_ENDPOINT_COUNTER_NUM_PACKETS_SENT];
        info.numPacketsReceived = counters[RELIABLE_ENDPOINT_COUNTER_NUM_PACKETS_RECEIVED];
        info.numPacketsAcked = counters[RELIABLE_ENDPOINT_COUNTER_NUM_PACKETS_ACKED];
        info.RTT = reliable_endpoint_rtt(clientEndpoint[clientIndex]);
        info.packetLoss = reliable_endpoint_packet_loss(clientEndpoint[clientIndex]);
        info.sentBandwidth, info.receivedBandwidth, info.ackedBandwidth = reliable_endpoint_bandwidth(clientEndpoint[clientIndex]);
    }
}

#scope_file

server_transmit_packet_function :: (ctx: *void, clientIndex: int, packetSequence: u16, packetData: [] u8) {
    using server := cast(*Server) ctx;

    if networkSimulator != null && network_simulator_is_active(networkSimulator) {
        network_simulator_send_packet(networkSimulator, clientIndex, packetData);
    } else {
        netcode_server_send_packet(netServer, clientIndex, packetData);
    }
}

server_process_packet_function :: (ctx: *void, clientIndex: int, packetSequence: u16, packetData: [] u8) -> {
    using server := cast(*Server) ctx;

    return cast(int) connection_process_packet(clientConnection[clientIndex], packetSequence, packetData);
}

server_connect_disconnect_callback :: (ctx: *void, clientIndex: int, connected: int) {
    using server := cast(*Server) ctx;

    if connected == 0 {
        // TODO(dlb): Callback null check?
        onClientDisconnected(server, clientIndex);
        reliable_endpoint_reset(clientEndpoint[clientIndex]);
        connection_reset(clientConnection[clientIndex]);
        if networkSimulator != null && network_simulator_is_active(networkSimulator) {
            network_simulator_discard_client_packets(networkSimulator, clientIndex);
        }
    } else {
        // TODO(dlb): Callback null check?
        onClientConnected(server, clientIndex);
    }
}

server_send_loopback_packet_callback :: (ctx: *void, clientIndex: int, packetData: [] u8, packetSequence: u64) {
    using server := cast(*Server) ctx;

    // TODO(dlb): Callback null check?
    onServerSendLoopbackPacket(server, clientIndex, packetData, packetSequence);
}
