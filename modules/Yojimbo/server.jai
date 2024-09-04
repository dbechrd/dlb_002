#scope_module

/*
Server implementation.
*/
Server :: struct {
    #as using base: BaseServer;

    server       : *netcode_server_t;
    address      : Address;             // original address passed to ctor
    boundAddress : Address;             // address after socket bind, eg. valid port
    privateKey   : [KeyBytes] u8;
};

server_init :: (using server: *Server, _privateKey: [KeyBytes] u8, _address: Address, _config: ClientServerConfig, _time: Apollo_Time) {
    server_init(base, _config, _time);
    assert(KeyBytes == NETCODE_KEY_BYTES);
    privateKey = _privateKey;  //memcpy( m_privateKey, privateKey, NETCODE_KEY_BYTES ); do we need this?
    address = _address;
    boundAddress = _address;
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

    server = netcode_server_create(addressString, *netcodeConfig, GetTime());  // TODO: GetTime() ??

    if server == null {
        server_stop(server);
        return;
    }

    netcode_server_start(server, maxClients);
    boundAddress.port = netcode_server_get_port(server);
}

server_stop :: (using server: *Server) {
    if server != null {
        boundAddress = address;
        netcode_server_stop(server);
        netcode_server_destroy(server);
        server = null;
    }
    server_stop(base);
}

server_disconnect_client :: (using server: *Server, clientIndex: int) {
    assert(server);
    netcode_server_disconnect_client(server, clientIndex);
    server_reset_client(server, clientIndex);
}

server_disconnect_all_clients :: (using server: *Server) {
    assert(server);
    netcode_server_disconnect_all_clients(server);
    for 0..maxClients-1 {
        server_reset_client(server, it);
    }
}

void Server::SendPackets()
{
    if ( m_server )
    {
        const int maxClients = GetMaxClients();
        for ( int i = 0; i < maxClients; ++i )
        {
            if ( IsClientConnected( i ) )
            {
                uint8_t * packetData = GetPacketBuffer();
                int packetBytes;
                uint16_t packetSequence = reliable_endpoint_next_packet_sequence( GetClientEndpoint(i) );
                if ( GetClientConnection(i).GeneratePacket( GetContext(), packetSequence, packetData, m_config.maxPacketSize, packetBytes ) )
                {
                    reliable_endpoint_send_packet( GetClientEndpoint(i), packetData, packetBytes );
                }
            }
        }
    }
}

void Server::ReceivePackets()
{
    if ( m_server )
    {
        const int maxClients = GetMaxClients();
        for ( int clientIndex = 0; clientIndex < maxClients; ++clientIndex )
        {
            while ( true )
            {
                int packetBytes;
                uint64_t packetSequence;
                uint8_t * packetData = netcode_server_receive_packet( m_server, clientIndex, &packetBytes, &packetSequence );
                if ( !packetData )
                    break;
                reliable_endpoint_receive_packet( GetClientEndpoint( clientIndex ), packetData, packetBytes );
                netcode_server_free_packet( m_server, packetData );
            }
        }
    }
}

void Server::AdvanceTime( double time )
{
    if ( m_server )
    {
        netcode_server_update( m_server, time );
    }
    BaseServer::AdvanceTime( time );
    NetworkSimulator * networkSimulator = GetNetworkSimulator();
    if ( networkSimulator && networkSimulator->IsActive() )
    {
        uint8_t ** packetData = (uint8_t**) alloca( sizeof( uint8_t*) * m_config.maxSimulatorPackets );
        int * packetBytes = (int*) alloca( sizeof(int) * m_config.maxSimulatorPackets );
        int * to = (int*) alloca( sizeof(int) * m_config.maxSimulatorPackets );
        int numPackets = networkSimulator->ReceivePackets( m_config.maxSimulatorPackets, packetData, packetBytes, to );
        for ( int i = 0; i < numPackets; ++i )
        {
            netcode_server_send_packet( m_server, to[i], (uint8_t*) packetData[i], packetBytes[i] );
            YOJIMBO_FREE( networkSimulator->GetAllocator(), packetData[i] );
        }
    }
}

bool Server::IsClientConnected( int clientIndex ) const
{
    return netcode_server_client_connected( m_server, clientIndex ) != 0;
}

uint64_t Server::GetClientId( int clientIndex ) const
{
    return netcode_server_client_id( m_server, clientIndex );
}

const uint8_t * Server::GetClientUserData( int clientIndex ) const
{
    return (const uint8_t*)netcode_server_client_user_data( m_server, clientIndex );
}

netcode_address_t * Server::GetClientAddress( int clientIndex ) const
{
    return netcode_server_client_address( m_server, clientIndex );
}

int Server::GetNumConnectedClients() const
{
    return netcode_server_num_connected_clients( m_server );
}

void Server::ConnectLoopbackClient( int clientIndex, uint64_t clientId, const uint8_t * userData )
{
    netcode_server_connect_loopback_client( m_server, clientIndex, clientId, userData );
}

void Server::DisconnectLoopbackClient( int clientIndex )
{
    netcode_server_disconnect_loopback_client( m_server, clientIndex );
}

bool Server::IsLoopbackClient( int clientIndex ) const
{
    return netcode_server_client_loopback( m_server, clientIndex ) != 0;
}

void Server::ProcessLoopbackPacket( int clientIndex, const uint8_t * packetData, int packetBytes, uint64_t packetSequence )
{
    netcode_server_process_loopback_packet( m_server, clientIndex, packetData, packetBytes, packetSequence );
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

void Server::TransmitPacketFunction( int clientIndex, uint16_t packetSequence, uint8_t * packetData, int packetBytes )
{
    (void) packetSequence;
    NetworkSimulator * networkSimulator = GetNetworkSimulator();
    if ( networkSimulator && networkSimulator->IsActive() )
    {
        networkSimulator->SendPacket( clientIndex, packetData, packetBytes );
    }
    else
    {
        netcode_server_send_packet( m_server, clientIndex, packetData, packetBytes );
    }
}

int Server::ProcessPacketFunction( int clientIndex, uint16_t packetSequence, uint8_t * packetData, int packetBytes )
{
    return (int) GetClientConnection(clientIndex).ProcessPacket( GetContext(), packetSequence, packetData, packetBytes );
}

void Server::ConnectDisconnectCallbackFunction( int clientIndex, int connected )
{
    if ( connected == 0 )
    {
        GetAdapter().OnServerClientDisconnected( clientIndex );
        reliable_endpoint_reset( GetClientEndpoint( clientIndex ) );
        GetClientConnection( clientIndex ).Reset();
        NetworkSimulator * networkSimulator = GetNetworkSimulator();
        if ( networkSimulator && networkSimulator->IsActive() )
        {
            networkSimulator->DiscardClientPackets( clientIndex );
        }
    }
    else
    {
        GetAdapter().OnServerClientConnected( clientIndex );
    }
}

void Server::SendLoopbackPacketCallbackFunction( int clientIndex, const uint8_t * packetData, int packetBytes, uint64_t packetSequence )
{
    GetAdapter().ServerSendLoopbackPacket( clientIndex, packetData, packetBytes, packetSequence );
}

void Server::StaticConnectDisconnectCallbackFunction( void * context, int clientIndex, int connected )
{
    Server * server = (Server*) context;
    server->ConnectDisconnectCallbackFunction( clientIndex, connected );
}

void Server::StaticSendLoopbackPacketCallbackFunction( void * context, int clientIndex, const uint8_t * packetData, int packetBytes, uint64_t packetSequence )
{
    Server * server = (Server*) context;
    server->SendLoopbackPacketCallbackFunction( clientIndex, packetData, packetBytes, packetSequence );
}
