#scope_module

/**
    Server implementation.
    */

class Server : public BaseServer
{
public:

    Server( Allocator & allocator, const uint8_t privateKey[], const Address & address, const ClientServerConfig & config, Adapter & adapter, double time );

    ~Server();

    void Start( int maxClients );

    void Stop();

    void DisconnectClient( int clientIndex );

    void DisconnectAllClients();

    void SendPackets();

    void ReceivePackets();

    void AdvanceTime( double time );

    bool IsClientConnected( int clientIndex ) const;

    uint64_t GetClientId( int clientIndex ) const;

    const uint8_t * GetClientUserData( int clientIndex ) const;

    netcode_address_t * GetClientAddress( int clientIndex ) const;

    int GetNumConnectedClients() const;

    void ConnectLoopbackClient( int clientIndex, uint64_t clientId, const uint8_t * userData );

    void DisconnectLoopbackClient( int clientIndex );

    bool IsLoopbackClient( int clientIndex ) const;

    void ProcessLoopbackPacket( int clientIndex, const uint8_t * packetData, int packetBytes, uint64_t packetSequence );

    const Address & GetAddress() const { return m_boundAddress; }

private:

    void TransmitPacketFunction( int clientIndex, uint16_t packetSequence, uint8_t * packetData, int packetBytes );

    int ProcessPacketFunction( int clientIndex, uint16_t packetSequence, uint8_t * packetData, int packetBytes );

    void ConnectDisconnectCallbackFunction( int clientIndex, int connected );

    void SendLoopbackPacketCallbackFunction( int clientIndex, const uint8_t * packetData, int packetBytes, uint64_t packetSequence );

    static void StaticConnectDisconnectCallbackFunction( void * context, int clientIndex, int connected );

    static void StaticSendLoopbackPacketCallbackFunction( void * context, int clientIndex, const uint8_t * packetData, int packetBytes, uint64_t packetSequence );

    ClientServerConfig m_config;
    netcode_server_t * m_server;
    Address m_address;                                  // original address passed to ctor
    Address m_boundAddress;                             // address after socket bind, eg. valid port
    uint8_t m_privateKey[KeyBytes];
};

Server::Server( Allocator & allocator, const uint8_t privateKey[], const Address & address, const ClientServerConfig & config, Adapter & adapter, double time )
    : BaseServer( allocator, config, adapter, time )
{
    yojimbo_assert( KeyBytes == NETCODE_KEY_BYTES );
    memcpy( m_privateKey, privateKey, NETCODE_KEY_BYTES );
    m_address = address;
    m_boundAddress = address;
    m_config = config;
    m_server = NULL;
}

Server::~Server()
{
    // IMPORTANT: Please stop the server before destroying it!
    yojimbo_assert( !m_server );
}

void Server::Start( int maxClients )
{
    if ( IsRunning() )
        Stop();

    BaseServer::Start( maxClients );

    char addressString[MaxAddressLength];
    m_address.ToString( addressString, MaxAddressLength );

    struct netcode_server_config_t netcodeConfig;
    netcode_default_server_config(&netcodeConfig);
    netcodeConfig.protocol_id = m_config.protocolId;
    memcpy(netcodeConfig.private_key, m_privateKey, NETCODE_KEY_BYTES);
    netcodeConfig.allocator_context = &GetGlobalAllocator();
    netcodeConfig.allocate_function = StaticAllocateFunction;
    netcodeConfig.free_function     = StaticFreeFunction;
    netcodeConfig.callback_context = this;
    netcodeConfig.connect_disconnect_callback = StaticConnectDisconnectCallbackFunction;
    netcodeConfig.send_loopback_packet_callback = StaticSendLoopbackPacketCallbackFunction;

    m_server = netcode_server_create(addressString, &netcodeConfig, GetTime());

    if ( !m_server )
    {
        Stop();
        return;
    }

    netcode_server_start( m_server, maxClients );

    m_boundAddress.SetPort( netcode_server_get_port( m_server ) );
}

void Server::Stop()
{
    if ( m_server )
    {
        m_boundAddress = m_address;
        netcode_server_stop( m_server );
        netcode_server_destroy( m_server );
        m_server = NULL;
    }
    BaseServer::Stop();
}

void Server::DisconnectClient( int clientIndex )
{
    yojimbo_assert( m_server );
    netcode_server_disconnect_client( m_server, clientIndex );
    ResetClient( clientIndex );
}

void Server::DisconnectAllClients()
{
    yojimbo_assert( m_server );
    netcode_server_disconnect_all_clients( m_server );
    const int maxClients = GetMaxClients();
    for ( int i = 0; i < maxClients; ++i )
    {
        ResetClient( i );
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