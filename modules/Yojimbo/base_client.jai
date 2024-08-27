#scope_module

/**
    Functionality that is common across all client implementations.
    */

class BaseClient : public ClientInterface
{
public:

    /**
        Base client constructor.
        @param allocator The allocator for all memory used by the client.
        @param config The base client/server configuration.
        @param time The current time in seconds. See ClientInterface::AdvanceTime
        @param allocator The adapter to the game program. Specifies allocators, message factory to use etc.
        */

    explicit BaseClient( class Allocator & allocator, const ClientServerConfig & config, class Adapter & adapter, double time );

    ~BaseClient();

    void SetContext( void * context ) { yojimbo_assert( IsDisconnected() ); m_context = context; }

    void Disconnect();

    void AdvanceTime( double time );

    bool IsConnecting() const { return m_clientState == CLIENT_STATE_CONNECTING; }

    bool IsConnected() const { return m_clientState == CLIENT_STATE_CONNECTED; }

    bool IsDisconnected() const { return m_clientState <= CLIENT_STATE_DISCONNECTED; }

    bool ConnectionFailed() const { return m_clientState == CLIENT_STATE_ERROR; }

    ClientState GetClientState() const { return m_clientState; }

    int GetClientIndex() const { return m_clientIndex; }

    double GetTime() const { return m_time; }

    void SetLatency( float milliseconds );

    void SetJitter( float milliseconds );

    void SetPacketLoss( float percent );

    void SetDuplicates( float percent );

    Message * CreateMessage( int type );

    uint8_t * AllocateBlock( int bytes );

    void AttachBlockToMessage( Message * message, uint8_t * block, int bytes );

    void FreeBlock( uint8_t * block );

    bool CanSendMessage( int channelIndex ) const;

    bool HasMessagesToSend( int channelIndex ) const;

    void SendMessage( int channelIndex, Message * message );

    Message * ReceiveMessage( int channelIndex );

    void ReleaseMessage( Message * message );

    void GetNetworkInfo( NetworkInfo & info ) const;

protected:

    uint8_t * GetPacketBuffer() { return m_packetBuffer; }

    void * GetContext() { return m_context; }

    Adapter & GetAdapter() { yojimbo_assert( m_adapter ); return *m_adapter; }

    void CreateInternal();

    void DestroyInternal();

    void SetClientState( ClientState clientState );

    class Allocator & GetClientAllocator() { yojimbo_assert( m_clientAllocator ); return *m_clientAllocator; }

    class MessageFactory & GetMessageFactory() { yojimbo_assert( m_messageFactory ); return *m_messageFactory; }

    class NetworkSimulator * GetNetworkSimulator() { return m_networkSimulator; }

    reliable_endpoint_t * GetEndpoint() { return m_endpoint; }

    class Connection & GetConnection() { yojimbo_assert( m_connection ); return *m_connection; }

    virtual void TransmitPacketFunction( uint16_t packetSequence, uint8_t * packetData, int packetBytes ) = 0;

    virtual int ProcessPacketFunction( uint16_t packetSequence, uint8_t * packetData, int packetBytes ) = 0;

    static void StaticTransmitPacketFunction( void * context, uint64_t index, uint16_t packetSequence, uint8_t * packetData, int packetBytes );

    static int StaticProcessPacketFunction( void * context, uint64_t index, uint16_t packetSequence, uint8_t * packetData, int packetBytes );

    static void * StaticAllocateFunction( void * context, size_t bytes );

    static void StaticFreeFunction( void * context, void * pointer );

protected:

    virtual void Reset();

private:

    ClientServerConfig m_config;                                        ///< The client/server configuration.
    Allocator * m_allocator;                                            ///< The allocator passed to the client on creation.
    Adapter * m_adapter;                                                ///< The adapter specifies the allocator to use, and the message factory class.
    void * m_context;                                                   ///< Context lets the user pass information to packet serialize functions.
    uint8_t * m_clientMemory;                                           ///< The memory backing the client allocator. Allocated from m_allocator.
    Allocator * m_clientAllocator;                                      ///< The client allocator. Everything allocated between connect and disconnected is allocated and freed via this allocator.
    reliable_endpoint_t * m_endpoint;                                   ///< reliable endpoint.
    MessageFactory * m_messageFactory;                                  ///< The client message factory. Created and destroyed on each connection attempt.
    Connection * m_connection;                                          ///< The client connection for exchanging messages with the server.
    NetworkSimulator * m_networkSimulator;                              ///< The network simulator used to simulate packet loss, latency, jitter etc. Optional.
    ClientState m_clientState;                                          ///< The current client state. See ClientInterface::GetClientState
    int m_clientIndex;                                                  ///< The client slot index on the server [0,maxClients-1]. -1 if not connected.
    double m_time;                                                      ///< The current client time. See ClientInterface::AdvanceTime
    uint8_t * m_packetBuffer;                                           ///< Buffer used to read and write packets.

private:

    BaseClient( const BaseClient & other );

    const BaseClient & operator = ( const BaseClient & other );
};

BaseClient::BaseClient( Allocator & allocator, const ClientServerConfig & config, Adapter & adapter, double time ) : m_config( config )
{
    m_allocator = &allocator;
    m_adapter = &adapter;
    m_time = time;
    m_context = NULL;
    m_clientMemory = NULL;
    m_clientAllocator = NULL;
    m_endpoint = NULL;
    m_connection = NULL;
    m_messageFactory = NULL;
    m_networkSimulator = NULL;
    m_clientState = CLIENT_STATE_DISCONNECTED;
    m_clientIndex = -1;
    m_packetBuffer = (uint8_t*) YOJIMBO_ALLOCATE( allocator, config.maxPacketSize );
}

BaseClient::~BaseClient()
{
    // IMPORTANT: Please disconnect the client before destroying it
    yojimbo_assert( m_clientState <= CLIENT_STATE_DISCONNECTED );
    YOJIMBO_FREE( *m_allocator, m_packetBuffer );
    m_allocator = NULL;
}

void BaseClient::Disconnect()
{
    SetClientState( CLIENT_STATE_DISCONNECTED );
    Reset();
}

void BaseClient::AdvanceTime( double time )
{
    m_time = time;
    if ( m_endpoint )
    {
        m_connection->AdvanceTime( time );
        if ( m_connection->GetErrorLevel() != CONNECTION_ERROR_NONE )
        {
            yojimbo_printf( YOJIMBO_LOG_LEVEL_DEBUG, "connection error. disconnecting client\n" );
            Disconnect();
            return;
        }
        reliable_endpoint_update( m_endpoint, m_time );
        int numAcks;
        const uint16_t * acks = reliable_endpoint_get_acks( m_endpoint, &numAcks );
        m_connection->ProcessAcks( acks, numAcks );
        reliable_endpoint_clear_acks( m_endpoint );
    }
    NetworkSimulator * networkSimulator = GetNetworkSimulator();
    if ( networkSimulator )
    {
        networkSimulator->AdvanceTime( time );
    }
}

void BaseClient::SetLatency( float milliseconds )
{
    if ( m_networkSimulator )
    {
        m_networkSimulator->SetLatency( milliseconds );
    }
}

void BaseClient::SetJitter( float milliseconds )
{
    if ( m_networkSimulator )
    {
        m_networkSimulator->SetJitter( milliseconds );
    }
}

void BaseClient::SetPacketLoss( float percent )
{
    if ( m_networkSimulator )
    {
        m_networkSimulator->SetPacketLoss( percent );
    }
}

void BaseClient::SetDuplicates( float percent )
{
    if ( m_networkSimulator )
    {
        m_networkSimulator->SetDuplicates( percent );
    }
}

void BaseClient::SetClientState( ClientState clientState )
{
    m_clientState = clientState;
}

void BaseClient::CreateInternal()
{
    yojimbo_assert( m_allocator );
    yojimbo_assert( m_adapter );
    yojimbo_assert( m_clientMemory == NULL );
    yojimbo_assert( m_clientAllocator == NULL );
    yojimbo_assert( m_messageFactory == NULL );
    m_clientMemory = (uint8_t*) YOJIMBO_ALLOCATE( *m_allocator, m_config.clientMemory );
    m_clientAllocator = m_adapter->CreateAllocator( *m_allocator, m_clientMemory, m_config.clientMemory );
    m_messageFactory = m_adapter->CreateMessageFactory( *m_clientAllocator );
    m_connection = YOJIMBO_NEW( *m_clientAllocator, Connection, *m_clientAllocator, *m_messageFactory, m_config, m_time );
    yojimbo_assert( m_connection );
    if ( m_config.networkSimulator )
    {
        m_networkSimulator = YOJIMBO_NEW( *m_clientAllocator, NetworkSimulator, *m_clientAllocator, m_config.maxSimulatorPackets, m_time );
    }
    reliable_config_t reliable_config;
    reliable_default_config( &reliable_config );
    yojimbo_copy_string( reliable_config.name, "client endpoint", sizeof( reliable_config.name ) );
    reliable_config.context = (void*) this;
    reliable_config.max_packet_size = m_config.maxPacketSize;
    reliable_config.fragment_above = m_config.fragmentPacketsAbove;
    reliable_config.max_fragments = m_config.maxPacketFragments;  // client_server_config_get_max_packet_fragments(*m_config)
    reliable_config.fragment_size = m_config.packetFragmentSize;
    reliable_config.ack_buffer_size = m_config.ackedPacketsBufferSize;
    reliable_config.received_packets_buffer_size = m_config.receivedPacketsBufferSize;
    reliable_config.fragment_reassembly_buffer_size = m_config.packetReassemblyBufferSize;
    reliable_config.rtt_smoothing_factor = m_config.rttSmoothingFactor;
    reliable_config.transmit_packet_function = BaseClient::StaticTransmitPacketFunction;
    reliable_config.process_packet_function = BaseClient::StaticProcessPacketFunction;
    reliable_config.allocator_context = m_clientAllocator;
    reliable_config.allocate_function = BaseClient::StaticAllocateFunction;
    reliable_config.free_function = BaseClient::StaticFreeFunction;
    m_endpoint = reliable_endpoint_create( &reliable_config, m_time );
    reliable_endpoint_reset( m_endpoint );
}

void BaseClient::DestroyInternal()
{
    yojimbo_assert( m_allocator );
    if ( m_endpoint )
    {
        reliable_endpoint_destroy( m_endpoint );
        m_endpoint = NULL;
    }
    YOJIMBO_DELETE( *m_clientAllocator, NetworkSimulator, m_networkSimulator );
    YOJIMBO_DELETE( *m_clientAllocator, Connection, m_connection );
    YOJIMBO_DELETE( *m_clientAllocator, MessageFactory, m_messageFactory );
    YOJIMBO_DELETE( *m_allocator, Allocator, m_clientAllocator );
    YOJIMBO_FREE( *m_allocator, m_clientMemory );
}

void BaseClient::StaticTransmitPacketFunction( void * context, uint64_t index, uint16_t packetSequence, uint8_t * packetData, int packetBytes )
{
    (void) index;
    BaseClient * client = (BaseClient*) context;
    client->TransmitPacketFunction( packetSequence, packetData, packetBytes );
}

int BaseClient::StaticProcessPacketFunction( void * context, uint64_t index, uint16_t packetSequence, uint8_t * packetData, int packetBytes )
{
    (void) index;
    BaseClient * client = (BaseClient*) context;
    return client->ProcessPacketFunction( packetSequence, packetData, packetBytes );
}

void * BaseClient::StaticAllocateFunction( void * context, size_t bytes )
{
    yojimbo_assert( context );
    Allocator * allocator = (Allocator*) context;
    return YOJIMBO_ALLOCATE( *allocator, bytes );
}

void BaseClient::StaticFreeFunction( void * context, void * pointer )
{
    yojimbo_assert( context );
    yojimbo_assert( pointer );
    Allocator * allocator = (Allocator*) context;
    YOJIMBO_FREE( *allocator, pointer );
}

Message * BaseClient::CreateMessage( int type )
{
    yojimbo_assert( m_messageFactory );
    return m_messageFactory->CreateMessage( type );
}

uint8_t * BaseClient::AllocateBlock( int bytes )
{
    return (uint8_t*) YOJIMBO_ALLOCATE( *m_clientAllocator, bytes );
}

void BaseClient::AttachBlockToMessage( Message * message, uint8_t * block, int bytes )
{
    yojimbo_assert( message );
    yojimbo_assert( block );
    yojimbo_assert( bytes > 0 );
    yojimbo_assert( message->IsBlockMessage() );
    BlockMessage * blockMessage = (BlockMessage*) message;
    blockMessage->AttachBlock( *m_clientAllocator, block, bytes );
}

void BaseClient::FreeBlock( uint8_t * block )
{
    YOJIMBO_FREE( *m_clientAllocator, block );
}

bool BaseClient::CanSendMessage( int channelIndex ) const
{
    yojimbo_assert( m_connection );
    return m_connection->CanSendMessage( channelIndex );
}

bool BaseClient::HasMessagesToSend( int channelIndex ) const
{
    yojimbo_assert( m_connection );
    return m_connection->HasMessagesToSend( channelIndex );
}

void BaseClient::SendMessage( int channelIndex, Message * message )
{
    yojimbo_assert( m_connection );
    m_connection->SendMessage( channelIndex, message, GetContext() );
}

Message * BaseClient::ReceiveMessage( int channelIndex )
{
    yojimbo_assert( m_connection );
    return m_connection->ReceiveMessage( channelIndex );
}

void BaseClient::ReleaseMessage( Message * message )
{
    yojimbo_assert( m_connection );
    m_connection->ReleaseMessage( message );
}

void BaseClient::GetNetworkInfo( NetworkInfo & info ) const
{
    memset( &info, 0, sizeof( info ) );
    if ( m_connection )
    {
        yojimbo_assert( m_endpoint );
        const uint64_t * counters = reliable_endpoint_counters( m_endpoint );
        info.numPacketsSent = counters[RELIABLE_ENDPOINT_COUNTER_NUM_PACKETS_SENT];
        info.numPacketsReceived = counters[RELIABLE_ENDPOINT_COUNTER_NUM_PACKETS_RECEIVED];
        info.numPacketsAcked = counters[RELIABLE_ENDPOINT_COUNTER_NUM_PACKETS_ACKED];
        info.RTT = reliable_endpoint_rtt( m_endpoint );
        info.packetLoss = reliable_endpoint_packet_loss( m_endpoint );
        reliable_endpoint_bandwidth( m_endpoint, &info.sentBandwidth, &info.receivedBandwidth, &info.ackedBandwidth );
    }
}

void BaseClient::Reset()
{
    if ( m_connection )
    {
        m_connection->Reset();
    }
}
