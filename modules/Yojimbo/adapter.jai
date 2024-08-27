#scope_module

/**
    Specifies the message factory and callbacks for clients and servers.
    An instance of this class is passed into the client and server constructors.
    You can share the same adapter across a client/server pair if you have local multiplayer, eg. loopback.
    */

class Adapter
{
public:

    virtual ~Adapter() {}

    /**
        Override this function to specify your own custom allocator class.
        @param allocator The base allocator that must be used to allocate your allocator instance.
        @param memory The block of memory backing your allocator.
        @param bytes The number of bytes of memory available to your allocator.
        @returns A pointer to the allocator instance you created.
        */

    virtual Allocator * CreateAllocator( Allocator & allocator, void * memory, size_t bytes )
    {
        return YOJIMBO_NEW( allocator, TLSF_Allocator, memory, bytes );
    }

    /**
        You must override this method to create the message factory used by the client and server.
        @param allocator The allocator that must be used to create your message factory instance via YOJIMBO_NEW
        @returns The message factory pointer you created.

        */

    virtual MessageFactory * CreateMessageFactory( Allocator & allocator )
    {
        (void) allocator;
        yojimbo_assert( false );
        return NULL;
    }

    /**
        Override this callback to process packets sent from client to server over loopback.
        @param clientIndex The client index in range [0,maxClients-1]
        @param packetData The packet data (raw) to be sent to the server.
        @param packetBytes The number of packet bytes in the server.
        @param packetSequence The sequence number of the packet.
        @see Client::ConnectLoopback
        */

    virtual void ClientSendLoopbackPacket( int clientIndex, const uint8_t * packetData, int packetBytes, uint64_t packetSequence )
    {
        (void) clientIndex;
        (void) packetData;
        (void) packetBytes;
        (void) packetSequence;
        yojimbo_assert( false );
    }

    /**
        Override this callback to process packets sent from client to server over loopback.
        @param clientIndex The client index in range [0,maxClients-1]
        @param packetData The packet data (raw) to be sent to the server.
        @param packetBytes The number of packet bytes in the server.
        @param packetSequence The sequence number of the packet.
        @see Server::ConnectLoopbackClient
        */

    virtual void ServerSendLoopbackPacket( int clientIndex, const uint8_t * packetData, int packetBytes, uint64_t packetSequence )
    {
        (void) clientIndex;
        (void) packetData;
        (void) packetBytes;
        (void) packetSequence;
        yojimbo_assert( false );
    }

    /**
        Override this to get a callback when a client connects on the server.
        */

    virtual void OnServerClientConnected( int clientIndex )
    {
        (void) clientIndex;
    }

    /**
        Override this to get a callback when a client disconnects from the server.
        */

    virtual void OnServerClientDisconnected( int clientIndex )
    {
        (void) clientIndex;
    }
};


