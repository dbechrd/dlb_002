#scope_module

/**
    Specifies the message factory and callbacks for clients and servers.
    An instance of this class is passed into the client and server constructors.
    You can share the same adapter across a client/server pair if you have local multiplayer, eg. loopback.
    */

Adapter :: struct {
    destroy :: #type (adapter: *Adapter);

    /**
        You must override this method to create the message factory used by the client and server.
        @param allocator The allocator that must be used to create your message factory instance via YOJIMBO_NEW
        @returns The message factory pointer you created.
        */
    create_message_factory :: #type (adapter: *Adapter) -> *MessageFactory;

    /**
        Override this callback to process packets sent from client to server over loopback.
        @param clientIndex The client index in range [0,maxClients-1]
        @param packetData The packet data (raw) to be sent to the server.
        @param packetBytes The number of packet bytes in the server.
        @param packetSequence The sequence number of the packet.
        @see Client::ConnectLoopback
        */
    client_send_loopback_packet :: #type (clientIndex: int, packetData: [] u8, packetSequence: u64);

    /**
        Override this callback to process packets sent from client to server over loopback.
        @param clientIndex The client index in range [0,maxClients-1]
        @param packetData The packet data (raw) to be sent to the server.
        @param packetBytes The number of packet bytes in the server.
        @param packetSequence The sequence number of the packet.
        @see Server::ConnectLoopbackClient
        */
    server_send_loopback_packet :: #type (clientIndex: int, packetData: [] u8, packetSequence: u64);

    /**
        Override this to get a callback when a client connects on the server.
        */
    on_server_client_connected :: #type (clientIndex: int);

    /**
        Override this to get a callback when a client disconnects from the server.
        */
    on_server_client_disconnected :: #type (clientIndex: int);
};


