#load "yojimbo_test_shared.jai";

quit := false;

client_main :: () {
    log("connecting client (insecure)\n");

    time := seconds_to_apollo(100);

    clientId := random_get();
    log("client id is %\n", clientId);

    config: ClientServerConfig;

    clientAddress := address_create_ipv4("0.0.0.0");
    client := New(Client);
    client_init(client, clientAddress, config, TestMessageFactory, time);

    serverAddress := address_create_ipv4("127.0.0.1", ServerPort);

    /*
    if ( argc == 2 )
    {
        Address commandLineAddress( argv[1] );
        if ( commandLineAddress.IsValid() )
        {
            if ( commandLineAddress.GetPort() == 0 )
                commandLineAddress.SetPort( ServerPort );
            serverAddress = commandLineAddress;
        }
    }
    */

    privateKey: [KeyBytes] u8;

    client_insecure_connect(client, privateKey, clientId, serverAddress);

    log("client address is %\n", address_to_string(client.boundAddress));

    deltaTime := milliseconds_to_apollo(100);

    while !quit {
        client_send_packets(client);
        client_receive_packets(client);

        log("client: %\n", client.clientState);

        if client.clientState == .Disconnected {
            break;
        }

        time += deltaTime;
        client_advance_time(client, time);

        if client.clientState == .Error {
            break;
        }

        sleep_milliseconds(cast(s32) to_milliseconds(deltaTime));
    }

    client_disconnect(client);
}

main :: () {
    if !yojimbo_init() {
        log("error: failed to initialize Yojimbo!\n");
        return;
    }

    //yojimbo_log_level( YOJIMBO_LOG_LEVEL_INFO );
    //srand( (unsigned int) time( NULL ) );

    client_main(); // argc, argv );

    yojimbo_shutdown();
}