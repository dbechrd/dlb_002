#import "Basic";
#import "Yojimbo";

#load "yojimbo_test_shared.jai";

quit := false;

server_main :: () {
    log("started server on port % (insecure)\n", ServerPort);

    time := seconds_to_apollo(100);

    config: ClientServerConfig;

    privateKey: [KeyBytes] u8;

    server_address := address_create_ipv4("127.0.0.1", ServerPort);
    server := New(Server);
    server_init(server, privateKey, server_address, config, time);

    server_start(server, MaxClients);

    log("server address is %\n", address_to_string(server_address));

    deltaTime := milliseconds_to_apollo(10);

    while !quit {
        server_send_packets(server);
        server_receive_packets(server);

        time += deltaTime;
        server_advance_time(server, time);

        if !server.running {
            break;
        }

        sleep_milliseconds(cast(s32) to_milliseconds(deltaTime));
    }

    server_stop(server);
}

main :: () {
    if !yojimbo_init() {
        log("error: failed to initialize Yojimbo!\n");
    }

    yojimbo_log_level(YOJIMBO_LOG_LEVEL_INFO);
    //random_seed(current_time_monotonic());
    server_main();

    yojimbo_shutdown();
}