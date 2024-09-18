
void test_client_server_keep_alive()
{
    struct netcode_network_simulator_t * network_simulator = netcode_network_simulator_create(null, null, null);

    network_simulator->latency_milliseconds = 250;
    network_simulator->jitter_milliseconds = 250;
    network_simulator->packet_loss_percent = 5;
    network_simulator->duplicate_packet_percent = 10;

    double time = 0.0;
    double delta_time = 1.0 / 10.0;

    // connect client to server

    struct netcode_client_config_t client_config;
    netcode_default_client_config(&client_config);
    client_config.network_simulator = network_simulator;

    struct netcode_client_t * client = netcode_client_create("[::]:50000", &client_config, time);

    check(client);

    struct netcode_server_config_t server_config;
    netcode_default_server_config(&server_config);
    server_config.protocol_id = TEST_PROTOCOL_ID;
    server_config.network_simulator = network_simulator;
    memcpy(&server_config.private_key, private_key, NETCODE_KEY_BYTES);

    struct netcode_server_t * server = netcode_server_create("[::1]:40000", &server_config, time);

    check(server);

    netcode_server_start(server, 1);

    NETCODE_CONST char * server_address = "[::1]:40000";

    uint8_t connect_token[NETCODE_CONNECT_TOKEN_BYTES];

    uint64_t client_id = 0;
    netcode_random_bytes((uint8_t*) &client_id, 8);

    uint8_t user_data[NETCODE_USER_DATA_BYTES];
    netcode_random_bytes(user_data, NETCODE_USER_DATA_BYTES);

    check(netcode_generate_connect_token(1, &server_address, &server_address, TEST_CONNECT_TOKEN_EXPIRY, TEST_TIMEOUT_SECONDS, client_id, TEST_PROTOCOL_ID, private_key, user_data, connect_token));

    netcode_client_connect(client, connect_token);

    while (1)
    {
        netcode_network_simulator_update(network_simulator, time);

        netcode_client_update(client, time);

        netcode_server_update(server, time);

        if (netcode_client_state(client) <= NETCODE_CLIENT_STATE_DISCONNECTED)
            break;

        if (netcode_client_state(client) == NETCODE_CLIENT_STATE_CONNECTED)
            break;

        time += delta_time;
    }

    check(netcode_client_state(client) == NETCODE_CLIENT_STATE_CONNECTED);
    check(netcode_client_index(client) == 0);
    check(netcode_server_client_connected(server, 0) == 1);
    check(netcode_server_num_connected_clients(server) == 1);

    // pump the client and server long enough that they would timeout without keep alive packets

    int num_iterations = (int) (1.25f * TEST_TIMEOUT_SECONDS / delta_time) + 1;

    int i;
    for (i = 0; i < num_iterations; i++)
    {
        netcode_network_simulator_update(network_simulator, time);

        netcode_client_update(client, time);

        netcode_server_update(server, time);

        if (netcode_client_state(client) <= NETCODE_CLIENT_STATE_DISCONNECTED)
            break;

        time += delta_time;
    }

    check(netcode_client_state(client) == NETCODE_CLIENT_STATE_CONNECTED);
    check(netcode_client_index(client) == 0);
    check(netcode_server_client_connected(server, 0) == 1);
    check(netcode_server_num_connected_clients(server) == 1);

    netcode_server_destroy(server);

    netcode_client_destroy(client);

    netcode_network_simulator_destroy(network_simulator);
}

void test_client_server_multiple_clients()
{
    #define NUM_START_STOP_ITERATIONS 3

    int max_clients[NUM_START_STOP_ITERATIONS] = { 2, 32, 5 };

    struct netcode_network_simulator_t * network_simulator = netcode_network_simulator_create(null, null, null);

    network_simulator->latency_milliseconds = 250;
    network_simulator->jitter_milliseconds = 250;
    network_simulator->packet_loss_percent = 5;
    network_simulator->duplicate_packet_percent = 10;

    double time = 0.0;
    double delta_time = 1.0 / 10.0;

    struct netcode_server_config_t server_config;
    netcode_default_server_config(&server_config);
    server_config.protocol_id = TEST_PROTOCOL_ID;
    server_config.network_simulator = network_simulator;
    memcpy(&server_config.private_key, private_key, NETCODE_KEY_BYTES);

    struct netcode_server_t * server = netcode_server_create("[::1]:40000", &server_config, time);

    check(server);

    int i;
    for (i = 0; i < NUM_START_STOP_ITERATIONS; i++)
    {
        // start the server with max # of clients for this iteration

        netcode_server_start(server, max_clients[i]);

        // create # of client objects for this iteration and connect to server

        struct netcode_client_t ** client = (struct netcode_client_t **) malloc(sizeof(struct netcode_client_t*) * max_clients[i]);

        check(client);

        int j;
        for (j = 0; j < max_clients[i]; j++)
        {
            char client_address[NETCODE_MAX_ADDRESS_STRING_LENGTH];
            snprintf(client_address, sizeof(client_address), "[::]:%d", 50000 + j);

            struct netcode_client_config_t client_config;
            netcode_default_client_config(&client_config);
            client_config.network_simulator = network_simulator;

            client[j] = netcode_client_create(client_address, &client_config, time);

            check(client[j]);

            uint64_t client_id = j;
            netcode_random_bytes((uint8_t*) &client_id, 8);

            NETCODE_CONST char * server_address = "[::1]:40000";

            uint8_t connect_token[NETCODE_CONNECT_TOKEN_BYTES];

            uint8_t user_data[NETCODE_USER_DATA_BYTES];
            netcode_random_bytes(user_data, NETCODE_USER_DATA_BYTES);

            check(netcode_generate_connect_token(1,
                                                   &server_address,
                                                   &server_address,
                                                   TEST_CONNECT_TOKEN_EXPIRY,
                                                   TEST_TIMEOUT_SECONDS,
                                                   client_id,
                                                   TEST_PROTOCOL_ID,
                                                   private_key,
                                                   user_data,
                                                   connect_token));

            netcode_client_connect(client[j], connect_token);
        }

        // make sure all clients can connect

        while (1)
        {
            netcode_network_simulator_update(network_simulator, time);

            for (j = 0; j < max_clients[i]; j++)
            {
                netcode_client_update(client[j], time);
            }

            netcode_server_update(server, time);

            int num_connected_clients = 0;

            for (j = 0; j < max_clients[i]; j++)
            {
                if (netcode_client_state(client[j]) <= NETCODE_CLIENT_STATE_DISCONNECTED)
                    break;

                if (netcode_client_state(client[j]) == NETCODE_CLIENT_STATE_CONNECTED)
                    num_connected_clients++;
            }

            if (num_connected_clients == max_clients[i])
                break;

            time += delta_time;
        }

        check(netcode_server_num_connected_clients(server) == max_clients[i]);

        for (j = 0; j < max_clients[i]; j++)
        {
            check(netcode_client_state(client[j]) == NETCODE_CLIENT_STATE_CONNECTED);
            check(netcode_server_client_connected(server, j) == 1);
        }

        // make sure all clients can exchange packets with the server

        int * server_num_packets_received = (int*) malloc(sizeof(int) * max_clients[i]);
        int * client_num_packets_received = (int*) malloc(sizeof(int) * max_clients[i]);

        memset(server_num_packets_received, 0, sizeof(int) * max_clients[i]);
        memset(client_num_packets_received, 0, sizeof(int) * max_clients[i]);

        uint8_t packet_data[NETCODE_MAX_PACKET_SIZE];
        for (j = 0; j < NETCODE_MAX_PACKET_SIZE; j++)
            packet_data[j] = (uint8_t) j;

        while (1)
        {
            netcode_network_simulator_update(network_simulator, time);

            for (j = 0; j < max_clients[i]; j++)
            {
                netcode_client_update(client[j], time);
            }

            netcode_server_update(server, time);

            for (j = 0; j < max_clients[i]; j++)
            {
                netcode_client_send_packet(client[j], packet_data, NETCODE_MAX_PACKET_SIZE);
            }

            for (j = 0; j < max_clients[i]; j++)
            {
                netcode_server_send_packet(server, j, packet_data, NETCODE_MAX_PACKET_SIZE);
            }

            for (j = 0; j < max_clients[i]; j++)
            {
                while (1)
                {
                    int packet_bytes;
                    uint64_t packet_sequence;
                    uint8_t * packet = netcode_client_receive_packet(client[j], &packet_bytes, &packet_sequence);
                    if (!packet)
                        break;
                    (void) packet_sequence;
                    netcode_assert(packet_bytes == NETCODE_MAX_PACKET_SIZE);
                    netcode_assert(memcmp(packet, packet_data, NETCODE_MAX_PACKET_SIZE) == 0);
                    client_num_packets_received[j]++;
                    netcode_client_free_packet(client[j], packet);
                }
            }

            for (j = 0; j < max_clients[i]; j++)
            {
                while (1)
                {
                    int packet_bytes;
                    uint64_t packet_sequence;
                    void * packet = netcode_server_receive_packet(server, j, &packet_bytes, &packet_sequence);
                    if (!packet)
                        break;
                    (void) packet_sequence;
                    netcode_assert(packet_bytes == NETCODE_MAX_PACKET_SIZE);
                    netcode_assert(memcmp(packet, packet_data, NETCODE_MAX_PACKET_SIZE) == 0);
                    server_num_packets_received[j]++;
                    netcode_server_free_packet(server, packet);
                }
            }

            int num_clients_ready = 0;

            for (j = 0; j < max_clients[i]; j++)
            {
                if (client_num_packets_received[j] >= 1 && server_num_packets_received[j] >= 1)
                {
                    num_clients_ready++;
                }
            }

            if (num_clients_ready == max_clients[i])
                break;

            for (j = 0; j < max_clients[i]; j++)
            {
                if (netcode_client_state(client[j]) <= NETCODE_CLIENT_STATE_DISCONNECTED)
                    break;
            }

            time += delta_time;
        }

        int num_clients_ready = 0;

        for (j = 0; j < max_clients[i]; j++)
        {
            if (client_num_packets_received[j] >= 1 && server_num_packets_received[j] >= 1)
            {
                num_clients_ready++;
            }
        }

        check(num_clients_ready == max_clients[i]);

        free(server_num_packets_received);
        free(client_num_packets_received);

        netcode_network_simulator_reset(network_simulator);

        for (j = 0; j < max_clients[i]; j++)
        {
            netcode_client_destroy(client[j]);
        }

        free(client);

        netcode_server_stop(server);
    }

    netcode_server_destroy(server);

    netcode_network_simulator_destroy(network_simulator);
}

void test_client_server_multiple_servers()
{
    struct netcode_network_simulator_t * network_simulator = netcode_network_simulator_create(null, null, null);

    network_simulator->latency_milliseconds = 250;
    network_simulator->jitter_milliseconds = 250;
    network_simulator->packet_loss_percent = 5;
    network_simulator->duplicate_packet_percent = 10;

    double time = 0.0;
    double delta_time = 1.0 / 10.0;

    struct netcode_client_config_t client_config;
    netcode_default_client_config(&client_config);
    client_config.network_simulator = network_simulator;

    struct netcode_client_t * client = netcode_client_create("[::]:50000", &client_config, time);

    check(client);

    struct netcode_server_config_t server_config;
    netcode_default_server_config(&server_config);
    server_config.protocol_id = TEST_PROTOCOL_ID;
    server_config.network_simulator = network_simulator;
    memcpy(&server_config.private_key, private_key, NETCODE_KEY_BYTES);

    struct netcode_server_t * server = netcode_server_create("[::1]:40000", &server_config, time);

    check(server);

    netcode_server_start(server, 1);

    NETCODE_CONST char * server_address[] = { "10.10.10.10:1000", "100.100.100.100:50000", "[::1]:40000" };

    uint8_t connect_token[NETCODE_CONNECT_TOKEN_BYTES];

    uint64_t client_id = 0;
    netcode_random_bytes((uint8_t*) &client_id, 8);

    uint8_t user_data[NETCODE_USER_DATA_BYTES];
    netcode_random_bytes(user_data, NETCODE_USER_DATA_BYTES);

    check(netcode_generate_connect_token(3, server_address, server_address, TEST_CONNECT_TOKEN_EXPIRY, TEST_TIMEOUT_SECONDS, client_id, TEST_PROTOCOL_ID, private_key, user_data, connect_token));

    netcode_client_connect(client, connect_token);

    while (1)
    {
        netcode_network_simulator_update(network_simulator, time);

        netcode_client_update(client, time);

        netcode_server_update(server, time);

        if (netcode_client_state(client) <= NETCODE_CLIENT_STATE_DISCONNECTED)
            break;

        if (netcode_client_state(client) == NETCODE_CLIENT_STATE_CONNECTED)
            break;

        time += delta_time;
    }

    check(netcode_client_state(client) == NETCODE_CLIENT_STATE_CONNECTED);
    check(netcode_client_index(client) == 0);
    check(netcode_server_client_connected(server, 0) == 1);
    check(netcode_server_num_connected_clients(server) == 1);

    int server_num_packets_received = 0;
    int client_num_packets_received = 0;

    uint8_t packet_data[NETCODE_MAX_PACKET_SIZE];
    int i;
    for (i = 0; i < NETCODE_MAX_PACKET_SIZE; i++)
        packet_data[i] = (uint8_t) i;

    while (1)
    {
        netcode_network_simulator_update(network_simulator, time);

        netcode_client_update(client, time);

        netcode_server_update(server, time);

        netcode_client_send_packet(client, packet_data, NETCODE_MAX_PACKET_SIZE);

        netcode_server_send_packet(server, 0, packet_data, NETCODE_MAX_PACKET_SIZE);

        while (1)
        {
            int packet_bytes;
            uint64_t packet_sequence;
            uint8_t * packet = netcode_client_receive_packet(client, &packet_bytes, &packet_sequence);
            if (!packet)
                break;
            (void) packet_sequence;
            netcode_assert(packet_bytes == NETCODE_MAX_PACKET_SIZE);
            netcode_assert(memcmp(packet, packet_data, NETCODE_MAX_PACKET_SIZE) == 0);
            client_num_packets_received++;
            netcode_client_free_packet(client, packet);
        }

        while (1)
        {
            int packet_bytes;
            uint64_t packet_sequence;
            void * packet = netcode_server_receive_packet(server, 0, &packet_bytes, &packet_sequence);
            if (!packet)
                break;
            netcode_assert(packet_bytes == NETCODE_MAX_PACKET_SIZE);
            netcode_assert(memcmp(packet, packet_data, NETCODE_MAX_PACKET_SIZE) == 0);
            server_num_packets_received++;
            netcode_server_free_packet(server, packet);
        }

        if (client_num_packets_received >= 10 && server_num_packets_received >= 10)
        {
            if (netcode_server_client_connected(server, 0))
            {
                netcode_server_disconnect_client(server, 0);
            }
        }

        if (netcode_client_state(client) <= NETCODE_CLIENT_STATE_DISCONNECTED)
            break;

        time += delta_time;
    }

    check(client_num_packets_received >= 10 && server_num_packets_received >= 10);

    netcode_server_destroy(server);

    netcode_client_destroy(client);

    netcode_network_simulator_destroy(network_simulator);
}

void test_client_error_connect_token_expired()
{
    struct netcode_network_simulator_t * network_simulator = netcode_network_simulator_create(null, null, null);

    network_simulator->latency_milliseconds = 250;
    network_simulator->jitter_milliseconds = 250;
    network_simulator->packet_loss_percent = 5;
    network_simulator->duplicate_packet_percent = 10;

    double time = 0.0;

    struct netcode_client_config_t client_config;
    netcode_default_client_config(&client_config);
    client_config.network_simulator = network_simulator;

    struct netcode_client_t * client = netcode_client_create("[::]:50000", &client_config, time);

    check(client);

    NETCODE_CONST char * server_address = "[::1]:40000";

    uint8_t connect_token[NETCODE_CONNECT_TOKEN_BYTES];

    uint64_t client_id = 0;
    netcode_random_bytes((uint8_t*) &client_id, 8);

    uint8_t user_data[NETCODE_USER_DATA_BYTES];
    netcode_random_bytes(user_data, NETCODE_USER_DATA_BYTES);

    check(netcode_generate_connect_token(1, &server_address, &server_address, 0, TEST_TIMEOUT_SECONDS, client_id, TEST_PROTOCOL_ID, private_key, user_data, connect_token));

    netcode_client_connect(client, connect_token);

    netcode_client_update(client, time);

    check(netcode_client_state(client) == NETCODE_CLIENT_STATE_CONNECT_TOKEN_EXPIRED);

    netcode_client_destroy(client);

    netcode_network_simulator_destroy(network_simulator);
}

void test_client_error_invalid_connect_token()
{
    struct netcode_network_simulator_t * network_simulator = netcode_network_simulator_create(null, null, null);

    network_simulator->latency_milliseconds = 250;
    network_simulator->jitter_milliseconds = 250;
    network_simulator->packet_loss_percent = 5;
    network_simulator->duplicate_packet_percent = 10;

    double time = 0.0;

    struct netcode_client_config_t client_config;
    netcode_default_client_config(&client_config);
    client_config.network_simulator = network_simulator;

    struct netcode_client_t * client = netcode_client_create("[::]:50000", &client_config, time);

    check(client);

    uint8_t connect_token[NETCODE_CONNECT_TOKEN_BYTES];
    netcode_random_bytes(connect_token, NETCODE_CONNECT_TOKEN_BYTES);

    uint64_t client_id = 0;
    netcode_random_bytes((uint8_t*) &client_id, 8);

    netcode_client_connect(client, connect_token);

    check(netcode_client_state(client) == NETCODE_CLIENT_STATE_INVALID_CONNECT_TOKEN);

    netcode_client_destroy(client);

    netcode_network_simulator_destroy(network_simulator);
}

void test_client_error_connection_timed_out()
{
    struct netcode_network_simulator_t * network_simulator = netcode_network_simulator_create(null, null, null);

    network_simulator->latency_milliseconds = 250;
    network_simulator->jitter_milliseconds = 250;
    network_simulator->packet_loss_percent = 5;
    network_simulator->duplicate_packet_percent = 10;

    double time = 0.0;
    double delta_time = 1.0 / 10.0;

    // connect a client to the server

    struct netcode_client_config_t client_config;
    netcode_default_client_config(&client_config);
    client_config.network_simulator = network_simulator;

    struct netcode_client_t * client = netcode_client_create("[::]:50000", &client_config, time);

    check(client);

    struct netcode_server_config_t server_config;
    netcode_default_server_config(&server_config);
    server_config.protocol_id = TEST_PROTOCOL_ID;
    server_config.network_simulator = network_simulator;
    memcpy(&server_config.private_key, private_key, NETCODE_KEY_BYTES);

    struct netcode_server_t * server = netcode_server_create("[::1]:40000", &server_config, time);

    check(server);

    netcode_server_start(server, 1);

    NETCODE_CONST char * server_address = "[::1]:40000";

    uint8_t connect_token[NETCODE_CONNECT_TOKEN_BYTES];

    uint64_t client_id = 0;
    netcode_random_bytes((uint8_t*) &client_id, 8);

    uint8_t user_data[NETCODE_USER_DATA_BYTES];
    netcode_random_bytes(user_data, NETCODE_USER_DATA_BYTES);

    check(netcode_generate_connect_token(1, &server_address, &server_address, TEST_CONNECT_TOKEN_EXPIRY, TEST_TIMEOUT_SECONDS, client_id, TEST_PROTOCOL_ID, private_key, user_data, connect_token));

    netcode_client_connect(client, connect_token);

    while (1)
    {
        netcode_network_simulator_update(network_simulator, time);

        netcode_client_update(client, time);

        netcode_server_update(server, time);

        if (netcode_client_state(client) <= NETCODE_CLIENT_STATE_DISCONNECTED)
            break;

        if (netcode_client_state(client) == NETCODE_CLIENT_STATE_CONNECTED)
            break;

        time += delta_time;
    }

    check(netcode_client_state(client) == NETCODE_CLIENT_STATE_CONNECTED);
    check(netcode_client_index(client) == 0);
    check(netcode_server_client_connected(server, 0) == 1);
    check(netcode_server_num_connected_clients(server) == 1);

    // now disable updating the server and verify that the client times out

    while (1)
    {
        netcode_network_simulator_update(network_simulator, time);

        netcode_client_update(client, time);

        if (netcode_client_state(client) <= NETCODE_CLIENT_STATE_DISCONNECTED)
            break;

        time += delta_time;
    }

    check(netcode_client_state(client) == NETCODE_CLIENT_STATE_CONNECTION_TIMED_OUT);

    netcode_server_destroy(server);

    netcode_client_destroy(client);

    netcode_network_simulator_destroy(network_simulator);
}

void test_client_error_connection_response_timeout()
{
    struct netcode_network_simulator_t * network_simulator = netcode_network_simulator_create(null, null, null);

    network_simulator->latency_milliseconds = 250;
    network_simulator->jitter_milliseconds = 250;
    network_simulator->packet_loss_percent = 5;
    network_simulator->duplicate_packet_percent = 10;

    double time = 0.0;
    double delta_time = 1.0 / 10.0;

    struct netcode_client_config_t client_config;
    netcode_default_client_config(&client_config);
    client_config.network_simulator = network_simulator;

    struct netcode_client_t * client = netcode_client_create("[::]:50000", &client_config, time);

    check(client);

    struct netcode_server_config_t server_config;
    netcode_default_server_config(&server_config);
    server_config.protocol_id = TEST_PROTOCOL_ID;
    server_config.network_simulator = network_simulator;
    memcpy(&server_config.private_key, private_key, NETCODE_KEY_BYTES);

    struct netcode_server_t * server = netcode_server_create("[::1]:40000", &server_config, time);

    check(server);

    server->flags = NETCODE_SERVER_FLAG_IGNORE_CONNECTION_RESPONSE_PACKETS;

    netcode_server_start(server, 1);

    NETCODE_CONST char * server_address = "[::1]:40000";

    uint8_t connect_token[NETCODE_CONNECT_TOKEN_BYTES];

    uint64_t client_id = 0;
    netcode_random_bytes((uint8_t*) &client_id, 8);

    uint8_t user_data[NETCODE_USER_DATA_BYTES];
    netcode_random_bytes(user_data, NETCODE_USER_DATA_BYTES);

    check(netcode_generate_connect_token(1, &server_address, &server_address, TEST_CONNECT_TOKEN_EXPIRY, TEST_TIMEOUT_SECONDS, client_id, TEST_PROTOCOL_ID, private_key, user_data, connect_token));

    netcode_client_connect(client, connect_token);

    while (1)
    {
        netcode_network_simulator_update(network_simulator, time);

        netcode_client_update(client, time);

        netcode_server_update(server, time);

        if (netcode_client_state(client) <= NETCODE_CLIENT_STATE_DISCONNECTED)
            break;

        if (netcode_client_state(client) == NETCODE_CLIENT_STATE_CONNECTED )
            break;

        time += delta_time;
    }

    check(netcode_client_state(client) == NETCODE_CLIENT_STATE_CONNECTION_RESPONSE_TIMED_OUT);

    netcode_server_destroy(server);

    netcode_client_destroy(client);

    netcode_network_simulator_destroy(network_simulator);
}

void test_client_error_connection_request_timeout()
{
    struct netcode_network_simulator_t * network_simulator = netcode_network_simulator_create(null, null, null);

    network_simulator->latency_milliseconds = 250;
    network_simulator->jitter_milliseconds = 250;
    network_simulator->packet_loss_percent = 5;
    network_simulator->duplicate_packet_percent = 10;

    double time = 0.0;
    double delta_time = 1.0 / 60.0;

    struct netcode_client_config_t client_config;
    netcode_default_client_config(&client_config);
    client_config.network_simulator = network_simulator;

    struct netcode_client_t * client = netcode_client_create("[::]:50000", &client_config, time);

    check(client);

    struct netcode_server_config_t server_config;
    netcode_default_server_config(&server_config);
    server_config.protocol_id = TEST_PROTOCOL_ID;
    server_config.network_simulator = network_simulator;
    memcpy(&server_config.private_key, private_key, NETCODE_KEY_BYTES);

    struct netcode_server_t * server = netcode_server_create("[::1]:40000", &server_config, time);

    check(server);

    server->flags = NETCODE_SERVER_FLAG_IGNORE_CONNECTION_REQUEST_PACKETS;

    netcode_server_start(server, 1);

    NETCODE_CONST char * server_address = "[::1]:40000";

    uint8_t connect_token[NETCODE_CONNECT_TOKEN_BYTES];

    uint64_t client_id = 0;
    netcode_random_bytes((uint8_t*) &client_id, 8);

    uint8_t user_data[NETCODE_USER_DATA_BYTES];
    netcode_random_bytes(user_data, NETCODE_USER_DATA_BYTES);

    check(netcode_generate_connect_token(1, &server_address, &server_address, TEST_CONNECT_TOKEN_EXPIRY, TEST_TIMEOUT_SECONDS, client_id, TEST_PROTOCOL_ID, private_key, user_data, connect_token));

    netcode_client_connect(client, connect_token);

    while (1)
    {
        netcode_network_simulator_update(network_simulator, time);

        netcode_client_update(client, time);

        netcode_server_update(server, time);

        if (netcode_client_state(client) <= NETCODE_CLIENT_STATE_DISCONNECTED)
            break;

        if (netcode_client_state(client) == NETCODE_CLIENT_STATE_CONNECTED )
            break;

        time += delta_time;
    }

    check(netcode_client_state(client) == NETCODE_CLIENT_STATE_CONNECTION_REQUEST_TIMED_OUT);

    netcode_server_destroy(server);

    netcode_client_destroy(client);

    netcode_network_simulator_destroy(network_simulator);
}

void test_client_error_connection_denied()
{
    struct netcode_network_simulator_t * network_simulator = netcode_network_simulator_create(null, null, null);

    network_simulator->latency_milliseconds = 250;
    network_simulator->jitter_milliseconds = 250;
    network_simulator->packet_loss_percent = 5;
    network_simulator->duplicate_packet_percent = 10;

    // start a server and connect one client

    double time = 0.0;
    double delta_time = 1.0 / 10.0;

    struct netcode_client_config_t client_config;
    netcode_default_client_config(&client_config);
    client_config.network_simulator = network_simulator;

    struct netcode_client_t * client = netcode_client_create("[::]:50000", &client_config, time);

    check(client);

    struct netcode_server_config_t server_config;
    netcode_default_server_config(&server_config);
    server_config.protocol_id = TEST_PROTOCOL_ID;
    server_config.network_simulator = network_simulator;
    memcpy(&server_config.private_key, private_key, NETCODE_KEY_BYTES);

    struct netcode_server_t * server = netcode_server_create("[::1]:40000", &server_config, time);

    check(server);

    netcode_server_start(server, 1);

    NETCODE_CONST char * server_address = "[::1]:40000";

    uint8_t connect_token[NETCODE_CONNECT_TOKEN_BYTES];

    uint64_t client_id = 0;
    netcode_random_bytes((uint8_t*) &client_id, 8);

    uint8_t user_data[NETCODE_USER_DATA_BYTES];
    netcode_random_bytes(user_data, NETCODE_USER_DATA_BYTES);

    check(netcode_generate_connect_token(1, &server_address, &server_address, TEST_CONNECT_TOKEN_EXPIRY, TEST_TIMEOUT_SECONDS, client_id, TEST_PROTOCOL_ID, private_key, user_data, connect_token));

    netcode_client_connect(client, connect_token);

    while (1)
    {
        netcode_network_simulator_update(network_simulator, time);

        netcode_client_update(client, time);

        netcode_server_update(server, time);

        if (netcode_client_state(client) <= NETCODE_CLIENT_STATE_DISCONNECTED)
            break;

        if (netcode_client_state(client) == NETCODE_CLIENT_STATE_CONNECTED)
            break;

        time += delta_time;
    }

    check(netcode_client_state(client) == NETCODE_CLIENT_STATE_CONNECTED);
    check(netcode_client_index(client) == 0);
    check(netcode_server_client_connected(server, 0) == 1);
    check(netcode_server_num_connected_clients(server) == 1);

    // now attempt to connect a second client. the connection should be denied.

    struct netcode_client_t * client2 = netcode_client_create("[::]:50001", &client_config, time);

    check(client2);

    uint8_t connect_token2[NETCODE_CONNECT_TOKEN_BYTES];

    uint64_t client_id2 = 0;
    netcode_random_bytes((uint8_t*) &client_id2, 8);

    uint8_t user_data2[NETCODE_USER_DATA_BYTES];
    netcode_random_bytes(user_data2, NETCODE_USER_DATA_BYTES);

    check(netcode_generate_connect_token(1, &server_address, &server_address, TEST_CONNECT_TOKEN_EXPIRY, TEST_TIMEOUT_SECONDS, client_id2, TEST_PROTOCOL_ID, private_key, user_data2, connect_token2));

    netcode_client_connect(client2, connect_token2);

    while (1)
    {
        netcode_network_simulator_update(network_simulator, time);

        netcode_client_update(client, time);

        netcode_client_update(client2, time);

        netcode_server_update(server, time);

        if (netcode_client_state(client) <= NETCODE_CLIENT_STATE_DISCONNECTED)
            break;

        if (netcode_client_state(client2) <= NETCODE_CLIENT_STATE_DISCONNECTED)
            break;

        time += delta_time;
    }

    check(netcode_client_state(client) == NETCODE_CLIENT_STATE_CONNECTED);
    check(netcode_client_state(client2) == NETCODE_CLIENT_STATE_CONNECTION_DENIED);
    check(netcode_server_client_connected(server, 0) == 1);
    check(netcode_server_num_connected_clients(server) == 1);

    netcode_server_destroy(server);

    netcode_client_destroy(client);

    netcode_client_destroy(client2);

    netcode_network_simulator_destroy(network_simulator);
}

void test_client_side_disconnect()
{
    struct netcode_network_simulator_t * network_simulator = netcode_network_simulator_create(null, null, null);

    // start a server and connect one client

    double time = 0.0;
    double delta_time = 1.0 / 10.0;

    struct netcode_client_config_t client_config;
    netcode_default_client_config(&client_config);
    client_config.network_simulator = network_simulator;

    struct netcode_client_t * client = netcode_client_create("[::]:50000", &client_config, time);

    check(client);

    struct netcode_server_config_t server_config;
    netcode_default_server_config(&server_config);
    server_config.protocol_id = TEST_PROTOCOL_ID;
    server_config.network_simulator = network_simulator;
    memcpy(&server_config.private_key, private_key, NETCODE_KEY_BYTES);

    struct netcode_server_t * server = netcode_server_create("[::1]:40000", &server_config, time);

    check(server);

    netcode_server_start(server, 1);

    NETCODE_CONST char * server_address = "[::1]:40000";

    uint8_t connect_token[NETCODE_CONNECT_TOKEN_BYTES];

    uint64_t client_id = 0;
    netcode_random_bytes((uint8_t*) &client_id, 8);

    uint8_t user_data[NETCODE_USER_DATA_BYTES];
    netcode_random_bytes(user_data, NETCODE_USER_DATA_BYTES);

    check(netcode_generate_connect_token(1, &server_address, &server_address, TEST_CONNECT_TOKEN_EXPIRY, TEST_TIMEOUT_SECONDS, client_id, TEST_PROTOCOL_ID, private_key, user_data, connect_token));

    netcode_client_connect(client, connect_token);

    while (1)
    {
        netcode_network_simulator_update(network_simulator, time);

        netcode_client_update(client, time);

        netcode_server_update(server, time);

        if (netcode_client_state(client) <= NETCODE_CLIENT_STATE_DISCONNECTED)
            break;

        if (netcode_client_state(client) == NETCODE_CLIENT_STATE_CONNECTED)
            break;

        time += delta_time;
    }

    check(netcode_client_state(client) == NETCODE_CLIENT_STATE_CONNECTED);
    check(netcode_client_index(client) == 0);
    check(netcode_server_client_connected(server, 0) == 1);
    check(netcode_server_num_connected_clients(server) == 1);

    // disconnect client side and verify that the server sees that client disconnect cleanly, rather than timing out.

    netcode_client_disconnect(client);

    int i;
    for (i = 0; i < 10; i++)
    {
        netcode_network_simulator_update(network_simulator, time);

        netcode_client_update(client, time);

        netcode_server_update(server, time);

        if (netcode_server_client_connected(server, 0) == 0)
            break;

        time += delta_time;
    }

    check(netcode_server_client_connected(server, 0) == 0);
    check(netcode_server_num_connected_clients(server) == 0);

    netcode_server_destroy(server);

    netcode_client_destroy(client);

    netcode_network_simulator_destroy(network_simulator);
}

void test_server_side_disconnect()
{
    struct netcode_network_simulator_t * network_simulator = netcode_network_simulator_create(null, null, null);

    // start a server and connect one client

    double time = 0.0;
    double delta_time = 1.0 / 10.0;

    struct netcode_client_config_t client_config;
    netcode_default_client_config(&client_config);
    client_config.network_simulator = network_simulator;

    struct netcode_client_t * client = netcode_client_create("[::]:50000", &client_config, time);

    check(client);

    struct netcode_server_config_t server_config;
    netcode_default_server_config(&server_config);
    server_config.protocol_id = TEST_PROTOCOL_ID;
    server_config.network_simulator = network_simulator;
    memcpy(&server_config.private_key, private_key, NETCODE_KEY_BYTES);

    struct netcode_server_t * server = netcode_server_create("[::1]:40000", &server_config, time);

    check(server);

    netcode_server_start(server, 1);

    NETCODE_CONST char * server_address = "[::1]:40000";

    uint8_t connect_token[NETCODE_CONNECT_TOKEN_BYTES];

    uint64_t client_id = 0;
    netcode_random_bytes((uint8_t*) &client_id, 8);

    uint8_t user_data[NETCODE_USER_DATA_BYTES];
    netcode_random_bytes(user_data, NETCODE_USER_DATA_BYTES);

    check(netcode_generate_connect_token(1, &server_address, &server_address, TEST_CONNECT_TOKEN_EXPIRY, TEST_TIMEOUT_SECONDS, client_id, TEST_PROTOCOL_ID, private_key, user_data, connect_token));

    netcode_client_connect(client, connect_token);

    while (1)
    {
        netcode_network_simulator_update(network_simulator, time);

        netcode_client_update(client, time);

        netcode_server_update(server, time);

        if (netcode_client_state(client) <= NETCODE_CLIENT_STATE_DISCONNECTED)
            break;

        if (netcode_client_state(client) == NETCODE_CLIENT_STATE_CONNECTED)
            break;

        time += delta_time;
    }

    check(netcode_client_state(client) == NETCODE_CLIENT_STATE_CONNECTED);
    check(netcode_client_index(client) == 0);
    check(netcode_server_client_connected(server, 0) == 1);
    check(netcode_server_num_connected_clients(server) == 1);

    // disconnect server side and verify that the client disconnects cleanly, rather than timing out.

    netcode_server_disconnect_client(server, 0);

    int i;
    for (i = 0; i < 10; i++)
    {
        netcode_network_simulator_update(network_simulator, time);

        netcode_client_update(client, time);

        netcode_server_update(server, time);

        if (netcode_client_state(client) == NETCODE_CLIENT_STATE_DISCONNECTED)
            break;

        time += delta_time;
    }

    check(netcode_client_state(client) == NETCODE_CLIENT_STATE_DISCONNECTED);
    check(netcode_server_client_connected(server, 0) == 0);
    check(netcode_server_num_connected_clients(server) == 0);

    netcode_server_destroy(server);

    netcode_client_destroy(client);

    netcode_network_simulator_destroy(network_simulator);
}

void test_client_reconnect()
{
    struct netcode_network_simulator_t * network_simulator = netcode_network_simulator_create(null, null, null);

    network_simulator->latency_milliseconds = 250;
    network_simulator->jitter_milliseconds = 250;
    network_simulator->packet_loss_percent = 5;
    network_simulator->duplicate_packet_percent = 10;

    // start a server and connect one client

    double time = 0.0;
    double delta_time = 1.0 / 10.0;

    struct netcode_client_config_t client_config;
    netcode_default_client_config(&client_config);
    client_config.network_simulator = network_simulator;

    struct netcode_client_t * client = netcode_client_create("[::]:50000", &client_config, time);

    check(client);

    struct netcode_server_config_t server_config;
    netcode_default_server_config(&server_config);
    server_config.protocol_id = TEST_PROTOCOL_ID;
    server_config.network_simulator = network_simulator;
    memcpy(&server_config.private_key, private_key, NETCODE_KEY_BYTES);

    struct netcode_server_t * server = netcode_server_create("[::1]:40000", &server_config, time);

    check(server);

    netcode_server_start(server, 1);

    NETCODE_CONST char * server_address = "[::1]:40000";

    uint8_t connect_token[NETCODE_CONNECT_TOKEN_BYTES];

    uint64_t client_id = 0;
    netcode_random_bytes((uint8_t*) &client_id, 8);

    uint8_t user_data[NETCODE_USER_DATA_BYTES];
    netcode_random_bytes(user_data, NETCODE_USER_DATA_BYTES);

    check(netcode_generate_connect_token(1, &server_address, &server_address, TEST_CONNECT_TOKEN_EXPIRY, TEST_TIMEOUT_SECONDS, client_id, TEST_PROTOCOL_ID, private_key, user_data, connect_token));

    netcode_client_connect(client, connect_token);

    while (1)
    {
        netcode_network_simulator_update(network_simulator, time);

        netcode_client_update(client, time);

        netcode_server_update(server, time);

        if (netcode_client_state(client) <= NETCODE_CLIENT_STATE_DISCONNECTED)
            break;

        if (netcode_client_state(client) == NETCODE_CLIENT_STATE_CONNECTED)
            break;

        time += delta_time;
    }

    check(netcode_client_state(client) == NETCODE_CLIENT_STATE_CONNECTED);
    check(netcode_client_index(client) == 0);
    check(netcode_server_client_connected(server, 0) == 1);
    check(netcode_server_num_connected_clients(server) == 1);

    // disconnect client on the server-side and wait until client sees the disconnect

    netcode_network_simulator_reset(network_simulator);

    netcode_server_disconnect_client(server, 0);

    while (1)
    {
        netcode_network_simulator_update(network_simulator, time);

        netcode_client_update(client, time);

        netcode_server_update(server, time);

        if (netcode_client_state(client) <= NETCODE_CLIENT_STATE_DISCONNECTED)
            break;

        time += delta_time;
    }

    check(netcode_client_state(client) == NETCODE_CLIENT_STATE_DISCONNECTED);
    check(netcode_server_client_connected(server, 0) == 0);
    check(netcode_server_num_connected_clients(server) == 0);

    // now reconnect the client and verify they connect

    netcode_network_simulator_reset(network_simulator);

    check(netcode_generate_connect_token(1, &server_address, &server_address, TEST_CONNECT_TOKEN_EXPIRY, TEST_TIMEOUT_SECONDS, client_id, TEST_PROTOCOL_ID, private_key, user_data, connect_token));

    netcode_client_connect(client, connect_token);

    while (1)
    {
        netcode_network_simulator_update(network_simulator, time);

        netcode_client_update(client, time);

        netcode_server_update(server, time);

        if (netcode_client_state(client) <= NETCODE_CLIENT_STATE_DISCONNECTED)
            break;

        if (netcode_client_state(client) == NETCODE_CLIENT_STATE_CONNECTED)
            break;

        time += delta_time;
    }

    check(netcode_client_state(client) == NETCODE_CLIENT_STATE_CONNECTED);
    check(netcode_client_index(client) == 0);
    check(netcode_server_client_connected(server, 0) == 1);
    check(netcode_server_num_connected_clients(server) == 1);

    netcode_server_destroy(server);

    netcode_client_destroy(client);

    netcode_network_simulator_destroy(network_simulator);
}

struct test_loopback_context_t
{
    struct netcode_client_t * client;
    struct netcode_server_t * server;
    int num_loopback_packets_sent_to_client;
    int num_loopback_packets_sent_to_server;
};

void client_send_loopback_packet_callback(void * _context, int client_index, NETCODE_CONST uint8_t * packet_data, int packet_bytes, uint64_t packet_sequence)
{
    (void) packet_sequence;
    check(_context);
    check(client_index == 0);
    check(packet_data);
    check(packet_bytes == NETCODE_MAX_PACKET_SIZE);
    int i;
    for (i = 0; i < packet_bytes; i++)
    {
        check(packet_data[i] == (uint8_t) i);
    }
    struct test_loopback_context_t * context = (struct test_loopback_context_t*) _context;
    context->num_loopback_packets_sent_to_server++;
    netcode_server_process_loopback_packet(context->server, client_index, packet_data, packet_bytes, packet_sequence);
}

void server_send_loopback_packet_callback(void * _context, int client_index, NETCODE_CONST uint8_t * packet_data, int packet_bytes, uint64_t packet_sequence)
{
    (void) packet_sequence;
    check(_context);
    check(client_index == 0);
    check(packet_data);
    check(packet_bytes == NETCODE_MAX_PACKET_SIZE);
    int i;
    for (i = 0; i < packet_bytes; i++)
    {
        check(packet_data[i] == (uint8_t) i);
    }
    struct test_loopback_context_t * context = (struct test_loopback_context_t*) _context;
    context->num_loopback_packets_sent_to_client++;
    netcode_client_process_loopback_packet(context->client, packet_data, packet_bytes, packet_sequence);
}

void test_disable_timeout()
{
    struct netcode_network_simulator_t * network_simulator = netcode_network_simulator_create(null, null, null);

    network_simulator->latency_milliseconds = 250;
    network_simulator->jitter_milliseconds = 250;
    network_simulator->packet_loss_percent = 5;
    network_simulator->duplicate_packet_percent = 10;

    double time = 0.0;
    double delta_time = 1.0 / 10.0;

    struct netcode_client_config_t client_config;
    netcode_default_client_config(&client_config);
    client_config.network_simulator = network_simulator;

    struct netcode_client_t * client = netcode_client_create("[::]:50000", &client_config, time);

    check(client);

    struct netcode_server_config_t server_config;
    netcode_default_server_config(&server_config);
    server_config.protocol_id = TEST_PROTOCOL_ID;
    server_config.network_simulator = network_simulator;
    memcpy(&server_config.private_key, private_key, NETCODE_KEY_BYTES);

    struct netcode_server_t * server = netcode_server_create("[::1]:40000", &server_config, time);

    check(server);

    netcode_server_start(server, 1);

    NETCODE_CONST char * server_address = "[::1]:40000";

    uint8_t connect_token[NETCODE_CONNECT_TOKEN_BYTES];

    uint64_t client_id = 0;
    netcode_random_bytes((uint8_t*) &client_id, 8);

    uint8_t user_data[NETCODE_USER_DATA_BYTES];
    netcode_random_bytes(user_data, NETCODE_USER_DATA_BYTES);

    check(netcode_generate_connect_token(1, &server_address, &server_address, TEST_CONNECT_TOKEN_EXPIRY, -1, client_id, TEST_PROTOCOL_ID, private_key, user_data, connect_token));

    netcode_client_connect(client, connect_token);

    while (1)
    {
        netcode_network_simulator_update(network_simulator, time);

        netcode_client_update(client, time);

        netcode_server_update(server, time);

        if (netcode_client_state(client) <= NETCODE_CLIENT_STATE_DISCONNECTED)
            break;

        if (netcode_client_state(client) == NETCODE_CLIENT_STATE_CONNECTED)
            break;

        time += delta_time;
    }

    check(netcode_client_state(client) == NETCODE_CLIENT_STATE_CONNECTED);
    check(netcode_client_index(client) == 0);
    check(netcode_server_client_connected(server, 0) == 1);
    check(netcode_server_num_connected_clients(server) == 1);

    int server_num_packets_received = 0;
    int client_num_packets_received = 0;

    uint8_t packet_data[NETCODE_MAX_PACKET_SIZE];
    int i;
    for (i = 0; i < NETCODE_MAX_PACKET_SIZE; i++)
        packet_data[i] = (uint8_t) i;

    while (1)
    {
        netcode_network_simulator_update(network_simulator, time);

        netcode_client_update(client, time);

        netcode_server_update(server, time);

        netcode_client_send_packet(client, packet_data, NETCODE_MAX_PACKET_SIZE);

        netcode_server_send_packet(server, 0, packet_data, NETCODE_MAX_PACKET_SIZE);

        while (1)
        {
            int packet_bytes;
            uint64_t packet_sequence;
            uint8_t * packet = netcode_client_receive_packet(client, &packet_bytes, &packet_sequence);
            if (!packet)
                break;
            (void) packet_sequence;
            netcode_assert(packet_bytes == NETCODE_MAX_PACKET_SIZE);
            netcode_assert(memcmp(packet, packet_data, NETCODE_MAX_PACKET_SIZE) == 0);
            client_num_packets_received++;
            netcode_client_free_packet(client, packet);
        }

        while (1)
        {
            int packet_bytes;
            uint64_t packet_sequence;
            void * packet = netcode_server_receive_packet(server, 0, &packet_bytes, &packet_sequence);
            if (!packet)
                break;
            (void) packet_sequence;
            netcode_assert(packet_bytes == NETCODE_MAX_PACKET_SIZE);
            netcode_assert(memcmp(packet, packet_data, NETCODE_MAX_PACKET_SIZE) == 0);
            server_num_packets_received++;
            netcode_server_free_packet(server, packet);
        }

        if (client_num_packets_received >= 10 && server_num_packets_received >= 10)
        {
            if (netcode_server_client_connected(server, 0))
            {
                netcode_server_disconnect_client(server, 0);
            }
        }

        if (netcode_client_state(client) <= NETCODE_CLIENT_STATE_DISCONNECTED)
            break;

        time += 1000.0f;        // normally this would timeout the client
    }

    check(client_num_packets_received >= 10 && server_num_packets_received >= 10);

    netcode_server_destroy(server);

    netcode_client_destroy(client);

    netcode_network_simulator_destroy(network_simulator);
}

void test_loopback()
{
    struct test_loopback_context_t context;
    memset(&context, 0, sizeof(context));

    struct netcode_network_simulator_t * network_simulator = netcode_network_simulator_create(null, null, null);

    network_simulator->latency_milliseconds = 250;
    network_simulator->jitter_milliseconds = 250;
    network_simulator->packet_loss_percent = 5;
    network_simulator->duplicate_packet_percent = 10;

    double time = 0.0;
    double delta_time = 1.0 / 10.0;

    // start the server

    struct netcode_server_config_t server_config;
    netcode_default_server_config(&server_config);
    server_config.protocol_id = TEST_PROTOCOL_ID;
    server_config.network_simulator = network_simulator;
    server_config.callback_context = &context;
    server_config.send_loopback_packet_callback = server_send_loopback_packet_callback;
    memcpy(&server_config.private_key, private_key, NETCODE_KEY_BYTES);

    struct netcode_server_t * server = netcode_server_create("[::1]:40000", &server_config, time);

    check(server);

    int max_clients = 2;

    netcode_server_start(server, max_clients);

    context.server = server;

    // connect a loopback client in slot 0

    struct netcode_client_config_t client_config;
    netcode_default_client_config(&client_config);
    client_config.callback_context = &context;
    client_config.send_loopback_packet_callback = client_send_loopback_packet_callback;
    client_config.network_simulator = network_simulator;

    struct netcode_client_t * loopback_client = netcode_client_create("[::]:50000", &client_config, time);
    check(loopback_client);
    netcode_client_connect_loopback(loopback_client, 0, max_clients);
    context.client = loopback_client;

    check(netcode_client_index(loopback_client) == 0);
    check(netcode_client_loopback(loopback_client) == 1);
    check(netcode_client_max_clients(loopback_client) == max_clients);
    check(netcode_client_state(loopback_client) == NETCODE_CLIENT_STATE_CONNECTED);

    uint64_t client_id = 0;
    netcode_random_bytes((uint8_t*) &client_id, 8);
    netcode_server_connect_loopback_client(server, 0, client_id, null);

    check(netcode_server_client_loopback(server, 0) == 1);
    check(netcode_server_client_connected(server, 0) == 1);
    check(netcode_server_num_connected_clients(server) == 1);

    // connect a regular client in the other slot

    struct netcode_client_t * regular_client = netcode_client_create("[::]:50001", &client_config, time);

    check(regular_client);

    NETCODE_CONST char * server_address = "[::1]:40000";

    uint8_t connect_token[NETCODE_CONNECT_TOKEN_BYTES];
    netcode_random_bytes((uint8_t*) &client_id, 8);

    uint8_t user_data[NETCODE_USER_DATA_BYTES];
    netcode_random_bytes(user_data, NETCODE_USER_DATA_BYTES);

    check(netcode_generate_connect_token(1, &server_address, &server_address, TEST_CONNECT_TOKEN_EXPIRY, TEST_TIMEOUT_SECONDS, client_id, TEST_PROTOCOL_ID, private_key, user_data, connect_token));

    netcode_client_connect(regular_client, connect_token);

    while (1)
    {
        netcode_network_simulator_update(network_simulator, time);

        netcode_client_update(regular_client, time);

        netcode_server_update(server, time);

        if (netcode_client_state(regular_client) <= NETCODE_CLIENT_STATE_DISCONNECTED)
            break;

        if (netcode_client_state(regular_client) == NETCODE_CLIENT_STATE_CONNECTED)
            break;

        time += delta_time;
    }

    check(netcode_client_state(regular_client) == NETCODE_CLIENT_STATE_CONNECTED);
    check(netcode_client_index(regular_client) == 1);
    check(netcode_server_client_connected(server, 0) == 1);
    check(netcode_server_client_connected(server, 1) == 1);
    check(netcode_server_client_loopback(server, 0) == 1);
    check(netcode_server_client_loopback(server, 1) == 0);
    check(netcode_server_num_connected_clients(server) == 2);

    // test that we can exchange packets for the regular client and the loopback client

    int loopback_client_num_packets_received = 0;
    int loopback_server_num_packets_received = 0;
    int regular_server_num_packets_received = 0;
    int regular_client_num_packets_received = 0;

    uint8_t packet_data[NETCODE_MAX_PACKET_SIZE];
    int i;
    for (i = 0; i < NETCODE_MAX_PACKET_SIZE; i++)
        packet_data[i] = (uint8_t) i;

    while (1)
    {
        netcode_network_simulator_update(network_simulator, time);

        netcode_client_update(regular_client, time);

        netcode_server_update(server, time);

        netcode_client_send_packet(loopback_client, packet_data, NETCODE_MAX_PACKET_SIZE);

        netcode_client_send_packet(regular_client, packet_data, NETCODE_MAX_PACKET_SIZE);

        netcode_server_send_packet(server, 0, packet_data, NETCODE_MAX_PACKET_SIZE);

        netcode_server_send_packet(server, 1, packet_data, NETCODE_MAX_PACKET_SIZE);

        while (1)
        {
            int packet_bytes;
            uint64_t packet_sequence;
            uint8_t * packet = netcode_client_receive_packet(loopback_client, &packet_bytes, &packet_sequence);
            if (!packet)
                break;
            (void) packet_sequence;
            netcode_assert(packet_bytes == NETCODE_MAX_PACKET_SIZE);
            netcode_assert(memcmp(packet, packet_data, NETCODE_MAX_PACKET_SIZE) == 0);
            loopback_client_num_packets_received++;
            netcode_client_free_packet(loopback_client, packet);
        }

        while (1)
        {
            int packet_bytes;
            uint64_t packet_sequence;
            uint8_t * packet = netcode_client_receive_packet(regular_client, &packet_bytes, &packet_sequence);
            if (!packet)
                break;
            (void) packet_sequence;
            netcode_assert(packet_bytes == NETCODE_MAX_PACKET_SIZE);
            netcode_assert(memcmp(packet, packet_data, NETCODE_MAX_PACKET_SIZE) == 0);
            regular_client_num_packets_received++;
            netcode_client_free_packet(regular_client, packet);
        }

        while (1)
        {
            int packet_bytes;
            uint64_t packet_sequence;
            void * packet = netcode_server_receive_packet(server, 0, &packet_bytes, &packet_sequence);
            if (!packet)
                break;
            (void) packet_sequence;
            netcode_assert(packet_bytes == NETCODE_MAX_PACKET_SIZE);
            netcode_assert(memcmp(packet, packet_data, NETCODE_MAX_PACKET_SIZE) == 0);
            loopback_server_num_packets_received++;
            netcode_server_free_packet(server, packet);
        }

        while (1)
        {
            int packet_bytes;
            uint64_t packet_sequence;
            void * packet = netcode_server_receive_packet(server, 1, &packet_bytes, &packet_sequence);
            if (!packet)
                break;
            (void) packet_sequence;
            netcode_assert(packet_bytes == NETCODE_MAX_PACKET_SIZE);
            netcode_assert(memcmp(packet, packet_data, NETCODE_MAX_PACKET_SIZE) == 0);
            regular_server_num_packets_received++;
            netcode_server_free_packet(server, packet);
        }

        if (loopback_client_num_packets_received >= 10 && loopback_server_num_packets_received >= 10 &&
             regular_client_num_packets_received >= 10 && regular_server_num_packets_received >= 10)
            break;

        if (netcode_client_state(regular_client) <= NETCODE_CLIENT_STATE_DISCONNECTED)
            break;

        time += delta_time;
    }

    check(loopback_client_num_packets_received >= 10);
    check(loopback_server_num_packets_received >= 10);
    check(regular_client_num_packets_received >= 10);
    check(regular_server_num_packets_received >= 10);
    check(context.num_loopback_packets_sent_to_client >= 10);
    check(context.num_loopback_packets_sent_to_server >= 10);

    // verify that we can disconnect the loopback client

    check(netcode_server_client_loopback(server, 0) == 1);
    check(netcode_server_client_connected(server, 0) == 1);
    check(netcode_server_num_connected_clients(server) == 2);

    netcode_server_disconnect_loopback_client(server, 0);

    check(netcode_server_client_loopback(server, 0) == 0);
    check(netcode_server_client_connected(server, 0) == 0);
    check(netcode_server_num_connected_clients(server) == 1);

    netcode_client_disconnect_loopback(loopback_client);

    check(netcode_client_state(loopback_client) == NETCODE_CLIENT_STATE_DISCONNECTED);

    // verify that we can reconnect the loopback client

    netcode_random_bytes((uint8_t*) &client_id, 8);
    netcode_server_connect_loopback_client(server, 0, client_id, null);

    check(netcode_server_client_loopback(server, 0) == 1);
    check(netcode_server_client_loopback(server, 1) == 0);
    check(netcode_server_client_connected(server, 0) == 1);
    check(netcode_server_client_connected(server, 1) == 1);
    check(netcode_server_num_connected_clients(server) == 2);

    netcode_client_connect_loopback(loopback_client, 0, max_clients);

    check(netcode_client_index(loopback_client) == 0);
    check(netcode_client_loopback(loopback_client) == 1);
    check(netcode_client_max_clients(loopback_client) == max_clients);
    check(netcode_client_state(loopback_client) == NETCODE_CLIENT_STATE_CONNECTED);

    // verify that we can exchange packets for both regular and loopback client post reconnect

    loopback_server_num_packets_received = 0;
    loopback_client_num_packets_received = 0;
    regular_server_num_packets_received = 0;
    regular_client_num_packets_received = 0;
    context.num_loopback_packets_sent_to_client = 0;
    context.num_loopback_packets_sent_to_server = 0;

    while (1)
    {
        netcode_network_simulator_update(network_simulator, time);

        netcode_client_update(regular_client, time);

        netcode_server_update(server, time);

        netcode_client_send_packet(loopback_client, packet_data, NETCODE_MAX_PACKET_SIZE);

        netcode_client_send_packet(regular_client, packet_data, NETCODE_MAX_PACKET_SIZE);

        netcode_server_send_packet(server, 0, packet_data, NETCODE_MAX_PACKET_SIZE);

        netcode_server_send_packet(server, 1, packet_data, NETCODE_MAX_PACKET_SIZE);

        while (1)
        {
            int packet_bytes;
            uint64_t packet_sequence;
            uint8_t * packet = netcode_client_receive_packet(loopback_client, &packet_bytes, &packet_sequence);
            if (!packet)
                break;
            (void) packet_sequence;
            netcode_assert(packet_bytes == NETCODE_MAX_PACKET_SIZE);
            netcode_assert(memcmp(packet, packet_data, NETCODE_MAX_PACKET_SIZE) == 0);
            loopback_client_num_packets_received++;
            netcode_client_free_packet(loopback_client, packet);
        }

        while (1)
        {
            int packet_bytes;
            uint64_t packet_sequence;
            uint8_t * packet = netcode_client_receive_packet(regular_client, &packet_bytes, &packet_sequence);
            if (!packet)
                break;
            (void) packet_sequence;
            netcode_assert(packet_bytes == NETCODE_MAX_PACKET_SIZE);
            netcode_assert(memcmp(packet, packet_data, NETCODE_MAX_PACKET_SIZE) == 0);
            regular_client_num_packets_received++;
            netcode_client_free_packet(regular_client, packet);
        }

        while (1)
        {
            int packet_bytes;
            uint64_t packet_sequence;
            void * packet = netcode_server_receive_packet(server, 0, &packet_bytes, &packet_sequence);
            if (!packet)
                break;
            (void) packet_sequence;
            netcode_assert(packet_bytes == NETCODE_MAX_PACKET_SIZE);
            netcode_assert(memcmp(packet, packet_data, NETCODE_MAX_PACKET_SIZE) == 0);
            loopback_server_num_packets_received++;
            netcode_server_free_packet(server, packet);
        }

        while (1)
        {
            int packet_bytes;
            uint64_t packet_sequence;
            void * packet = netcode_server_receive_packet(server, 1, &packet_bytes, &packet_sequence);
            if (!packet)
                break;
            (void) packet_sequence;
            netcode_assert(packet_bytes == NETCODE_MAX_PACKET_SIZE);
            netcode_assert(memcmp(packet, packet_data, NETCODE_MAX_PACKET_SIZE) == 0);
            regular_server_num_packets_received++;
            netcode_server_free_packet(server, packet);
        }

        if (loopback_client_num_packets_received >= 10 && loopback_server_num_packets_received >= 10 &&
             regular_client_num_packets_received >= 10 && regular_server_num_packets_received >= 10)
            break;

        if (netcode_client_state(regular_client) <= NETCODE_CLIENT_STATE_DISCONNECTED)
            break;

        time += delta_time;
    }

    check(loopback_client_num_packets_received >= 10);
    check(loopback_server_num_packets_received >= 10);
    check(regular_client_num_packets_received >= 10);
    check(regular_server_num_packets_received >= 10);
    check(context.num_loopback_packets_sent_to_client >= 10);
    check(context.num_loopback_packets_sent_to_server >= 10);

    // verify the regular client times out but loopback client doesn't

    time += 100000.0;

    netcode_server_update(server, time);

    check(netcode_server_client_connected(server, 0) == 1);
    check(netcode_server_client_connected(server, 1) == 0);

    netcode_client_update(loopback_client, time);

    check(netcode_client_state(loopback_client) == NETCODE_CLIENT_STATE_CONNECTED);

    // verify that disconnect all clients leaves loopback clients alone

    netcode_server_disconnect_all_clients(server);

    check(netcode_server_client_connected(server, 0) == 1);
    check(netcode_server_client_connected(server, 1) == 0);
    check(netcode_server_client_loopback(server, 0) == 1);

    // clean up

    netcode_client_destroy(regular_client);

    netcode_client_destroy(loopback_client);

    netcode_server_destroy(server);

    netcode_network_simulator_destroy(network_simulator);
}

void test_address_map()
{
    const char * str_address_1 = "107.77.207.77:40000";
    const char * str_address_2 = "127.0.0.1:23650";
    const char * str_address_3 = "fe80::202:b3ff:fe1e:8329";
    const char * str_address_4 = "fe80::202:b3ff:fe1e:8330";

    struct netcode_address_map_t * map = netcode_address_map_create(null, null, null);

    struct netcode_address_t address_set;
    struct netcode_address_t address_get;
    struct netcode_address_t address_delete;

    netcode_address_map_reset(map);

    // Set ipv4
    netcode_parse_address(str_address_1, &address_set);
    check(netcode_address_map_set(map, &address_set, 0) == 1);

    // Set ipv6
    netcode_parse_address(str_address_3, &address_set);
    check(netcode_address_map_set(map, &address_set, 1) == 1);

    // Get ipv4
    netcode_parse_address(str_address_1, &address_get);
    check(netcode_address_map_get(map, &address_get) == 0);

    // Get ipv6
    netcode_parse_address(str_address_3, &address_get);
    check(netcode_address_map_get(map, &address_get) == 1);

    // Get non-existent ipv4
    netcode_parse_address(str_address_2, &address_get);
    check(netcode_address_map_get(map, &address_get) == -1);

    // Get non-existent ipv6
    netcode_parse_address(str_address_4, &address_get);
    check(netcode_address_map_get(map, &address_get) == -1);

    // Try to delete key, after that, the key should disappear
    netcode_parse_address(str_address_1, &address_delete);
    netcode_parse_address(str_address_1, &address_get);
    check(netcode_address_map_delete(map, &address_delete) == 1);
    check(netcode_address_map_get(map, &address_get) == -1);

    // Try to delete non-existent key
    netcode_parse_address(str_address_2, &address_delete);
    check (netcode_address_map_delete(map, &address_delete) == 0);

    netcode_address_map_destroy(map);
}
