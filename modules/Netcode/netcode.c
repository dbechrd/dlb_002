

int netcode_server_socket_create(struct netcode_socket_t * socket,
                                  struct netcode_address_t * address,
                                  int send_buffer_size,
                                  int receive_buffer_size,
                                  NETCODE_CONST struct netcode_server_config_t * config)
{
    assert(socket);
    assert(address);
    assert(config);

    if (!config->network_simulator)
    {
        if (!config->override_send_and_receive)
        {
            if (netcode_socket_create(socket, address, send_buffer_size, receive_buffer_size) != NETCODE_SOCKET_ERROR_NONE)
            {
                return 0;
            }
        }
    }

    return 1;
}

struct netcode_server_t * netcode_server_create_overload(NETCODE_CONST char * server_address1_string, NETCODE_CONST char * server_address2_string, NETCODE_CONST struct netcode_server_config_t * config, double time)
{
    assert(config);
    assert(netcode.initialized);

    struct netcode_address_t server_address1;
    struct netcode_address_t server_address2;

    memset(&server_address1, 0, sizeof(server_address1));
    memset(&server_address2, 0, sizeof(server_address2));

    if (netcode_parse_address(server_address1_string, &server_address1) != NETCODE_OK)
    {
        netcode_log(.ERROR, "error: failed to parse server public address\n");
        return NULL;
    }

    if (server_address2_string != NULL && netcode_parse_address(server_address2_string, &server_address2) != NETCODE_OK)
    {
        netcode_log(.ERROR, "error: failed to parse server public address2\n");
        return NULL;
    }

    struct netcode_address_t bind_address_ipv4;
    struct netcode_address_t bind_address_ipv6;

    memset(&bind_address_ipv4, 0, sizeof(bind_address_ipv4));
    memset(&bind_address_ipv6, 0, sizeof(bind_address_ipv6));

    struct netcode_socket_t socket_ipv4;
    struct netcode_socket_t socket_ipv6;

    memset(&socket_ipv4, 0, sizeof(socket_ipv4));
    memset(&socket_ipv6, 0, sizeof(socket_ipv6));

    if (server_address1.type == NETCODE_ADDRESS_IPV4 || server_address2.type == NETCODE_ADDRESS_IPV4)
    {
        bind_address_ipv4.type = NETCODE_ADDRESS_IPV4;
        bind_address_ipv4.port = server_address1.type == NETCODE_ADDRESS_IPV4 ? server_address1.port : server_address2.port;

        if (!netcode_server_socket_create(&socket_ipv4, &bind_address_ipv4, NETCODE_SERVER_SOCKET_SNDBUF_SIZE, NETCODE_SERVER_SOCKET_RCVBUF_SIZE, config))
        {
            return NULL;
        }
    }

    if (server_address1.type == NETCODE_ADDRESS_IPV6 || server_address2.type == NETCODE_ADDRESS_IPV6)
    {
        bind_address_ipv6.type = NETCODE_ADDRESS_IPV6;
        bind_address_ipv6.port = server_address1.type == NETCODE_ADDRESS_IPV6 ? server_address1.port : server_address2.port;

        if (!netcode_server_socket_create(&socket_ipv6, &bind_address_ipv6, NETCODE_SERVER_SOCKET_SNDBUF_SIZE, NETCODE_SERVER_SOCKET_RCVBUF_SIZE, config))
        {
            return NULL;
        }
    }

    struct netcode_server_t * server = (struct netcode_server_t*) config->allocate_function(config->allocator_context, sizeof(struct netcode_server_t));
    if (!server)
    {
        netcode_socket_destroy(&socket_ipv4);
        netcode_socket_destroy(&socket_ipv6);
        return NULL;
    }

    if (!config->network_simulator)
    {
        netcode_log(.VERBOSE_ONLY, "server listening on %s\n", server_address1_string);
    }
    else
    {
        netcode_log(.VERBOSE_ONLY, "server listening on %s (network simulator)\n", server_address1_string);
    }

    server->config = *config;
    server->socket_holder.ipv4 = socket_ipv4;
    server->socket_holder.ipv6 = socket_ipv6;
    server->address = server_address1;
    server->flags = 0;
    server->time = time;
    server->running = 0;
    server->max_clients = 0;
    server->num_connected_clients = 0;
    server->global_sequence = 1ULL << 63;

    memset(server->client_connected, 0, sizeof(server->client_connected));
    memset(server->client_loopback, 0, sizeof(server->client_loopback));
    memset(server->client_confirmed, 0, sizeof(server->client_confirmed));
    memset(server->client_id, 0, sizeof(server->client_id));
    memset(server->client_sequence, 0, sizeof(server->client_sequence));
    memset(server->client_last_packet_send_time, 0, sizeof(server->client_last_packet_send_time));
    memset(server->client_last_packet_receive_time, 0, sizeof(server->client_last_packet_receive_time));
    memset(server->client_address, 0, sizeof(server->client_address));
    netcode_address_map_reset(&server->client_address_map);
    memset(server->client_user_data, 0, sizeof(server->client_user_data));

    int i;
    for (i = 0; i < NETCODE_MAX_CLIENTS; i++)
        server->client_encryption_index[i] = -1;

    netcode_connect_token_entries_reset(server->connect_token_entries);

    netcode_encryption_manager_reset(&server->encryption_manager);

    for (i = 0; i < NETCODE_MAX_CLIENTS; i++)
        netcode_replay_protection_reset(&server->client_replay_protection[i]);

    memset(&server->client_packet_queue, 0, sizeof(server->client_packet_queue));

    return server;
}

struct netcode_server_t * netcode_server_create(NETCODE_CONST char * server_address_string, NETCODE_CONST struct netcode_server_config_t * config, double time)
{
    return netcode_server_create_overload(server_address_string, NULL, config, time);
}

void netcode_server_stop(struct netcode_server_t * server);

void netcode_server_destroy(struct netcode_server_t * server)
{
    assert(server);

    netcode_server_stop(server);

    netcode_socket_destroy(&server->socket_holder.ipv4);
    netcode_socket_destroy(&server->socket_holder.ipv6);

    server->config.free_function(server->config.allocator_context, server);
}

void netcode_server_start(struct netcode_server_t * server, int max_clients)
{
    assert(server);
    assert(max_clients > 0);
    assert(max_clients <= NETCODE_MAX_CLIENTS);

    if (server->running)
        netcode_server_stop(server);

    netcode_log(.VERBOSE_ONLY, "server started with %d client slots\n", max_clients);

    server->running = 1;
    server->max_clients = max_clients;
    server->num_connected_clients = 0;
    server->challenge_sequence = 0;
    netcode_generate_key(server->challenge_key);

    int i;
    for (i = 0; i < server->max_clients; i++)
    {
        //netcode_packet_queue_init(&server->client_packet_queue[i], server->config.allocator_context, server->config.allocate_function, server->config.free_function);
    }
}

void netcode_server_send_global_packet(struct netcode_server_t * server, void * packet, struct netcode_address_t * to, uint8_t * packet_key)
{
    assert(server);
    assert(packet);
    assert(to);
    assert(packet_key);

    uint8_t packet_data[NETCODE_MAX_PACKET_BYTES];

    int packet_bytes = netcode_write_packet(packet, packet_data, NETCODE_MAX_PACKET_BYTES, server->global_sequence, packet_key, server->config.protocol_id);

    assert(packet_bytes <= NETCODE_MAX_PACKET_BYTES);

    if (server->config.network_simulator)
    {
        netcode_network_simulator_send_packet(server->config.network_simulator, &server->address, to, packet_data, packet_bytes);
    }
    else
    {
        if (server->config.override_send_and_receive)
        {
            server->config.send_packet_override(server->config.callback_context, to, packet_data, packet_bytes);
        }
        else if (to->type == NETCODE_ADDRESS_IPV4)
        {
            netcode_socket_send_packet(&server->socket_holder.ipv4, to, packet_data, packet_bytes);
        }
        else if (to->type == NETCODE_ADDRESS_IPV6)
        {
            netcode_socket_send_packet(&server->socket_holder.ipv6, to, packet_data, packet_bytes);
        }
    }

    server->global_sequence++;
}

void netcode_server_send_client_packet(struct netcode_server_t * server, void * packet, int client_index)
{
    assert(server);
    assert(packet);
    assert(client_index >= 0);
    assert(client_index < server->max_clients);
    assert(server->client_connected[client_index]);
    assert(!server->client_loopback[client_index]);

    uint8_t packet_data[NETCODE_MAX_PACKET_BYTES];

    if (!netcode_encryption_manager_touch(&server->encryption_manager,
                                            server->client_encryption_index[client_index],
                                            &server->client_address[client_index],
                                            server->time))
    {
        netcode_log(.ERROR, "error: encryption mapping is out of date for client %d\n", client_index);
        return;
    }

    uint8_t * packet_key = netcode_encryption_manager_get_send_key(&server->encryption_manager, server->client_encryption_index[client_index]);

    int packet_bytes = netcode_write_packet(packet, packet_data, NETCODE_MAX_PACKET_BYTES, server->client_sequence[client_index], packet_key, server->config.protocol_id);

    assert(packet_bytes <= NETCODE_MAX_PACKET_BYTES);

    if (server->config.network_simulator)
    {
        netcode_network_simulator_send_packet(server->config.network_simulator, &server->address, &server->client_address[client_index], packet_data, packet_bytes);
    }
    else
    {
        if (server->config.override_send_and_receive)
        {
            server->config.send_packet_override(server->config.callback_context, &server->client_address[client_index], packet_data, packet_bytes);
        }
        else
        {
            if (server->client_address[client_index].type == NETCODE_ADDRESS_IPV4)
            {
                netcode_socket_send_packet(&server->socket_holder.ipv4, &server->client_address[client_index], packet_data, packet_bytes);
            }
            else if (server->client_address[client_index].type == NETCODE_ADDRESS_IPV6)
            {
                netcode_socket_send_packet(&server->socket_holder.ipv6, &server->client_address[client_index], packet_data, packet_bytes);
            }
        }
    }

    server->client_sequence[client_index]++;

    server->client_last_packet_send_time[client_index] = server->time;
}

void netcode_server_disconnect_client_internal(struct netcode_server_t * server, int client_index, int send_disconnect_packets)
{
    assert(server);
    assert(server->running);
    assert(client_index >= 0);
    assert(client_index < server->max_clients);
    assert(server->client_connected[client_index]);
    assert(!server->client_loopback[client_index]);
    assert(server->encryption_manager.client_index[server->client_encryption_index[client_index]] == client_index);

    netcode_log(.VERBOSE_ONLY, "server disconnected client %d\n", client_index);

    if (server->config.connect_disconnect_callback)
    {
        server->config.connect_disconnect_callback(server->config.callback_context, client_index, 0);
    }

    if (send_disconnect_packets)
    {
        netcode_log(.VERY_VERBOSE_ONLY, "server sent disconnect packets to client %d\n", client_index);

        int i;
        for (i = 0; i < NETCODE_NUM_DISCONNECT_PACKETS; i++)
        {
            netcode_log(.VERY_VERBOSE_ONLY, "server sent disconnect packet %d\n", i);

            struct netcode_connection_disconnect_packet_t packet;
            packet.packet_type = NETCODE_CONNECTION_DISCONNECT_PACKET;

            netcode_server_send_client_packet(server, &packet, client_index);
        }
    }

    while (1)
    {
        void * packet = netcode_packet_queue_pop(&server->client_packet_queue[client_index], NULL);
        if (!packet)
            break;
        server->config.free_function(server->config.allocator_context, packet);
    }

    netcode_packet_queue_clear(&server->client_packet_queue[client_index]);

    netcode_replay_protection_reset(&server->client_replay_protection[client_index]);

    server->encryption_manager.client_index[server->client_encryption_index[client_index]] = -1;

    netcode_encryption_manager_remove_encryption_mapping(&server->encryption_manager, &server->client_address[client_index], server->time);

    server->client_connected[client_index] = 0;
    server->client_confirmed[client_index] = 0;
    server->client_id[client_index] = 0;
    server->client_sequence[client_index] = 0;
    server->client_last_packet_send_time[client_index] = 0.0;
    server->client_last_packet_receive_time[client_index] = 0.0;
    netcode_address_map_delete(&server->client_address_map, &server->client_address[client_index]);
    memset(&server->client_address[client_index], 0, sizeof(struct netcode_address_t));
    server->client_encryption_index[client_index] = -1;
    memset(server->client_user_data[client_index], 0, NETCODE_USER_DATA_BYTES);

    server->num_connected_clients--;

    assert(server->num_connected_clients >= 0);
}

void netcode_server_disconnect_client(struct netcode_server_t * server, int client_index)
{
    assert(server);

    if (!server->running)
        return;

    assert(client_index >= 0);
    assert(client_index < server->max_clients);
    assert(server->client_loopback[client_index] == 0);

    if (!server->client_connected[client_index])
        return;

    if (server->client_loopback[client_index])
        return;

    netcode_server_disconnect_client_internal(server, client_index, 1);
}

void netcode_server_disconnect_all_clients(struct netcode_server_t * server)
{
    assert(server);

    if (!server->running)
        return;

    int i;
    for (i = 0; i < server->max_clients; i++)
    {
        if (server->client_connected[i] && !server->client_loopback[i])
        {
            netcode_server_disconnect_client_internal(server, i, 1);
        }
    }
}

void netcode_server_stop(struct netcode_server_t * server)
{
    assert(server);

    if (!server->running)
        return;

    netcode_server_disconnect_all_clients(server);

    server->running = 0;
    server->max_clients = 0;
    server->num_connected_clients = 0;

    server->global_sequence = 0;
    server->challenge_sequence = 0;
    memset(server->challenge_key, 0, NETCODE_KEY_BYTES);

    netcode_connect_token_entries_reset(server->connect_token_entries);

    netcode_encryption_manager_reset(&server->encryption_manager);

    netcode_log(.VERBOSE_ONLY, "server stopped\n");
}

int netcode_server_find_client_index_by_id(struct netcode_server_t * server, uint64_t client_id)
{
    assert(server);

    int i;
    for (i = 0; i < server->max_clients; i++)
    {
        if (server->client_connected[i] && server->client_id[i] == client_id)
            return i;
    }

    return -1;
}

int netcode_server_find_client_index_by_address(struct netcode_server_t * server, struct netcode_address_t * address)
{
    assert(server);
    assert(address);

    if (address->type == 0)
        return -1;

    return netcode_address_map_get(&server->client_address_map, address);
}

void netcode_server_process_connection_request_packet(struct netcode_server_t * server,
                                                       struct netcode_address_t * from,
                                                       struct netcode_connection_request_packet_t * packet)
{
    assert(server);

    (void) from;

    struct netcode_connect_token_private_t connect_token_private;
    if (netcode_read_connect_token_private(packet->connect_token_data, NETCODE_CONNECT_TOKEN_PRIVATE_BYTES, &connect_token_private) != NETCODE_OK)
    {
        netcode_log(.VERY_VERBOSE_ONLY, "server ignored connection request. failed to read connect token\n");
        return;
    }

    int found_server_address = 0;
    int i;
    for (i = 0; i < connect_token_private.num_server_addresses; i++)
    {
        if (netcode_address_equal(&server->address, &connect_token_private.server_addresses[i]))
        {
            found_server_address = 1;
        }
    }
    if (!found_server_address)
    {
        netcode_log(.VERY_VERBOSE_ONLY, "server ignored connection request. server address not in connect token whitelist\n");
        return;
    }

    if (netcode_server_find_client_index_by_address(server, from) != -1)
    {
        netcode_log(.VERY_VERBOSE_ONLY, "server ignored connection request. a client with this address is already connected\n");
        return;
    }

    if (netcode_server_find_client_index_by_id(server, connect_token_private.client_id) != -1)
    {
        netcode_log(.VERY_VERBOSE_ONLY, "server ignored connection request. a client with this id is already connected\n");
        return;
    }

    if (!netcode_connect_token_entries_find_or_add(server->connect_token_entries,
                                                     from,
                                                     packet->connect_token_data + NETCODE_CONNECT_TOKEN_PRIVATE_BYTES - NETCODE_MAC_BYTES,
                                                     server->time))
    {
        netcode_log(.VERY_VERBOSE_ONLY, "server ignored connection request. connect token has already been used\n");
        return;
    }

    if (server->num_connected_clients == server->max_clients)
    {
        netcode_log(.VERY_VERBOSE_ONLY, "server denied connection request. server is full\n");

        struct netcode_connection_denied_packet_t p;
        p.packet_type = NETCODE_CONNECTION_DENIED_PACKET;

        netcode_server_send_global_packet(server, &p, from, connect_token_private.server_to_client_key);

        return;
    }

    double expire_time = (connect_token_private.timeout_seconds >= 0) ? server->time + connect_token_private.timeout_seconds : -1.0;

    if (!netcode_encryption_manager_add_encryption_mapping(&server->encryption_manager,
                                                             from,
                                                             connect_token_private.server_to_client_key,
                                                             connect_token_private.client_to_server_key,
                                                             server->time,
                                                             expire_time,
                                                             connect_token_private.timeout_seconds))
    {
        netcode_log(.VERY_VERBOSE_ONLY, "server ignored connection request. failed to add encryption mapping\n");
        return;
    }

    struct netcode_challenge_token_t challenge_token;
    challenge_token.client_id = connect_token_private.client_id;
    memcpy(challenge_token.user_data, connect_token_private.user_data, NETCODE_USER_DATA_BYTES);

    struct netcode_connection_challenge_packet_t challenge_packet;
    challenge_packet.packet_type = NETCODE_CONNECTION_CHALLENGE_PACKET;
    challenge_packet.challenge_token_sequence = server->challenge_sequence;
    netcode_write_challenge_token(&challenge_token, challenge_packet.challenge_token_data, NETCODE_CHALLENGE_TOKEN_BYTES);
    if (netcode_encrypt_challenge_token(challenge_packet.challenge_token_data,
                                          NETCODE_CHALLENGE_TOKEN_BYTES,
                                          server->challenge_sequence,
                                          server->challenge_key) != NETCODE_OK)
    {
        netcode_log(.VERY_VERBOSE_ONLY, "server ignored connection request. failed to encrypt challenge token\n");
        return;
    }

    server->challenge_sequence++;

    netcode_log(.VERY_VERBOSE_ONLY, "server sent connection challenge packet\n");

    netcode_server_send_global_packet(server, &challenge_packet, from, connect_token_private.server_to_client_key);
}

int netcode_server_find_free_client_index(struct netcode_server_t * server)
{
    assert(server);

    int i;
    for (i = 0; i < server->max_clients; i++)
    {
        if (!server->client_connected[i])
            return i;
    }

    return -1;
}

void netcode_server_connect_client(struct netcode_server_t * server,
                                    int client_index,
                                    struct netcode_address_t * address,
                                    uint64_t client_id,
                                    int encryption_index,
                                    int timeout_seconds,
                                    void * user_data)
{
    assert(server);
    assert(server->running);
    assert(client_index >= 0);
    assert(client_index < server->max_clients);
    assert(address);
    assert(encryption_index != -1);
    assert(user_data);
    assert(server->encryption_manager.client_index[encryption_index] == -1);

    server->num_connected_clients++;

    assert(server->num_connected_clients <= server->max_clients);

    assert(server->client_connected[client_index] == 0);

    netcode_encryption_manager_set_expire_time(&server->encryption_manager, encryption_index, -1.0);

    server->encryption_manager.client_index[encryption_index] = client_index;

    server->client_connected[client_index] = 1;
    server->client_timeout[client_index] = timeout_seconds;
    server->client_encryption_index[client_index] = encryption_index;
    server->client_id[client_index] = client_id;
    server->client_sequence[client_index] = 0;
    server->client_address[client_index] = *address;
    netcode_address_map_set(&server->client_address_map, address, client_index);
    server->client_last_packet_send_time[client_index] = server->time;
    server->client_last_packet_receive_time[client_index] = server->time;
    memcpy(server->client_user_data[client_index], user_data, NETCODE_USER_DATA_BYTES);

    char address_string[NETCODE_MAX_ADDRESS_STRING_LENGTH];

    netcode_log(.VERBOSE_ONLY, "server accepted client %s %.16" PRIx64 " in slot %d\n",
        netcode_address_to_string(address, address_string), client_id, client_index);

    struct netcode_connection_keep_alive_packet_t packet;
    packet.packet_type = NETCODE_CONNECTION_KEEP_ALIVE_PACKET;
    packet.client_index = client_index;
    packet.max_clients = server->max_clients;

    netcode_server_send_client_packet(server, &packet, client_index);

    if (server->config.connect_disconnect_callback)
    {
        server->config.connect_disconnect_callback(server->config.callback_context, client_index, 1);
    }
}

void netcode_server_process_connection_response_packet(struct netcode_server_t * server,
                                                        struct netcode_address_t * from,
                                                        struct netcode_connection_response_packet_t * packet,
                                                        int encryption_index)
{
    assert(server);

    if (netcode_decrypt_challenge_token(packet->challenge_token_data,
                                          NETCODE_CHALLENGE_TOKEN_BYTES,
                                          packet->challenge_token_sequence,
                                          server->challenge_key) != NETCODE_OK)
    {
        netcode_log(.VERY_VERBOSE_ONLY, "server ignored connection response. failed to decrypt challenge token\n");
        return;
    }

    struct netcode_challenge_token_t challenge_token;
    if (netcode_read_challenge_token(packet->challenge_token_data, NETCODE_CHALLENGE_TOKEN_BYTES, &challenge_token) != NETCODE_OK)
    {
        netcode_log(.VERY_VERBOSE_ONLY, "server ignored connection response. failed to read challenge token\n");
        return;
    }

    uint8_t * packet_send_key = netcode_encryption_manager_get_send_key(&server->encryption_manager, encryption_index);

    if (!packet_send_key)
    {
        netcode_log(.VERY_VERBOSE_ONLY, "server ignored connection response. no packet send key\n");
        return;
    }

    if (netcode_server_find_client_index_by_address(server, from) != -1)
    {
        netcode_log(.VERY_VERBOSE_ONLY, "server ignored connection response. a client with this address is already connected\n");
        return;
    }

    if (netcode_server_find_client_index_by_id(server, challenge_token.client_id) != -1)
    {
        netcode_log(.VERY_VERBOSE_ONLY, "server ignored connection response. a client with this id is already connected\n");
        return;
    }

    if (server->num_connected_clients == server->max_clients)
    {
        netcode_log(.VERY_VERBOSE_ONLY, "server denied connection response. server is full\n");

        struct netcode_connection_denied_packet_t p;
        p.packet_type = NETCODE_CONNECTION_DENIED_PACKET;

        netcode_server_send_global_packet(server, &p, from, packet_send_key);

        return;
    }

    int client_index = netcode_server_find_free_client_index(server);

    assert(client_index != -1);

    int timeout_seconds = netcode_encryption_manager_get_timeout(&server->encryption_manager, encryption_index);

    netcode_server_connect_client(server, client_index, from, challenge_token.client_id, encryption_index, timeout_seconds, challenge_token.user_data);
}

void netcode_server_process_packet_internal(struct netcode_server_t * server,
                                             struct netcode_address_t * from,
                                             void * packet,
                                             uint64_t sequence,
                                             int encryption_index,
                                             int client_index)
{
    assert(server);
    assert(packet);

    (void) from;
    (void) sequence;

    uint8_t packet_type = ((uint8_t*) packet) [0];

    switch (packet_type)
    {
        case NETCODE_CONNECTION_REQUEST_PACKET:
        {
            if ((server->flags & NETCODE_SERVER_FLAG_IGNORE_CONNECTION_REQUEST_PACKETS) == 0)
            {
                char from_address_string[NETCODE_MAX_ADDRESS_STRING_LENGTH];
                netcode_log(.VERY_VERBOSE_ONLY, "server received connection request from %s\n", netcode_address_to_string(from, from_address_string));
                netcode_server_process_connection_request_packet(server, from, (struct netcode_connection_request_packet_t*) packet);
            }
        }
        break;

        case NETCODE_CONNECTION_RESPONSE_PACKET:
        {
            if ((server->flags & NETCODE_SERVER_FLAG_IGNORE_CONNECTION_RESPONSE_PACKETS) == 0)
            {
                char from_address_string[NETCODE_MAX_ADDRESS_STRING_LENGTH];
                netcode_log(.VERY_VERBOSE_ONLY, "server received connection response from %s\n", netcode_address_to_string(from, from_address_string));
                netcode_server_process_connection_response_packet(server, from, (struct netcode_connection_response_packet_t*) packet, encryption_index);
            }
        }
        break;

        case NETCODE_CONNECTION_KEEP_ALIVE_PACKET:
        {
            if (client_index != -1)
            {
                netcode_log(.VERY_VERBOSE_ONLY, "server received connection keep alive packet from client %d\n", client_index);
                server->client_last_packet_receive_time[client_index] = server->time;
                if (!server->client_confirmed[client_index])
                {
                    netcode_log(.VERY_VERBOSE_ONLY, "server confirmed connection with client %d\n", client_index);
                    server->client_confirmed[client_index] = 1;
                }
            }
        }
        break;

        case NETCODE_CONNECTION_PAYLOAD_PACKET:
        {
            if (client_index != -1)
            {
                netcode_log(.VERY_VERBOSE_ONLY, "server received connection payload packet from client %d\n", client_index);
                server->client_last_packet_receive_time[client_index] = server->time;
                if (!server->client_confirmed[client_index])
                {
                    netcode_log(.VERY_VERBOSE_ONLY, "server confirmed connection with client %d\n", client_index);
                    server->client_confirmed[client_index] = 1;
                }
                netcode_packet_queue_push(&server->client_packet_queue[client_index], packet, sequence);
                return;
            }
        }
        break;

        case NETCODE_CONNECTION_DISCONNECT_PACKET:
        {
            if (client_index != -1)
            {
                netcode_log(.VERY_VERBOSE_ONLY, "server received disconnect packet from client %d\n", client_index);
                netcode_server_disconnect_client_internal(server, client_index, 0);
           }
        }
        break;

        default:
            break;
    }

    server->config.free_function(server->config.allocator_context, packet);
}

void netcode_server_process_packet(struct netcode_server_t * server, struct netcode_address_t * from, uint8_t * packet_data, int packet_bytes)
{
    uint8_t allowed_packets[NETCODE_CONNECTION_NUM_PACKETS];
    memset(allowed_packets, 0, sizeof(allowed_packets));
    allowed_packets[NETCODE_CONNECTION_REQUEST_PACKET] = 1;
    allowed_packets[NETCODE_CONNECTION_RESPONSE_PACKET] = 1;
    allowed_packets[NETCODE_CONNECTION_KEEP_ALIVE_PACKET] = 1;
    allowed_packets[NETCODE_CONNECTION_PAYLOAD_PACKET] = 1;
    allowed_packets[NETCODE_CONNECTION_DISCONNECT_PACKET] = 1;

    uint64_t current_timestamp = (uint64_t) time(NULL);

    uint64_t sequence;

    int encryption_index = -1;
    int client_index = netcode_server_find_client_index_by_address(server, from);
    if (client_index != -1)
    {
        assert(client_index >= 0);
        assert(client_index < server->max_clients);
        encryption_index = server->client_encryption_index[client_index];
    }
    else
    {
        encryption_index = netcode_encryption_manager_find_encryption_mapping(&server->encryption_manager, from, server->time);
    }

    uint8_t * read_packet_key = netcode_encryption_manager_get_receive_key(&server->encryption_manager, encryption_index);

    if (!read_packet_key && packet_data[0] != 0)
    {
        char address_string[NETCODE_MAX_ADDRESS_STRING_LENGTH];
        netcode_log(.VERY_VERBOSE_ONLY, "server could not process packet because no encryption mapping exists for %s\n", netcode_address_to_string(from, address_string));
        return;
    }

    void * packet = netcode_read_packet(packet_data,
                                         packet_bytes,
                                         &sequence,
                                         read_packet_key,
                                         server->config.protocol_id,
                                         current_timestamp,
                                         server->config.private_key,
                                         allowed_packets,
                                         (client_index != -1) ? &server->client_replay_protection[client_index] : NULL,
                                         server->config.allocator_context,
                                         server->config.allocate_function);

    if (!packet)
        return;

    netcode_server_process_packet_internal(server, from, packet, sequence, encryption_index, client_index);
}

void netcode_server_read_and_process_packet(struct netcode_server_t * server,
                                             struct netcode_address_t * from,
                                             uint8_t * packet_data,
                                             int packet_bytes,
                                             uint64_t current_timestamp,
                                             uint8_t * allowed_packets)
{
    if (!server->running)
        return;

    if (packet_bytes <= 1)
        return;

    uint64_t sequence;

    int encryption_index = -1;
    int client_index = netcode_server_find_client_index_by_address(server, from);
    if (client_index != -1)
    {
        assert(client_index >= 0);
        assert(client_index < server->max_clients);
        encryption_index = server->client_encryption_index[client_index];
    }
    else
    {
        encryption_index = netcode_encryption_manager_find_encryption_mapping(&server->encryption_manager, from, server->time);
    }

    uint8_t * read_packet_key = netcode_encryption_manager_get_receive_key(&server->encryption_manager, encryption_index);

    if (!read_packet_key && packet_data[0] != 0)
    {
        char address_string[NETCODE_MAX_ADDRESS_STRING_LENGTH];
        netcode_log(.VERY_VERBOSE_ONLY, "server could not process packet because no encryption mapping exists for %s\n", netcode_address_to_string(from, address_string));
        return;
    }

    void * packet = netcode_read_packet(packet_data,
                                         packet_bytes,
                                         &sequence,
                                         read_packet_key,
                                         server->config.protocol_id,
                                         current_timestamp,
                                         server->config.private_key,
                                         allowed_packets,
                                         (client_index != -1) ? &server->client_replay_protection[client_index] : NULL,
                                         server->config.allocator_context,
                                         server->config.allocate_function);

    if (!packet)
        return;

    netcode_server_process_packet_internal(server, from, packet, sequence, encryption_index, client_index);
}

void netcode_server_receive_packets(struct netcode_server_t * server)
{
    assert(server);

    uint8_t allowed_packets[NETCODE_CONNECTION_NUM_PACKETS];
    memset(allowed_packets, 0, sizeof(allowed_packets));
    allowed_packets[NETCODE_CONNECTION_REQUEST_PACKET] = 1;
    allowed_packets[NETCODE_CONNECTION_RESPONSE_PACKET] = 1;
    allowed_packets[NETCODE_CONNECTION_KEEP_ALIVE_PACKET] = 1;
    allowed_packets[NETCODE_CONNECTION_PAYLOAD_PACKET] = 1;
    allowed_packets[NETCODE_CONNECTION_DISCONNECT_PACKET] = 1;

    uint64_t current_timestamp = (uint64_t) time(NULL);

    if (!server->config.network_simulator)
    {
        // process packets received from socket

        while (1)
        {
            struct netcode_address_t from;

            uint8_t packet_data[NETCODE_MAX_PACKET_BYTES];

            int packet_bytes = 0;

            if (server->config.override_send_and_receive)
            {
                packet_bytes = server->config.receive_packet_override(server->config.callback_context, &from, packet_data, NETCODE_MAX_PACKET_BYTES);
            }
            else
            {
                if (server->socket_holder.ipv4.handle != 0)
                    packet_bytes = netcode_socket_receive_packet(&server->socket_holder.ipv4, &from, packet_data, NETCODE_MAX_PACKET_BYTES);

                if (packet_bytes == 0 && server->socket_holder.ipv6.handle != 0)
                    packet_bytes = netcode_socket_receive_packet(&server->socket_holder.ipv6, &from, packet_data, NETCODE_MAX_PACKET_BYTES);
            }

            if (packet_bytes == 0)
                break;

            netcode_server_read_and_process_packet(server, &from, packet_data, packet_bytes, current_timestamp, allowed_packets);
        }
    }
    else
    {
        // process packets received from network simulator

        int num_packets_received = netcode_network_simulator_receive_packets(server->config.network_simulator,
                                                                              &server->address,
                                                                              NETCODE_SERVER_MAX_RECEIVE_PACKETS,
                                                                              server->receive_packet_data,
                                                                              server->receive_packet_bytes,
                                                                              server->receive_from);

        int i;
        for (i = 0; i < num_packets_received; i++)
        {
            netcode_server_read_and_process_packet(server,
                                                    &server->receive_from[i],
                                                    server->receive_packet_data[i],
                                                    server->receive_packet_bytes[i],
                                                    current_timestamp,
                                                    allowed_packets);

            server->config.free_function(server->config.allocator_context, server->receive_packet_data[i]);
        }
    }
}

void netcode_server_send_packets(struct netcode_server_t * server)
{
    assert(server);

    if (!server->running)
        return;

    int i;
    for (i = 0; i < server->max_clients; i++)
    {
        if (server->client_connected[i] && !server->client_loopback[i] &&
             (server->client_last_packet_send_time[i] + (1.0 / NETCODE_PACKET_SEND_RATE) <= server->time))
        {
            netcode_log(.VERY_VERBOSE_ONLY, "server sent connection keep alive packet to client %d\n", i);
            struct netcode_connection_keep_alive_packet_t packet;
            packet.packet_type = NETCODE_CONNECTION_KEEP_ALIVE_PACKET;
            packet.client_index = i;
            packet.max_clients = server->max_clients;
            netcode_server_send_client_packet(server, &packet, i);
        }
    }
}

void netcode_server_check_for_timeouts(struct netcode_server_t * server)
{
    assert(server);

    if (!server->running)
        return;

    int i;
    for (i = 0; i < server->max_clients; i++)
    {
        if (server->client_connected[i] && server->client_timeout[i] > 0 && !server->client_loopback[i] &&
             (server->client_last_packet_receive_time[i] + server->client_timeout[i] <= server->time))
        {
            netcode_log(.VERBOSE_ONLY, "server timed out client %d\n", i);
            netcode_server_disconnect_client_internal(server, i, 0);
        }
    }
}

int netcode_server_client_connected(struct netcode_server_t * server, int client_index)
{
    assert(server);

    if (!server->running)
        return 0;

    if (client_index < 0 || client_index >= server->max_clients)
        return 0;

    return server->client_connected[client_index];
}

uint64_t netcode_server_client_id(struct netcode_server_t * server, int client_index)
{
    assert(server);

    if (!server->running)
        return 0;

    if (client_index < 0 || client_index >= server->max_clients)
        return 0;

    return server->client_id[client_index];
}

struct netcode_address_t * netcode_server_client_address(struct netcode_server_t * server, int client_index)
{
    assert(server);

    if (!server->running)
        return NULL;

    if (client_index < 0 || client_index >= server->max_clients)
        return NULL;

    return &server->client_address[client_index];
}

uint64_t netcode_server_next_packet_sequence(struct netcode_server_t * server, int client_index)
{
    assert(client_index >= 0);
    assert(client_index < server->max_clients);
    if (!server->client_connected[client_index])
        return 0;
    return server->client_sequence[client_index];
}

void netcode_server_send_packet(struct netcode_server_t * server, int client_index, NETCODE_CONST uint8_t * packet_data, int packet_bytes)
{
    assert(server);
    assert(packet_data);
    assert(packet_bytes >= 0);
    assert(packet_bytes <= NETCODE_MAX_PACKET_SIZE);

    if (!server->running)
        return;

    assert(client_index >= 0);
    assert(client_index < server->max_clients);
    if (!server->client_connected[client_index])
        return;

    if (!server->client_loopback[client_index])
    {
        uint8_t buffer[NETCODE_MAX_PAYLOAD_BYTES*2];

        struct netcode_connection_payload_packet_t * packet = (struct netcode_connection_payload_packet_t*) buffer;

        packet->packet_type = NETCODE_CONNECTION_PAYLOAD_PACKET;
        packet->payload_bytes = packet_bytes;
        memcpy(packet->payload_data, packet_data, packet_bytes);

        if (!server->client_confirmed[client_index])
        {
            struct netcode_connection_keep_alive_packet_t keep_alive_packet;
            keep_alive_packet.packet_type = NETCODE_CONNECTION_KEEP_ALIVE_PACKET;
            keep_alive_packet.client_index = client_index;
            keep_alive_packet.max_clients = server->max_clients;
            netcode_server_send_client_packet(server, &keep_alive_packet, client_index);
        }

        netcode_server_send_client_packet(server, packet, client_index);
    }
    else
    {
        assert(server->config.send_loopback_packet_callback);

        server->config.send_loopback_packet_callback(server->config.callback_context,
                                                      client_index,
                                                      packet_data,
                                                      packet_bytes,
                                                      server->client_sequence[client_index]++);

        server->client_last_packet_send_time[client_index] = server->time;
    }
}

uint8_t * netcode_server_receive_packet(struct netcode_server_t * server, int client_index, int * packet_bytes, uint64_t * packet_sequence)
{
    assert(server);
    assert(packet_bytes);

    if (!server->running)
        return NULL;

    if (!server->client_connected[client_index])
        return NULL;

    assert(client_index >= 0);
    assert(client_index < server->max_clients);

    struct netcode_connection_payload_packet_t * packet = (struct netcode_connection_payload_packet_t*)
        netcode_packet_queue_pop(&server->client_packet_queue[client_index], packet_sequence);

    if (packet)
    {
        assert(packet->packet_type == NETCODE_CONNECTION_PAYLOAD_PACKET);
        *packet_bytes = packet->payload_bytes;
        assert(*packet_bytes >= 0);
        assert(*packet_bytes <= NETCODE_MAX_PAYLOAD_BYTES);
        return (uint8_t*) &packet->payload_data;
    }
    else
    {
        return NULL;
    }
}

void netcode_server_free_packet(struct netcode_server_t * server, void * packet)
{
    assert(server);
    assert(packet);
    (void) server;
    int offset = offsetof(struct netcode_connection_payload_packet_t, payload_data);
    server->config.free_function(server->config.allocator_context, ((uint8_t*) packet) - offset);
}

int netcode_server_num_connected_clients(struct netcode_server_t * server)
{
    assert(server);
    return server->num_connected_clients;
}

void * netcode_server_client_user_data(struct netcode_server_t * server, int client_index)
{
    assert(server);
    assert(client_index >= 0);
    assert(client_index < server->max_clients);
    return server->client_user_data[client_index];
}

int netcode_server_running(struct netcode_server_t * server)
{
    assert(server);
    return server->running;
}

int netcode_server_max_clients(struct netcode_server_t * server)
{
    return server->max_clients;
}

void netcode_server_update(struct netcode_server_t * server, double time)
{
    assert(server);
    server->time = time;
    netcode_server_receive_packets(server);
    netcode_server_send_packets(server);
    netcode_server_check_for_timeouts(server);
}

void netcode_server_connect_loopback_client(struct netcode_server_t * server, int client_index, uint64_t client_id, NETCODE_CONST uint8_t * user_data)
{
    assert(server);
    assert(client_index >= 0);
    assert(client_index < server->max_clients);
    assert(server->running);
    assert(!server->client_connected[client_index]);

    server->num_connected_clients++;

    assert(server->num_connected_clients <= server->max_clients);

    server->client_loopback[client_index] = 1;
    server->client_connected[client_index] = 1;
    server->client_confirmed[client_index] = 1;
    server->client_encryption_index[client_index] = -1;
    server->client_id[client_index] = client_id;
    server->client_sequence[client_index] = 0;
    memset(&server->client_address[client_index], 0, sizeof(struct netcode_address_t));
    netcode_address_map_set(&server->client_address_map, &server->client_address[client_index], client_index);
    server->client_last_packet_send_time[client_index] = server->time;
    server->client_last_packet_receive_time[client_index] = server->time;

    if (user_data)
    {
        memcpy(server->client_user_data[client_index], user_data, NETCODE_USER_DATA_BYTES);
    }
    else
    {
        memset(server->client_user_data[client_index], 0, NETCODE_USER_DATA_BYTES);
    }

    netcode_log(.VERBOSE_ONLY, "server connected loopback client %.16" PRIx64 " in slot %d\n", client_id, client_index);

    if (server->config.connect_disconnect_callback)
    {
        server->config.connect_disconnect_callback(server->config.callback_context, client_index, 1);
    }
}

void netcode_server_disconnect_loopback_client(struct netcode_server_t * server, int client_index)
{
    assert(server);
    assert(client_index >= 0);
    assert(client_index < server->max_clients);
    assert(server->running);
    assert(server->client_connected[client_index]);
    assert(server->client_loopback[client_index]);

    netcode_log(.VERBOSE_ONLY, "server disconnected loopback client %d\n", client_index);

    if (server->config.connect_disconnect_callback)
    {
        server->config.connect_disconnect_callback(server->config.callback_context, client_index, 0);
    }

    while (1)
    {
        void * packet = netcode_packet_queue_pop(&server->client_packet_queue[client_index], NULL);
        if (!packet)
            break;
        server->config.free_function(server->config.allocator_context, packet);
    }

    netcode_packet_queue_clear(&server->client_packet_queue[client_index]);

    server->client_connected[client_index] = 0;
    server->client_loopback[client_index] = 0;
    server->client_confirmed[client_index] = 0;
    server->client_id[client_index] = 0;
    server->client_sequence[client_index] = 0;
    server->client_last_packet_send_time[client_index] = 0.0;
    server->client_last_packet_receive_time[client_index] = 0.0;
    netcode_address_map_delete(&server->client_address_map, &server->client_address[client_index]);
    memset(&server->client_address[client_index], 0, sizeof(struct netcode_address_t));
    server->client_encryption_index[client_index] = -1;
    memset(server->client_user_data[client_index], 0, NETCODE_USER_DATA_BYTES);

    server->num_connected_clients--;

    assert(server->num_connected_clients >= 0);
}

int netcode_server_client_loopback(struct netcode_server_t * server, int client_index)
{
    assert(server);
    assert(server->running);
    assert(client_index >= 0);
    assert(client_index < server->max_clients);
    return server->client_loopback[client_index];
}

void netcode_server_process_loopback_packet(struct netcode_server_t * server, int client_index, NETCODE_CONST uint8_t * packet_data, int packet_bytes, uint64_t packet_sequence)
{
    assert(server);
    assert(client_index >= 0);
    assert(client_index < server->max_clients);
    assert(packet_data);
    assert(packet_bytes >= 0);
    assert(packet_bytes <= NETCODE_MAX_PACKET_SIZE);
    assert(server->client_connected[client_index]);
    assert(server->client_loopback[client_index]);
    assert(server->running);

    struct netcode_connection_payload_packet_t * packet = netcode_create_payload_packet(packet_bytes, server->config.allocator_context, server->config.allocate_function);
    if (!packet)
        return;

    memcpy(packet->payload_data, packet_data, packet_bytes);

    netcode_log(.VERY_VERBOSE_ONLY, "server processing loopback packet from client %d\n", client_index);

    server->client_last_packet_receive_time[client_index] = server->time;

    netcode_packet_queue_push(&server->client_packet_queue[client_index], packet, packet_sequence);
}

uint16_t netcode_server_get_port(struct netcode_server_t * server)
{
    assert(server);
    return server->address.type == NETCODE_ADDRESS_IPV4 ? server->socket_holder.ipv4.address.port : server->socket_holder.ipv6.address.port;
}

// ----------------------------------------------------------------

int netcode_generate_connect_token(int num_server_addresses,
                                    NETCODE_CONST char ** public_server_addresses,
                                    NETCODE_CONST char ** internal_server_addresses,
                                    int expire_seconds,
                                    int timeout_seconds,
                                    uint64_t client_id,
                                    uint64_t protocol_id,
                                    NETCODE_CONST uint8_t * private_key,
                                    uint8_t * user_data,
                                    uint8_t * output_buffer)
{
    assert(num_server_addresses > 0);
    assert(num_server_addresses <= NETCODE_MAX_SERVERS_PER_CONNECT);
    assert(public_server_addresses);
    assert(internal_server_addresses);
    assert(private_key);
    assert(user_data);
    assert(output_buffer);

    // parse public server addresses

    struct netcode_address_t parsed_public_server_addresses[NETCODE_MAX_SERVERS_PER_CONNECT];
    int i;
    for (i = 0; i < num_server_addresses; i++)
    {
        if (netcode_parse_address(public_server_addresses[i], &parsed_public_server_addresses[i]) != NETCODE_OK)
        {
            return NETCODE_ERROR;
        }
    }

    // parse internal server addresses

     struct netcode_address_t parsed_internal_server_addresses[NETCODE_MAX_SERVERS_PER_CONNECT];
    for (i = 0; i < num_server_addresses; i++)
    {
        if (netcode_parse_address(internal_server_addresses[i], &parsed_internal_server_addresses[i]) != NETCODE_OK)
        {
            return NETCODE_ERROR;
        }
    }

    // generate a connect token

    uint8_t nonce[NETCODE_CONNECT_TOKEN_NONCE_BYTES];
    netcode_generate_nonce(nonce);

    struct netcode_connect_token_private_t connect_token_private;
    netcode_generate_connect_token_private(&connect_token_private, client_id, timeout_seconds, num_server_addresses, parsed_internal_server_addresses, user_data);

    // write it to a buffer

    uint8_t connect_token_data[NETCODE_CONNECT_TOKEN_PRIVATE_BYTES];
    netcode_write_connect_token_private(&connect_token_private, connect_token_data, NETCODE_CONNECT_TOKEN_PRIVATE_BYTES);

    // encrypt the buffer

    uint64_t create_timestamp = time(NULL);
    uint64_t expire_timestamp = (expire_seconds >= 0) ? (create_timestamp + expire_seconds) : 0xFFFF_FFFF_FFFF_FFFF;
    if (netcode_encrypt_connect_token_private(connect_token_data, NETCODE_CONNECT_TOKEN_PRIVATE_BYTES, NETCODE_VERSION_INFO, protocol_id, expire_timestamp, nonce, private_key) != NETCODE_OK)
        return NETCODE_ERROR;

    // wrap a connect token around the private connect token data

    struct netcode_connect_token_t connect_token;
    memcpy(connect_token.version_info, NETCODE_VERSION_INFO, NETCODE_VERSION_INFO_BYTES);
    connect_token.protocol_id = protocol_id;
    connect_token.create_timestamp = create_timestamp;
    connect_token.expire_timestamp = expire_timestamp;
    memcpy(connect_token.nonce, nonce, NETCODE_CONNECT_TOKEN_NONCE_BYTES);
    memcpy(connect_token.private_data, connect_token_data, NETCODE_CONNECT_TOKEN_PRIVATE_BYTES);
    connect_token.num_server_addresses = num_server_addresses;
    for (i = 0; i < num_server_addresses; i++)
        connect_token.server_addresses[i] = parsed_public_server_addresses[i];
    memcpy(connect_token.client_to_server_key, connect_token_private.client_to_server_key, NETCODE_KEY_BYTES);
    memcpy(connect_token.server_to_client_key, connect_token_private.server_to_client_key, NETCODE_KEY_BYTES);
    connect_token.timeout_seconds = timeout_seconds;

    // write the connect token to the output buffer

    netcode_write_connect_token(&connect_token, output_buffer, NETCODE_CONNECT_TOKEN_BYTES);

    return NETCODE_OK;
}

// ---------------------------------------------------------------

#if NETCODE_ENABLE_TESTS
// TODO(dlb): Port the tests
#endif // #if NETCODE_ENABLE_TESTS
