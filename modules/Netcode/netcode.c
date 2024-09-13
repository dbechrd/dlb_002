
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

    uint64_t current_timestamp = (uint64_t) time(null);

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
        return null;

    if (client_index < 0 || client_index >= server->max_clients)
        return null;

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
        return null;

    if (!server->client_connected[client_index])
        return null;

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
        return null;
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
        void * packet = netcode_packet_queue_pop(&server->client_packet_queue[client_index], null);
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

    uint64_t create_timestamp = time(null);
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
