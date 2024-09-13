


static void test_address()
{
    {
        struct netcode_address_t address;
        check(netcode_parse_address("", &address) == NETCODE_ERROR);
        check(netcode_parse_address("[", &address) == NETCODE_ERROR);
        check(netcode_parse_address("[]", &address) == NETCODE_ERROR);
        check(netcode_parse_address("[]:", &address) == NETCODE_ERROR);
        check(netcode_parse_address(":", &address) == NETCODE_ERROR);
        check(netcode_parse_address("1", &address) == NETCODE_ERROR);
        check(netcode_parse_address("12", &address) == NETCODE_ERROR);
        check(netcode_parse_address("123", &address) == NETCODE_ERROR);
        check(netcode_parse_address("1234", &address) == NETCODE_ERROR);
        check(netcode_parse_address("1234.0.12313.0000", &address) == NETCODE_ERROR);
        check(netcode_parse_address("1234.0.12313.0000.0.0.0.0.0", &address) == NETCODE_ERROR);
        check(netcode_parse_address("1312313:123131:1312313:123131:1312313:123131:1312313:123131:1312313:123131:1312313:123131", &address) == NETCODE_ERROR);
        check(netcode_parse_address(".", &address) == NETCODE_ERROR);
        check(netcode_parse_address("..", &address) == NETCODE_ERROR);
        check(netcode_parse_address("...", &address) == NETCODE_ERROR);
        check(netcode_parse_address("....", &address) == NETCODE_ERROR);
        check(netcode_parse_address(".....", &address) == NETCODE_ERROR);
    }

    {
        struct netcode_address_t address;
        check(netcode_parse_address("107.77.207.77", &address) == NETCODE_OK);
        check(address.type == NETCODE_ADDRESS_IPV4);
        check(address.port == 0);
        check(address.data.ipv4[0] == 107);
        check(address.data.ipv4[1] == 77);
        check(address.data.ipv4[2] == 207);
        check(address.data.ipv4[3] == 77);
    }

    {
        struct netcode_address_t address;
        check(netcode_parse_address("127.0.0.1", &address) == NETCODE_OK);
        check(address.type == NETCODE_ADDRESS_IPV4);
        check(address.port == 0);
        check(address.data.ipv4[0] == 127);
        check(address.data.ipv4[1] == 0);
        check(address.data.ipv4[2] == 0);
        check(address.data.ipv4[3] == 1);
    }

    {
        struct netcode_address_t address;
        check(netcode_parse_address("107.77.207.77:40000", &address) == NETCODE_OK);
        check(address.type == NETCODE_ADDRESS_IPV4);
        check(address.port == 40000);
        check(address.data.ipv4[0] == 107);
        check(address.data.ipv4[1] == 77);
        check(address.data.ipv4[2] == 207);
        check(address.data.ipv4[3] == 77);
    }

    {
        struct netcode_address_t address;
        check(netcode_parse_address("127.0.0.1:40000", &address) == NETCODE_OK);
        check(address.type == NETCODE_ADDRESS_IPV4);
        check(address.port == 40000);
        check(address.data.ipv4[0] == 127);
        check(address.data.ipv4[1] == 0);
        check(address.data.ipv4[2] == 0);
        check(address.data.ipv4[3] == 1);
    }

    {
        struct netcode_address_t address;
        check(netcode_parse_address("fe80::202:b3ff:fe1e:8329", &address) == NETCODE_OK);
        check(address.type == NETCODE_ADDRESS_IPV6);
        check(address.port == 0);
        check(address.data.ipv6[0] == 0xfe80);
        check(address.data.ipv6[1] == 0x0000);
        check(address.data.ipv6[2] == 0x0000);
        check(address.data.ipv6[3] == 0x0000);
        check(address.data.ipv6[4] == 0x0202);
        check(address.data.ipv6[5] == 0xb3ff);
        check(address.data.ipv6[6] == 0xfe1e);
        check(address.data.ipv6[7] == 0x8329);
    }

    {
        struct netcode_address_t address;
        check(netcode_parse_address("::", &address) == NETCODE_OK);
        check(address.type == NETCODE_ADDRESS_IPV6);
        check(address.port == 0);
        check(address.data.ipv6[0] == 0x0000);
        check(address.data.ipv6[1] == 0x0000);
        check(address.data.ipv6[2] == 0x0000);
        check(address.data.ipv6[3] == 0x0000);
        check(address.data.ipv6[4] == 0x0000);
        check(address.data.ipv6[5] == 0x0000);
        check(address.data.ipv6[6] == 0x0000);
        check(address.data.ipv6[7] == 0x0000);
    }

    {
        struct netcode_address_t address;
        check(netcode_parse_address("::1", &address) == NETCODE_OK);
        check(address.type == NETCODE_ADDRESS_IPV6);
        check(address.port == 0);
        check(address.data.ipv6[0] == 0x0000);
        check(address.data.ipv6[1] == 0x0000);
        check(address.data.ipv6[2] == 0x0000);
        check(address.data.ipv6[3] == 0x0000);
        check(address.data.ipv6[4] == 0x0000);
        check(address.data.ipv6[5] == 0x0000);
        check(address.data.ipv6[6] == 0x0000);
        check(address.data.ipv6[7] == 0x0001);
    }

    {
        struct netcode_address_t address;
        check(netcode_parse_address("[fe80::202:b3ff:fe1e:8329]:40000", &address) == NETCODE_OK);
        check(address.type == NETCODE_ADDRESS_IPV6);
        check(address.port == 40000);
        check(address.data.ipv6[0] == 0xfe80);
        check(address.data.ipv6[1] == 0x0000);
        check(address.data.ipv6[2] == 0x0000);
        check(address.data.ipv6[3] == 0x0000);
        check(address.data.ipv6[4] == 0x0202);
        check(address.data.ipv6[5] == 0xb3ff);
        check(address.data.ipv6[6] == 0xfe1e);
        check(address.data.ipv6[7] == 0x8329);
    }

    {
        struct netcode_address_t address;
        check(netcode_parse_address("[::]:40000", &address) == NETCODE_OK);
        check(address.type == NETCODE_ADDRESS_IPV6);
        check(address.port == 40000);
        check(address.data.ipv6[0] == 0x0000);
        check(address.data.ipv6[1] == 0x0000);
        check(address.data.ipv6[2] == 0x0000);
        check(address.data.ipv6[3] == 0x0000);
        check(address.data.ipv6[4] == 0x0000);
        check(address.data.ipv6[5] == 0x0000);
        check(address.data.ipv6[6] == 0x0000);
        check(address.data.ipv6[7] == 0x0000);
    }

    {
        struct netcode_address_t address;
        check(netcode_parse_address("[::1]:40000", &address) == NETCODE_OK);
        check(address.type == NETCODE_ADDRESS_IPV6);
        check(address.port == 40000);
        check(address.data.ipv6[0] == 0x0000);
        check(address.data.ipv6[1] == 0x0000);
        check(address.data.ipv6[2] == 0x0000);
        check(address.data.ipv6[3] == 0x0000);
        check(address.data.ipv6[4] == 0x0000);
        check(address.data.ipv6[5] == 0x0000);
        check(address.data.ipv6[6] == 0x0000);
        check(address.data.ipv6[7] == 0x0001);
    }
}

#define TEST_PROTOCOL_ID            0x1122334455667788ULL
#define TEST_CLIENT_ID              0x1ULL
#define TEST_SERVER_PORT            40000
#define TEST_CONNECT_TOKEN_EXPIRY   30
#define TEST_TIMEOUT_SECONDS        15

static void test_connect_token()
{
    // generate a connect token

    struct netcode_address_t server_address;
    server_address.type = NETCODE_ADDRESS_IPV4;
    server_address.data.ipv4[0] = 127;
    server_address.data.ipv4[1] = 0;
    server_address.data.ipv4[2] = 0;
    server_address.data.ipv4[3] = 1;
    server_address.port = TEST_SERVER_PORT;

    uint8_t user_data[NETCODE_USER_DATA_BYTES];
    netcode_random_bytes(user_data, NETCODE_USER_DATA_BYTES);

    struct netcode_connect_token_private_t input_token;

    netcode_generate_connect_token_private(&input_token, TEST_CLIENT_ID, TEST_TIMEOUT_SECONDS, 1, &server_address, user_data);

    check(input_token.client_id == TEST_CLIENT_ID);
    check(input_token.num_server_addresses == 1);
    check(memcmp(input_token.user_data, user_data, NETCODE_USER_DATA_BYTES) == 0);
    check(netcode_address_equal(&input_token.server_addresses[0], &server_address));

    // write it to a buffer

    uint8_t buffer[NETCODE_CONNECT_TOKEN_PRIVATE_BYTES];

    netcode_write_connect_token_private(&input_token, buffer, NETCODE_CONNECT_TOKEN_PRIVATE_BYTES);

    // encrypt the buffer

    uint64_t expire_timestamp = time(null) + 30;
    uint8_t nonce[NETCODE_CONNECT_TOKEN_NONCE_BYTES];
    netcode_generate_nonce(nonce);
    uint8_t key[NETCODE_KEY_BYTES];
    netcode_generate_key(key);

    check(netcode_encrypt_connect_token_private(buffer,
                                                  NETCODE_CONNECT_TOKEN_PRIVATE_BYTES,
                                                  NETCODE_VERSION_INFO,
                                                  TEST_PROTOCOL_ID,
                                                  expire_timestamp,
                                                  nonce,
                                                  key) == NETCODE_OK);

    // decrypt the buffer

    check(netcode_decrypt_connect_token_private(buffer,
                                                  NETCODE_CONNECT_TOKEN_PRIVATE_BYTES,
                                                  NETCODE_VERSION_INFO,
                                                  TEST_PROTOCOL_ID,
                                                  expire_timestamp,
                                                  nonce,
                                                  key) == NETCODE_OK);

    // read the connect token back in

    struct netcode_connect_token_private_t output_token;

    check(netcode_read_connect_token_private(buffer, NETCODE_CONNECT_TOKEN_PRIVATE_BYTES, &output_token) == NETCODE_OK);

    // make sure that everything matches the original connect token

    check(output_token.client_id == input_token.client_id);
    check(output_token.timeout_seconds == input_token.timeout_seconds);
    check(output_token.num_server_addresses == input_token.num_server_addresses);
    check(netcode_address_equal(&output_token.server_addresses[0], &input_token.server_addresses[0]));
    check(memcmp(output_token.client_to_server_key, input_token.client_to_server_key, NETCODE_KEY_BYTES) == 0);
    check(memcmp(output_token.server_to_client_key, input_token.server_to_client_key, NETCODE_KEY_BYTES) == 0);
    check(memcmp(output_token.user_data, input_token.user_data, NETCODE_USER_DATA_BYTES) == 0);
}

static void test_challenge_token()
{
    // generate a challenge token

    struct netcode_challenge_token_t input_token;

    input_token.client_id = TEST_CLIENT_ID;
    netcode_random_bytes(input_token.user_data, NETCODE_USER_DATA_BYTES);

    // write it to a buffer

    uint8_t buffer[NETCODE_CHALLENGE_TOKEN_BYTES];

    netcode_write_challenge_token(&input_token, buffer, NETCODE_CHALLENGE_TOKEN_BYTES);

    // encrypt the buffer

    uint64_t sequence = 1000;
    uint8_t key[NETCODE_KEY_BYTES];
    netcode_generate_key(key);

    check(netcode_encrypt_challenge_token(buffer, NETCODE_CHALLENGE_TOKEN_BYTES, sequence, key) == NETCODE_OK);

    // decrypt the buffer

    check(netcode_decrypt_challenge_token(buffer, NETCODE_CHALLENGE_TOKEN_BYTES, sequence, key) == NETCODE_OK);

    // read the challenge token back in

    struct netcode_challenge_token_t output_token;

    check(netcode_read_challenge_token(buffer, NETCODE_CHALLENGE_TOKEN_BYTES, &output_token) == NETCODE_OK);

    // make sure that everything matches the original challenge token

    check(output_token.client_id == input_token.client_id);
    check(memcmp(output_token.user_data, input_token.user_data, NETCODE_USER_DATA_BYTES) == 0);
}

static void test_connection_request_packet()
{
    // generate a connect token

    struct netcode_address_t server_address;
    server_address.type = NETCODE_ADDRESS_IPV4;
    server_address.data.ipv4[0] = 127;
    server_address.data.ipv4[1] = 0;
    server_address.data.ipv4[2] = 0;
    server_address.data.ipv4[3] = 1;
    server_address.port = TEST_SERVER_PORT;

    uint8_t user_data[NETCODE_USER_DATA_BYTES];
    netcode_random_bytes(user_data, NETCODE_USER_DATA_BYTES);

    struct netcode_connect_token_private_t input_token;

    netcode_generate_connect_token_private(&input_token, TEST_CLIENT_ID, TEST_TIMEOUT_SECONDS, 1, &server_address, user_data);

    check(input_token.client_id == TEST_CLIENT_ID);
    check(input_token.num_server_addresses == 1);
    check(memcmp(input_token.user_data, user_data, NETCODE_USER_DATA_BYTES) == 0);
    check(netcode_address_equal(&input_token.server_addresses[0], &server_address));

    // write the conect token to a buffer (non-encrypted)

    uint8_t connect_token_data[NETCODE_CONNECT_TOKEN_PRIVATE_BYTES];

    netcode_write_connect_token_private(&input_token, connect_token_data, NETCODE_CONNECT_TOKEN_PRIVATE_BYTES);

    // copy to a second buffer then encrypt it in place (we need the unencrypted token for verification later on)

    uint8_t encrypted_connect_token_data[NETCODE_CONNECT_TOKEN_PRIVATE_BYTES];

    memcpy(encrypted_connect_token_data, connect_token_data, NETCODE_CONNECT_TOKEN_PRIVATE_BYTES);

    uint64_t connect_token_expire_timestamp = time(null) + 30;
    uint8_t connect_token_nonce[NETCODE_CONNECT_TOKEN_NONCE_BYTES];
    netcode_generate_nonce(connect_token_nonce);
    uint8_t connect_token_key[NETCODE_KEY_BYTES];
    netcode_generate_key(connect_token_key);

    check(netcode_encrypt_connect_token_private(encrypted_connect_token_data,
                                                  NETCODE_CONNECT_TOKEN_PRIVATE_BYTES,
                                                  NETCODE_VERSION_INFO,
                                                  TEST_PROTOCOL_ID,
                                                  connect_token_expire_timestamp,
                                                  connect_token_nonce,
                                                  connect_token_key) == NETCODE_OK);

    // setup a connection request packet wrapping the encrypted connect token

    struct netcode_connection_request_packet_t input_packet;

    input_packet.packet_type = NETCODE_CONNECTION_REQUEST_PACKET;
    memcpy(input_packet.version_info, NETCODE_VERSION_INFO, NETCODE_VERSION_INFO_BYTES);
    input_packet.protocol_id = TEST_PROTOCOL_ID;
    input_packet.connect_token_expire_timestamp = connect_token_expire_timestamp;
    memcpy(input_packet.connect_token_nonce, connect_token_nonce, NETCODE_CONNECT_TOKEN_NONCE_BYTES);
    memcpy(input_packet.connect_token_data, encrypted_connect_token_data, NETCODE_CONNECT_TOKEN_PRIVATE_BYTES);

    // write the connection request packet to a buffer

    uint8_t buffer[2048];

    uint8_t packet_key[NETCODE_KEY_BYTES];

    netcode_generate_key(packet_key);

    int bytes_written = netcode_write_packet(&input_packet, buffer, sizeof(buffer), 1000, packet_key, TEST_PROTOCOL_ID);

    check(bytes_written > 0);

    // read the connection request packet back in from the buffer (the connect token data is decrypted as part of the read packet validation)

    uint64_t sequence = 1000;

    uint8_t allowed_packets[NETCODE_CONNECTION_NUM_PACKETS];
    memset(allowed_packets, 1, sizeof(allowed_packets));

    struct netcode_connection_request_packet_t * output_packet = (struct netcode_connection_request_packet_t*)
        netcode_read_packet(buffer, bytes_written, &sequence, packet_key, TEST_PROTOCOL_ID, time(null), connect_token_key, allowed_packets, null, null, null);

    check(output_packet);

    // make sure the read packet matches what was written

    check(output_packet->packet_type == NETCODE_CONNECTION_REQUEST_PACKET);
    check(memcmp(output_packet->version_info, input_packet.version_info, NETCODE_VERSION_INFO_BYTES) == 0);
    check(output_packet->protocol_id == input_packet.protocol_id);
    check(output_packet->connect_token_expire_timestamp == input_packet.connect_token_expire_timestamp);
    check(memcmp(output_packet->connect_token_nonce, input_packet.connect_token_nonce, NETCODE_CONNECT_TOKEN_NONCE_BYTES) == 0);
    check(memcmp(output_packet->connect_token_data, connect_token_data, NETCODE_CONNECT_TOKEN_PRIVATE_BYTES - NETCODE_MAC_BYTES) == 0);

    free(output_packet);
}

void test_connection_denied_packet()
{
    // setup a connection denied packet

    struct netcode_connection_denied_packet_t input_packet;

    input_packet.packet_type = NETCODE_CONNECTION_DENIED_PACKET;

    // write the packet to a buffer

    uint8_t buffer[NETCODE_MAX_PACKET_BYTES];

    uint8_t packet_key[NETCODE_KEY_BYTES];

    netcode_generate_key(packet_key);

    int bytes_written = netcode_write_packet(&input_packet, buffer, sizeof(buffer), 1000, packet_key, TEST_PROTOCOL_ID);

    check(bytes_written > 0);

    // read the packet back in from the buffer

    uint64_t sequence;

    uint8_t allowed_packet_types[NETCODE_CONNECTION_NUM_PACKETS];
    memset(allowed_packet_types, 1, sizeof(allowed_packet_types));

    struct netcode_connection_denied_packet_t * output_packet = (struct netcode_connection_denied_packet_t*)
        netcode_read_packet(buffer, bytes_written, &sequence, packet_key, TEST_PROTOCOL_ID, time(null), null, allowed_packet_types, null, null, null);

    check(output_packet);

    // make sure the read packet matches what was written

    check(output_packet->packet_type == NETCODE_CONNECTION_DENIED_PACKET);

    free(output_packet);
}

void test_connection_challenge_packet()
{
    // setup a connection challenge packet

    struct netcode_connection_challenge_packet_t input_packet;

    input_packet.packet_type = NETCODE_CONNECTION_CHALLENGE_PACKET;
    input_packet.challenge_token_sequence = 0;
    netcode_random_bytes(input_packet.challenge_token_data, NETCODE_CHALLENGE_TOKEN_BYTES);

    // write the packet to a buffer

    uint8_t buffer[NETCODE_MAX_PACKET_BYTES];

    uint8_t packet_key[NETCODE_KEY_BYTES];

    netcode_generate_key(packet_key);

    int bytes_written = netcode_write_packet(&input_packet, buffer, sizeof(buffer), 1000, packet_key, TEST_PROTOCOL_ID);

    check(bytes_written > 0);

    // read the packet back in from the buffer

    uint64_t sequence;

    uint8_t allowed_packet_types[NETCODE_CONNECTION_NUM_PACKETS];
    memset(allowed_packet_types, 1, sizeof(allowed_packet_types));

    struct netcode_connection_challenge_packet_t * output_packet = (struct netcode_connection_challenge_packet_t*)
        netcode_read_packet(buffer, bytes_written, &sequence, packet_key, TEST_PROTOCOL_ID, time(null), null, allowed_packet_types, null, null, null);

    check(output_packet);

    // make sure the read packet packet matches what was written

    check(output_packet->packet_type == NETCODE_CONNECTION_CHALLENGE_PACKET);
    check(output_packet->challenge_token_sequence == input_packet.challenge_token_sequence);
    check(memcmp(output_packet->challenge_token_data, input_packet.challenge_token_data, NETCODE_CHALLENGE_TOKEN_BYTES) == 0);

    free(output_packet);
}

void test_connection_response_packet()
{
    // setup a connection response packet

    struct netcode_connection_response_packet_t input_packet;

    input_packet.packet_type = NETCODE_CONNECTION_RESPONSE_PACKET;
    input_packet.challenge_token_sequence = 0;
    netcode_random_bytes(input_packet.challenge_token_data, NETCODE_CHALLENGE_TOKEN_BYTES);

    // write the packet to a buffer

    uint8_t buffer[NETCODE_MAX_PACKET_BYTES];

    uint8_t packet_key[NETCODE_KEY_BYTES];

    netcode_generate_key(packet_key);

    int bytes_written = netcode_write_packet(&input_packet, buffer, sizeof(buffer), 1000, packet_key, TEST_PROTOCOL_ID);

    check(bytes_written > 0);

    // read the packet back in from the buffer

    uint64_t sequence;

    uint8_t allowed_packet_types[NETCODE_CONNECTION_NUM_PACKETS];
    memset(allowed_packet_types, 1, sizeof(allowed_packet_types));

    struct netcode_connection_response_packet_t * output_packet = (struct netcode_connection_response_packet_t*)
        netcode_read_packet(buffer, bytes_written, &sequence, packet_key, TEST_PROTOCOL_ID, time(null), null, allowed_packet_types, null, null, null);

    check(output_packet);

    // make sure the read packet matches what was written

    check(output_packet->packet_type == NETCODE_CONNECTION_RESPONSE_PACKET);
    check(output_packet->challenge_token_sequence == input_packet.challenge_token_sequence);
    check(memcmp(output_packet->challenge_token_data, input_packet.challenge_token_data, NETCODE_CHALLENGE_TOKEN_BYTES) == 0);

    free(output_packet);
}

void test_connection_keep_alive_packet()
{
    // setup a connection keep alive packet

    struct netcode_connection_keep_alive_packet_t input_packet;

    input_packet.packet_type = NETCODE_CONNECTION_KEEP_ALIVE_PACKET;
    input_packet.client_index = 10;
    input_packet.max_clients = 16;

    // write the packet to a buffer

    uint8_t buffer[NETCODE_MAX_PACKET_BYTES];

    uint8_t packet_key[NETCODE_KEY_BYTES];

    netcode_generate_key(packet_key);

    int bytes_written = netcode_write_packet(&input_packet, buffer, sizeof(buffer), 1000, packet_key, TEST_PROTOCOL_ID);

    check(bytes_written > 0);

    // read the packet back in from the buffer

    uint64_t sequence;

    uint8_t allowed_packet_types[NETCODE_CONNECTION_NUM_PACKETS];
    memset(allowed_packet_types, 1, sizeof(allowed_packet_types));

    struct netcode_connection_keep_alive_packet_t * output_packet = (struct netcode_connection_keep_alive_packet_t*)
        netcode_read_packet(buffer, bytes_written, &sequence, packet_key, TEST_PROTOCOL_ID, time(null), null, allowed_packet_types, null, null, null);

    check(output_packet);

    // make sure the read packet matches what was written

    check(output_packet->packet_type == NETCODE_CONNECTION_KEEP_ALIVE_PACKET);
    check(output_packet->client_index == input_packet.client_index);
    check(output_packet->max_clients == input_packet.max_clients);

    free(output_packet);
}

void test_connection_payload_packet()
{
    // setup a connection payload packet

    struct netcode_connection_payload_packet_t * input_packet = netcode_create_payload_packet(NETCODE_MAX_PAYLOAD_BYTES, null, null);

    check(input_packet->packet_type == NETCODE_CONNECTION_PAYLOAD_PACKET);
    check(input_packet->payload_bytes == NETCODE_MAX_PAYLOAD_BYTES);

    netcode_random_bytes(input_packet->payload_data, NETCODE_MAX_PAYLOAD_BYTES);

    // write the packet to a buffer

    uint8_t buffer[NETCODE_MAX_PACKET_BYTES];

    uint8_t packet_key[NETCODE_KEY_BYTES];

    netcode_generate_key(packet_key);

    int bytes_written = netcode_write_packet(input_packet, buffer, sizeof(buffer), 1000, packet_key, TEST_PROTOCOL_ID);

    check(bytes_written > 0);

    // read the packet back in from the buffer

    uint64_t sequence;

    uint8_t allowed_packet_types[NETCODE_CONNECTION_NUM_PACKETS];
    memset(allowed_packet_types, 1, sizeof(allowed_packet_types));

    struct netcode_connection_payload_packet_t * output_packet = (struct netcode_connection_payload_packet_t*)
        netcode_read_packet(buffer, bytes_written, &sequence, packet_key, TEST_PROTOCOL_ID, time(null), null, allowed_packet_types, null, null, null);

    check(output_packet);

    // make sure the read packet matches what was written

    check(output_packet->packet_type == NETCODE_CONNECTION_PAYLOAD_PACKET);
    check(output_packet->payload_bytes == input_packet->payload_bytes);
    check(memcmp(output_packet->payload_data, input_packet->payload_data, NETCODE_MAX_PAYLOAD_BYTES) == 0);

    free(input_packet);
    free(output_packet);
}

void test_connection_disconnect_packet()
{
    // setup a connection disconnect packet

    struct netcode_connection_disconnect_packet_t input_packet;

    input_packet.packet_type = NETCODE_CONNECTION_DISCONNECT_PACKET;

    // write the packet to a buffer

    uint8_t buffer[NETCODE_MAX_PACKET_BYTES];

    uint8_t packet_key[NETCODE_KEY_BYTES];

    netcode_generate_key(packet_key);

    int bytes_written = netcode_write_packet(&input_packet, buffer, sizeof(buffer), 1000, packet_key, TEST_PROTOCOL_ID);

    check(bytes_written > 0);

    // read the packet back in from the buffer

    uint64_t sequence;

    uint8_t allowed_packet_types[NETCODE_CONNECTION_NUM_PACKETS];
    memset(allowed_packet_types, 1, sizeof(allowed_packet_types));

    struct netcode_connection_disconnect_packet_t * output_packet = (struct netcode_connection_disconnect_packet_t*)
        netcode_read_packet(buffer, bytes_written, &sequence, packet_key, TEST_PROTOCOL_ID, time(null), null, allowed_packet_types, null, null, null);

    check(output_packet);

    // make sure the read packet matches what was written

    check(output_packet->packet_type == NETCODE_CONNECTION_DISCONNECT_PACKET);

    free(output_packet);
}

void test_connect_token_public()
{
    // generate a private connect token

    struct netcode_address_t server_address;
    server_address.type = NETCODE_ADDRESS_IPV4;
    server_address.data.ipv4[0] = 127;
    server_address.data.ipv4[1] = 0;
    server_address.data.ipv4[2] = 0;
    server_address.data.ipv4[3] = 1;
    server_address.port = TEST_SERVER_PORT;

    uint8_t user_data[NETCODE_USER_DATA_BYTES];
    netcode_random_bytes(user_data, NETCODE_USER_DATA_BYTES);

    struct netcode_connect_token_private_t connect_token_private;

    netcode_generate_connect_token_private(&connect_token_private, TEST_CLIENT_ID, TEST_TIMEOUT_SECONDS, 1, &server_address, user_data);

    check(connect_token_private.client_id == TEST_CLIENT_ID);
    check(connect_token_private.num_server_addresses == 1);
    check(memcmp(connect_token_private.user_data, user_data, NETCODE_USER_DATA_BYTES) == 0);
    check(netcode_address_equal(&connect_token_private.server_addresses[0], &server_address));

    // write it to a buffer

    uint8_t connect_token_private_data[NETCODE_CONNECT_TOKEN_PRIVATE_BYTES];
    netcode_write_connect_token_private(&connect_token_private, connect_token_private_data, NETCODE_CONNECT_TOKEN_PRIVATE_BYTES);

    // encrypt the buffer

    uint64_t create_timestamp = time(null);
    uint64_t expire_timestamp = create_timestamp + 30;
    uint8_t connect_token_nonce[NETCODE_CONNECT_TOKEN_NONCE_BYTES];
    netcode_generate_nonce(connect_token_nonce);
    uint8_t key[NETCODE_KEY_BYTES];
    netcode_generate_key(key);
    check(netcode_encrypt_connect_token_private(connect_token_private_data,
                                                  NETCODE_CONNECT_TOKEN_PRIVATE_BYTES,
                                                  NETCODE_VERSION_INFO,
                                                  TEST_PROTOCOL_ID,
                                                  expire_timestamp,
                                                  connect_token_nonce,
                                                  key) == 1);

    // wrap a public connect token around the private connect token data

    struct netcode_connect_token_t input_connect_token;
    memset(&input_connect_token, 0, sizeof(struct netcode_connect_token_t));
    memcpy(input_connect_token.version_info, NETCODE_VERSION_INFO, NETCODE_VERSION_INFO_BYTES);
    input_connect_token.protocol_id = TEST_PROTOCOL_ID;
    input_connect_token.create_timestamp = create_timestamp;
    input_connect_token.expire_timestamp = expire_timestamp;
    memcpy(input_connect_token.nonce, connect_token_nonce, NETCODE_CONNECT_TOKEN_NONCE_BYTES);
    memcpy(input_connect_token.private_data, connect_token_private_data, NETCODE_CONNECT_TOKEN_PRIVATE_BYTES);
    input_connect_token.num_server_addresses = 1;
    input_connect_token.server_addresses[0] = server_address;
    memcpy(input_connect_token.client_to_server_key, connect_token_private.client_to_server_key, NETCODE_KEY_BYTES);
    memcpy(input_connect_token.server_to_client_key, connect_token_private.server_to_client_key, NETCODE_KEY_BYTES);
    input_connect_token.timeout_seconds = (int) TEST_TIMEOUT_SECONDS;

    // write the connect token to a buffer

    uint8_t buffer[NETCODE_CONNECT_TOKEN_BYTES];
    netcode_write_connect_token(&input_connect_token, buffer, NETCODE_CONNECT_TOKEN_BYTES);

    // read the buffer back in

    struct netcode_connect_token_t output_connect_token;
    memset(&output_connect_token, 0, sizeof(struct netcode_connect_token_t));
    check(netcode_read_connect_token(buffer, NETCODE_CONNECT_TOKEN_BYTES, &output_connect_token) == 1);

    // make sure the public connect token matches what was written

    check(memcmp(output_connect_token.version_info, input_connect_token.version_info, NETCODE_VERSION_INFO_BYTES) == 0);
    check(output_connect_token.protocol_id == input_connect_token.protocol_id);
    check(output_connect_token.create_timestamp == input_connect_token.create_timestamp);
    check(output_connect_token.expire_timestamp == input_connect_token.expire_timestamp);
    check(memcmp(output_connect_token.nonce, input_connect_token.nonce, NETCODE_CONNECT_TOKEN_NONCE_BYTES) == 0);
    check(memcmp(output_connect_token.private_data, input_connect_token.private_data, NETCODE_CONNECT_TOKEN_PRIVATE_BYTES) == 0);
    check(output_connect_token.num_server_addresses == input_connect_token.num_server_addresses);
    check(netcode_address_equal(&output_connect_token.server_addresses[0], &input_connect_token.server_addresses[0]));
    check(memcmp(output_connect_token.client_to_server_key, input_connect_token.client_to_server_key, NETCODE_KEY_BYTES) == 0);
    check(memcmp(output_connect_token.server_to_client_key, input_connect_token.server_to_client_key, NETCODE_KEY_BYTES) == 0);
    check(output_connect_token.timeout_seconds == input_connect_token.timeout_seconds);
}

void test_encryption_manager()
{
    struct netcode_encryption_manager_t encryption_manager;

    netcode_encryption_manager_reset(&encryption_manager);

    double time = 100.0;

    // generate some test encryption mappings

    struct encryption_mapping_t
    {
        struct netcode_address_t address;
        uint8_t send_key[NETCODE_KEY_BYTES];
        uint8_t receive_key[NETCODE_KEY_BYTES];
    };

    #define NUM_ENCRYPTION_MAPPINGS 5

    struct encryption_mapping_t encryption_mapping[NUM_ENCRYPTION_MAPPINGS];
    memset(encryption_mapping, 0, sizeof(encryption_mapping));
    int i;
    for (i = 0; i < NUM_ENCRYPTION_MAPPINGS; i++)
    {
        encryption_mapping[i].address.type = NETCODE_ADDRESS_IPV6;
        encryption_mapping[i].address.data.ipv6[7] = 1;
        encryption_mapping[i].address.port = (uint16_t) (20000 + i);
        netcode_generate_key(encryption_mapping[i].send_key);
        netcode_generate_key(encryption_mapping[i].receive_key);
    }

    // add the encryption mappings to the manager and make sure they can be looked up by address

    for (i = 0; i < NUM_ENCRYPTION_MAPPINGS; i++)
    {
        int encryption_index = netcode_encryption_manager_find_encryption_mapping(&encryption_manager, &encryption_mapping[i].address, time);

        check(encryption_index == -1);

        check(netcode_encryption_manager_get_send_key(&encryption_manager, encryption_index) == null);
        check(netcode_encryption_manager_get_receive_key(&encryption_manager, encryption_index) == null);

        check(netcode_encryption_manager_add_encryption_mapping(&encryption_manager,
                                                                  &encryption_mapping[i].address,
                                                                  encryption_mapping[i].send_key,
                                                                  encryption_mapping[i].receive_key,
                                                                  time,
                                                                  -1.0,
                                                                  TEST_TIMEOUT_SECONDS));

        encryption_index = netcode_encryption_manager_find_encryption_mapping(&encryption_manager, &encryption_mapping[i].address, time);

        uint8_t * send_key = netcode_encryption_manager_get_send_key(&encryption_manager, encryption_index);
        uint8_t * receive_key = netcode_encryption_manager_get_receive_key(&encryption_manager, encryption_index);

        check(send_key);
        check(receive_key);

        check(memcmp(send_key, encryption_mapping[i].send_key, NETCODE_KEY_BYTES) == 0);
        check(memcmp(receive_key, encryption_mapping[i].receive_key, NETCODE_KEY_BYTES) == 0);
    }

    // removing an encryption mapping that doesn't exist should return 0
    {
        struct netcode_address_t address;
        address.type = NETCODE_ADDRESS_IPV6;
        address.data.ipv6[7] = 1;
        address.port = 50000;

        check(netcode_encryption_manager_remove_encryption_mapping(&encryption_manager, &address, time) == 0);
    }

    // remove the first and last encryption mappings

    check(netcode_encryption_manager_remove_encryption_mapping(&encryption_manager, &encryption_mapping[0].address, time) == 1);

    check(netcode_encryption_manager_remove_encryption_mapping(&encryption_manager, &encryption_mapping[NUM_ENCRYPTION_MAPPINGS-1].address, time) == 1);

    // make sure the encryption mappings that were removed can no longer be looked up by address

    for (i = 0; i < NUM_ENCRYPTION_MAPPINGS; i++)
    {
        int encryption_index = netcode_encryption_manager_find_encryption_mapping(&encryption_manager, &encryption_mapping[i].address, time);

        uint8_t * send_key = netcode_encryption_manager_get_send_key(&encryption_manager, encryption_index);
        uint8_t * receive_key = netcode_encryption_manager_get_receive_key(&encryption_manager, encryption_index);

        if (i != 0 && i != NUM_ENCRYPTION_MAPPINGS - 1)
        {
            check(send_key);
            check(receive_key);

            check(memcmp(send_key, encryption_mapping[i].send_key, NETCODE_KEY_BYTES) == 0);
            check(memcmp(receive_key, encryption_mapping[i].receive_key, NETCODE_KEY_BYTES) == 0);
        }
        else
        {
            check(!send_key);
            check(!receive_key);
        }
    }

    // add the encryption mappings back in

    check(netcode_encryption_manager_add_encryption_mapping(&encryption_manager,
                                                              &encryption_mapping[0].address,
                                                              encryption_mapping[0].send_key,
                                                              encryption_mapping[0].receive_key,
                                                              time,
                                                              -1.0,
                                                              TEST_TIMEOUT_SECONDS));

    check(netcode_encryption_manager_add_encryption_mapping(&encryption_manager,
                                                              &encryption_mapping[NUM_ENCRYPTION_MAPPINGS-1].address,
                                                              encryption_mapping[NUM_ENCRYPTION_MAPPINGS-1].send_key,
                                                              encryption_mapping[NUM_ENCRYPTION_MAPPINGS-1].receive_key,
                                                              time,
                                                              -1.0,
                                                              TEST_TIMEOUT_SECONDS));

    // all encryption mappings should be able to be looked up by address again

    for (i = 0; i < NUM_ENCRYPTION_MAPPINGS; i++)
    {
        int encryption_index = netcode_encryption_manager_find_encryption_mapping(&encryption_manager, &encryption_mapping[i].address, time);

        uint8_t * send_key = netcode_encryption_manager_get_send_key(&encryption_manager, encryption_index);
        uint8_t * receive_key = netcode_encryption_manager_get_receive_key(&encryption_manager, encryption_index);

        check(send_key);
        check(receive_key);

        check(memcmp(send_key, encryption_mapping[i].send_key, NETCODE_KEY_BYTES) == 0);
        check(memcmp(receive_key, encryption_mapping[i].receive_key, NETCODE_KEY_BYTES) == 0);
    }

    // check that encryption mappings time out properly

    time += TEST_TIMEOUT_SECONDS * 2;

    for (i = 0; i < NUM_ENCRYPTION_MAPPINGS; i++)
    {
        int encryption_index = netcode_encryption_manager_find_encryption_mapping(&encryption_manager, &encryption_mapping[i].address, time);

        uint8_t * send_key = netcode_encryption_manager_get_send_key(&encryption_manager, encryption_index);
        uint8_t * receive_key = netcode_encryption_manager_get_receive_key(&encryption_manager, encryption_index);

        check(!send_key);
        check(!receive_key);
    }

    // add the same encryption mappings after timeout

    for (i = 0; i < NUM_ENCRYPTION_MAPPINGS; i++)
    {
        int encryption_index = netcode_encryption_manager_find_encryption_mapping(&encryption_manager, &encryption_mapping[i].address, time);

        check(encryption_index == -1);

        check(netcode_encryption_manager_get_send_key(&encryption_manager, encryption_index) == null);
        check(netcode_encryption_manager_get_receive_key(&encryption_manager, encryption_index) == null);

        check(netcode_encryption_manager_add_encryption_mapping(&encryption_manager,
                                                                  &encryption_mapping[i].address,
                                                                  encryption_mapping[i].send_key,
                                                                  encryption_mapping[i].receive_key,
                                                                  time,
                                                                  -1.0,
                                                                  TEST_TIMEOUT_SECONDS));

        encryption_index = netcode_encryption_manager_find_encryption_mapping(&encryption_manager, &encryption_mapping[i].address, time);

        uint8_t * send_key = netcode_encryption_manager_get_send_key(&encryption_manager, encryption_index);
        uint8_t * receive_key = netcode_encryption_manager_get_receive_key(&encryption_manager, encryption_index);

        check(send_key);
        check(receive_key);

        check(memcmp(send_key, encryption_mapping[i].send_key, NETCODE_KEY_BYTES) == 0);
        check(memcmp(receive_key, encryption_mapping[i].receive_key, NETCODE_KEY_BYTES) == 0);
    }

    // reset the encryption mapping and verify that all encryption mappings have been removed

    netcode_encryption_manager_reset(&encryption_manager);

    for (i = 0; i < NUM_ENCRYPTION_MAPPINGS; i++)
    {
        int encryption_index = netcode_encryption_manager_find_encryption_mapping(&encryption_manager, &encryption_mapping[i].address, time);

        uint8_t * send_key = netcode_encryption_manager_get_send_key(&encryption_manager, encryption_index);
        uint8_t * receive_key = netcode_encryption_manager_get_receive_key(&encryption_manager, encryption_index);

        check(!send_key);
        check(!receive_key);
    }

    // test the expire time for encryption mapping works as expected

    check(netcode_encryption_manager_add_encryption_mapping(&encryption_manager,
                                                              &encryption_mapping[0].address,
                                                              encryption_mapping[0].send_key,
                                                              encryption_mapping[0].receive_key,
                                                              time,
                                                              time + 1.0,
                                                              TEST_TIMEOUT_SECONDS));

    int encryption_index = netcode_encryption_manager_find_encryption_mapping(&encryption_manager, &encryption_mapping[0].address, time);

    check(encryption_index != -1);

    check(netcode_encryption_manager_find_encryption_mapping(&encryption_manager, &encryption_mapping[0].address, time + 1.1f) == -1);

    netcode_encryption_manager_set_expire_time(&encryption_manager, encryption_index, -1.0);

    check(netcode_encryption_manager_find_encryption_mapping(&encryption_manager, &encryption_mapping[0].address, time) == encryption_index);
}

void test_replay_protection()
{
    struct netcode_replay_protection_t replay_protection;

    int i;
    for (i = 0; i < 2; i++)
    {
        netcode_replay_protection_reset(&replay_protection);

        check(replay_protection.most_recent_sequence == 0);

        // the first time we receive packets, they should not be already received

        #define MAX_SEQUENCE (NETCODE_REPLAY_PROTECTION_BUFFER_SIZE * 4)

        uint64_t sequence;
        for (sequence = 0; sequence < MAX_SEQUENCE; ++sequence)
        {
            check(netcode_replay_protection_already_received(&replay_protection, sequence) == 0);
            netcode_replay_protection_advance_sequence(&replay_protection, sequence);
        }

        // old packets outside buffer should be considered already received

        check(netcode_replay_protection_already_received(&replay_protection, 0) == 1);

        // packets received a second time should be flagged already received

        for (sequence = MAX_SEQUENCE - 10; sequence < MAX_SEQUENCE; ++sequence)
        {
            check(netcode_replay_protection_already_received(&replay_protection, sequence) == 1);
        }

        // jumping ahead to a much higher sequence should be considered not already received

        check(netcode_replay_protection_already_received(&replay_protection, MAX_SEQUENCE + NETCODE_REPLAY_PROTECTION_BUFFER_SIZE) == 0);

        // old packets should be considered already received

        for (sequence = 0; sequence < MAX_SEQUENCE; ++sequence)
        {
            check(netcode_replay_protection_already_received(&replay_protection, sequence) == 1);
        }
    }
}

void test_client_create()
{
    {
        struct netcode_client_config_t client_config;
        netcode_default_client_config(&client_config);

        struct netcode_client_t * client = netcode_client_create("127.0.0.1:40000", &client_config, 0.0);

        struct netcode_address_t test_address;
        netcode_parse_address("127.0.0.1:40000", &test_address);

        check(client);
        check(client->socket_holder.ipv4.handle != 0);
        check(client->socket_holder.ipv6.handle == 0);
        check(netcode_address_equal(&client->address, &test_address));

        netcode_client_destroy(client);
    }

    {
        struct netcode_client_config_t client_config;
        netcode_default_client_config(&client_config);

        struct netcode_client_t * client = netcode_client_create("[::]:50000", &client_config, 0.0);

        struct netcode_address_t test_address;
        netcode_parse_address("[::]:50000", &test_address);

        check(client);
        check(client->socket_holder.ipv4.handle == 0);
        check(client->socket_holder.ipv6.handle != 0);
        check(netcode_address_equal(&client->address, &test_address));

        netcode_client_destroy(client);
    }

    {
        struct netcode_client_config_t client_config;
        netcode_default_client_config(&client_config);

        struct netcode_client_t * client = netcode_client_create_overload("127.0.0.1:40000", "[::]:50000", &client_config, 0.0);

        struct netcode_address_t test_address;
        netcode_parse_address("127.0.0.1:40000", &test_address);

        check(client);
        check(client->socket_holder.ipv4.handle != 0);
        check(client->socket_holder.ipv6.handle != 0);
        check(netcode_address_equal(&client->address, &test_address));

        netcode_client_destroy(client);
    }

    {
        struct netcode_client_config_t client_config;
        netcode_default_client_config(&client_config);

        struct netcode_client_t * client = netcode_client_create_overload("[::]:50000", "127.0.0.1:40000", &client_config, 0.0);

        struct netcode_address_t test_address;
        netcode_parse_address("[::]:50000", &test_address);

        check(client);
        check(client->socket_holder.ipv4.handle != 0);
        check(client->socket_holder.ipv6.handle != 0);
        check(netcode_address_equal(&client->address, &test_address));

        netcode_client_destroy(client);
    }
}

void test_server_create()
{
    {
        struct netcode_server_config_t server_config;
        netcode_default_server_config(&server_config);

        struct netcode_server_t * server = netcode_server_create("127.0.0.1:40000", &server_config, 0.0);

        struct netcode_address_t test_address;
        netcode_parse_address("127.0.0.1:40000", &test_address);

        check(server);
        check(server->socket_holder.ipv4.handle != 0);
        check(server->socket_holder.ipv6.handle == 0);
        check(netcode_address_equal(&server->address, &test_address));

        netcode_server_destroy(server);
    }

    {
        struct netcode_server_config_t server_config;
        netcode_default_server_config(&server_config);

        struct netcode_server_t * server = netcode_server_create("[::1]:50000", &server_config, 0.0);

        struct netcode_address_t test_address;
        netcode_parse_address("[::1]:50000", &test_address);

        check(server);
        check(server->socket_holder.ipv4.handle == 0);
        check(server->socket_holder.ipv6.handle != 0);
        check(netcode_address_equal(&server->address, &test_address));

        netcode_server_destroy(server);
    }

    {
        struct netcode_server_config_t server_config;
        netcode_default_server_config(&server_config);

        struct netcode_server_t * server = netcode_server_create_overload("127.0.0.1:40000", "[::1]:50000", &server_config, 0.0);

        struct netcode_address_t test_address;
        netcode_parse_address("127.0.0.1:40000", &test_address);

        check(server);
        check(server->socket_holder.ipv4.handle != 0);
        check(server->socket_holder.ipv6.handle != 0);
        check(netcode_address_equal(&server->address, &test_address));

        netcode_server_destroy(server);
    }

    {
        struct netcode_server_config_t server_config;
        netcode_default_server_config(&server_config);

        struct netcode_server_t * server = netcode_server_create_overload("[::1]:50000", "127.0.0.1:40000", &server_config, 0.0);

        struct netcode_address_t test_address;
        netcode_parse_address("[::1]:50000", &test_address);

        check(server);
        check(server->socket_holder.ipv4.handle != 0);
        check(server->socket_holder.ipv6.handle != 0);
        check(netcode_address_equal(&server->address, &test_address));

        netcode_server_destroy(server);
    }
}

static uint8_t private_key[NETCODE_KEY_BYTES] = { 0x60, 0x6a, 0xbe, 0x6e, 0xc9, 0x19, 0x10, 0xea,
                                                  0x9a, 0x65, 0x62, 0xf6, 0x6f, 0x2b, 0x30, 0xe4,
                                                  0x43, 0x71, 0xd6, 0x2c, 0xd1, 0x99, 0x27, 0x26,
                                                  0x6b, 0x3c, 0x60, 0xf4, 0xb7, 0x15, 0xab, 0xa1 };

void test_client_server_connect()
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

        time += delta_time;
    }

    check(client_num_packets_received >= 10 && server_num_packets_received >= 10);

    netcode_server_destroy(server);

    netcode_client_destroy(client);

    netcode_network_simulator_destroy(network_simulator);
}

void test_client_server_ipv4_socket_connect()
{
    {
        double time = 0.0;
        double delta_time = 1.0 / 10.0;

        struct netcode_client_config_t client_config;
        netcode_default_client_config(&client_config);

        struct netcode_client_t * client = netcode_client_create("0.0.0.0:50000", &client_config, time);

        check(client);

        struct netcode_server_config_t server_config;
        netcode_default_server_config(&server_config);
        server_config.protocol_id = TEST_PROTOCOL_ID;
        memcpy(&server_config.private_key, private_key, NETCODE_KEY_BYTES);

        struct netcode_server_t * server = netcode_server_create("127.0.0.1:40000", &server_config, time);

        check(server);

        netcode_server_start(server, 1);

        NETCODE_CONST char * server_address = "127.0.0.1:40000";

        uint8_t connect_token[NETCODE_CONNECT_TOKEN_BYTES];

        uint64_t client_id = 0;
        netcode_random_bytes((uint8_t*) &client_id, 8);

        uint8_t user_data[NETCODE_USER_DATA_BYTES];
        netcode_random_bytes(user_data, NETCODE_USER_DATA_BYTES);

        check(netcode_generate_connect_token(1, &server_address, &server_address, TEST_CONNECT_TOKEN_EXPIRY, TEST_TIMEOUT_SECONDS, client_id, TEST_PROTOCOL_ID, private_key, user_data, connect_token));

        netcode_client_connect(client, connect_token);

        while (1)
        {
            netcode_client_update(client, time);

            netcode_server_update(server, time);

            if (netcode_client_state(client) <= NETCODE_CLIENT_STATE_DISCONNECTED)
                break;

            if (netcode_client_state(client) == NETCODE_CLIENT_STATE_CONNECTED)
                break;

            time += delta_time;
        }

        netcode_server_destroy(server);

        netcode_client_destroy(client);
    }

    {
        double time = 0.0;
        double delta_time = 1.0 / 10.0;

        struct netcode_client_config_t client_config;
        netcode_default_client_config(&client_config);

        struct netcode_client_t * client = netcode_client_create("0.0.0.0:50000", &client_config, time);

        check(client);

        struct netcode_server_config_t server_config;
        netcode_default_server_config(&server_config);
        server_config.protocol_id = TEST_PROTOCOL_ID;
        memcpy(&server_config.private_key, private_key, NETCODE_KEY_BYTES);

        struct netcode_server_t * server = netcode_server_create_overload("127.0.0.1:40000", "[::1]:40000", &server_config, time);

        check(server);

        netcode_server_start(server, 1);

        NETCODE_CONST char * server_address = "127.0.0.1:40000";

        uint8_t connect_token[NETCODE_CONNECT_TOKEN_BYTES];

        uint64_t client_id = 0;
        netcode_random_bytes((uint8_t*) &client_id, 8);

        uint8_t user_data[NETCODE_USER_DATA_BYTES];
        netcode_random_bytes(user_data, NETCODE_USER_DATA_BYTES);

        check(netcode_generate_connect_token(1, &server_address, &server_address, TEST_CONNECT_TOKEN_EXPIRY, TEST_TIMEOUT_SECONDS, client_id, TEST_PROTOCOL_ID, private_key, user_data, connect_token));

        netcode_client_connect(client, connect_token);

        while (1)
        {
            netcode_client_update(client, time);

            netcode_server_update(server, time);

            if (netcode_client_state(client) <= NETCODE_CLIENT_STATE_DISCONNECTED)
                break;

            if (netcode_client_state(client) == NETCODE_CLIENT_STATE_CONNECTED)
                break;

            time += delta_time;
        }

        netcode_server_destroy(server);

        netcode_client_destroy(client);
    }

    {
        double time = 0.0;
        double delta_time = 1.0 / 10.0;

        struct netcode_client_config_t client_config;
        netcode_default_client_config(&client_config);

        struct netcode_client_t * client = netcode_client_create_overload("0.0.0.0:50000", "[::]:50000", &client_config, time);

        check(client);

        struct netcode_server_config_t server_config;
        netcode_default_server_config(&server_config);
        server_config.protocol_id = TEST_PROTOCOL_ID;
        memcpy(&server_config.private_key, private_key, NETCODE_KEY_BYTES);

        struct netcode_server_t * server = netcode_server_create("127.0.0.1:40000", &server_config, time);

        check(server);

        netcode_server_start(server, 1);

        NETCODE_CONST char * server_address = "127.0.0.1:40000";

        uint8_t connect_token[NETCODE_CONNECT_TOKEN_BYTES];

        uint64_t client_id = 0;
        netcode_random_bytes((uint8_t*) &client_id, 8);

        uint8_t user_data[NETCODE_USER_DATA_BYTES];
        netcode_random_bytes(user_data, NETCODE_USER_DATA_BYTES);

        check(netcode_generate_connect_token(1, &server_address, &server_address, TEST_CONNECT_TOKEN_EXPIRY, TEST_TIMEOUT_SECONDS, client_id, TEST_PROTOCOL_ID, private_key, user_data, connect_token));

        netcode_client_connect(client, connect_token);

        while (1)
        {
            netcode_client_update(client, time);

            netcode_server_update(server, time);

            if (netcode_client_state(client) <= NETCODE_CLIENT_STATE_DISCONNECTED)
                break;

            if (netcode_client_state(client) == NETCODE_CLIENT_STATE_CONNECTED)
                break;

            time += delta_time;
        }

        netcode_server_destroy(server);

        netcode_client_destroy(client);
    }

    {
        double time = 0.0;
        double delta_time = 1.0 / 10.0;

        struct netcode_client_config_t client_config;
        netcode_default_client_config(&client_config);

        struct netcode_client_t * client = netcode_client_create_overload("0.0.0.0:50000", "[::]:50000", &client_config, time);

        check(client);

        struct netcode_server_config_t server_config;
        netcode_default_server_config(&server_config);
        server_config.protocol_id = TEST_PROTOCOL_ID;
        memcpy(&server_config.private_key, private_key, NETCODE_KEY_BYTES);

        struct netcode_server_t * server = netcode_server_create_overload("127.0.0.1:40000", "[::1]:40000", &server_config, time);

        check(server);

        netcode_server_start(server, 1);

        NETCODE_CONST char * server_address = "127.0.0.1:40000";

        uint8_t connect_token[NETCODE_CONNECT_TOKEN_BYTES];

        uint64_t client_id = 0;
        netcode_random_bytes((uint8_t*) &client_id, 8);

        uint8_t user_data[NETCODE_USER_DATA_BYTES];
        netcode_random_bytes(user_data, NETCODE_USER_DATA_BYTES);

        check(netcode_generate_connect_token(1, &server_address, &server_address, TEST_CONNECT_TOKEN_EXPIRY, TEST_TIMEOUT_SECONDS, client_id, TEST_PROTOCOL_ID, private_key, user_data, connect_token));

        netcode_client_connect(client, connect_token);

        while (1)
        {
            netcode_client_update(client, time);

            netcode_server_update(server, time);

            if (netcode_client_state(client) <= NETCODE_CLIENT_STATE_DISCONNECTED)
                break;

            if (netcode_client_state(client) == NETCODE_CLIENT_STATE_CONNECTED)
                break;

            time += delta_time;
        }

        netcode_server_destroy(server);

        netcode_client_destroy(client);
    }
}

void test_client_server_ipv6_socket_connect()
{
    {
        double time = 0.0;
        double delta_time = 1.0 / 10.0;

        struct netcode_client_config_t client_config;
        netcode_default_client_config(&client_config);

        struct netcode_client_t * client = netcode_client_create("[::]:50000", &client_config, time);

        check(client);

        struct netcode_server_config_t server_config;
        netcode_default_server_config(&server_config);
        server_config.protocol_id = TEST_PROTOCOL_ID;
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
            netcode_client_update(client, time);

            netcode_server_update(server, time);

            if (netcode_client_state(client) <= NETCODE_CLIENT_STATE_DISCONNECTED)
                break;

            if (netcode_client_state(client) == NETCODE_CLIENT_STATE_CONNECTED)
                break;

            time += delta_time;
        }

        netcode_server_destroy(server);

        netcode_client_destroy(client);
    }

    {
        double time = 0.0;
        double delta_time = 1.0 / 10.0;

        struct netcode_client_config_t client_config;
        netcode_default_client_config(&client_config);

        struct netcode_client_t * client = netcode_client_create("[::]:50000", &client_config, time);

        check(client);

        struct netcode_server_config_t server_config;
        netcode_default_server_config(&server_config);
        server_config.protocol_id = TEST_PROTOCOL_ID;
        memcpy(&server_config.private_key, private_key, NETCODE_KEY_BYTES);

        struct netcode_server_t * server = netcode_server_create_overload("127.0.0.1:40000", "[::1]:40000", &server_config, time);

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
            netcode_client_update(client, time);

            netcode_server_update(server, time);

            if (netcode_client_state(client) <= NETCODE_CLIENT_STATE_DISCONNECTED)
                break;

            if (netcode_client_state(client) == NETCODE_CLIENT_STATE_CONNECTED)
                break;

            time += delta_time;
        }

        netcode_server_destroy(server);

        netcode_client_destroy(client);
    }

    {
        double time = 0.0;
        double delta_time = 1.0 / 10.0;

        struct netcode_client_config_t client_config;
        netcode_default_client_config(&client_config);

        struct netcode_client_t * client = netcode_client_create_overload("0.0.0.0:50000", "[::]:50000", &client_config, time);

        check(client);

        struct netcode_server_config_t server_config;
        netcode_default_server_config(&server_config);
        server_config.protocol_id = TEST_PROTOCOL_ID;
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
            netcode_client_update(client, time);

            netcode_server_update(server, time);

            if (netcode_client_state(client) <= NETCODE_CLIENT_STATE_DISCONNECTED)
                break;

            if (netcode_client_state(client) == NETCODE_CLIENT_STATE_CONNECTED)
                break;

            time += delta_time;
        }

        netcode_server_destroy(server);

        netcode_client_destroy(client);
    }

    {
        double time = 0.0;
        double delta_time = 1.0 / 10.0;

        struct netcode_client_config_t client_config;
        netcode_default_client_config(&client_config);

        struct netcode_client_t * client = netcode_client_create_overload("0.0.0.0:50000", "[::]:50000", &client_config, time);

        check(client);

        struct netcode_server_config_t server_config;
        netcode_default_server_config(&server_config);
        server_config.protocol_id = TEST_PROTOCOL_ID;
        memcpy(&server_config.private_key, private_key, NETCODE_KEY_BYTES);

        struct netcode_server_t * server = netcode_server_create_overload("127.0.0.1:40000", "[::1]:40000", &server_config, time);

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
            netcode_client_update(client, time);

            netcode_server_update(server, time);

            if (netcode_client_state(client) <= NETCODE_CLIENT_STATE_DISCONNECTED)
                break;

            if (netcode_client_state(client) == NETCODE_CLIENT_STATE_CONNECTED)
                break;

            time += delta_time;
        }

        netcode_server_destroy(server);

        netcode_client_destroy(client);
    }
}

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
