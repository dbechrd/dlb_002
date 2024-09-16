#scope_file

// Keep "check" for semantics of a test check vs. an assert, but actually just use assert for now.
check :: assert;

// NOTE(dlb): Timestamps get truncated to the nearest millisecond when being sent over the wire
current_time_ms :: () -> Apollo_Time {
    return milliseconds_to_apollo(to_milliseconds(current_time_monotonic()));
}

test_queue :: () {
    queue: netcode_packet_queue_t;

    check(queue.num_packets == 0);
    check(queue.start_index == 0);

    // attempting to pop a packet off an empty queue should return null

    check(netcode_packet_queue_pop(*queue) == null);

    // add some packets to the queue and make sure they pop off in the correct order
    {
        NUM_PACKETS :: 100;

        packets: [NUM_PACKETS] *netcode_connection_packet_t;

        for 0..NUM_PACKETS-1 {
            // NOTE(dlb): Huh? Why the weird malloc sizes?
            packets[it] = New(netcode_connection_packet_t);
            check(netcode_packet_queue_push(*queue, packets[it], cast(u64) it) == true);
        }

        check(queue.num_packets == NUM_PACKETS);

        for 0..NUM_PACKETS-1 {
            packet, sequence := netcode_packet_queue_pop(*queue);
            check(sequence == cast(u64) it) ;
            check(packet == packets[it]);
            free(packet);
        }
    }

    // after all entries are popped off, the queue is empty, so calls to pop should return null

    check(queue.num_packets == 0);

    check(netcode_packet_queue_pop(*queue) == null);

    // test that the packet queue can be filled to max capacity

    packets: [NETCODE_PACKET_QUEUE_SIZE] *netcode_connection_packet_t;

    for 0..NETCODE_PACKET_QUEUE_SIZE-1 {
        packets[it] = New(netcode_connection_packet_t);
        check(netcode_packet_queue_push(*queue, packets[it], cast(u64) it) == true);
    }

    check(queue.num_packets == NETCODE_PACKET_QUEUE_SIZE);

    // when the queue is full, attempting to push a packet should fail and return 0

    another_packet := New(netcode_connection_packet_t);
    check(netcode_packet_queue_push(*queue, another_packet, 0) == false);

    // make sure all packets pop off in the correct order

    for 0..NETCODE_PACKET_QUEUE_SIZE-1 {
        packet, sequence := netcode_packet_queue_pop(*queue);
        check(sequence == cast(u64) it);
        check(packet == packets[it]);
        free(packet);
    }

    // add some packets again

    for 0..NETCODE_PACKET_QUEUE_SIZE-1 {
        packets[it] = New(netcode_connection_packet_t);
        check(netcode_packet_queue_push(*queue, packets[it], cast(u64) it) == true);
    }

    // clear the queue and make sure that all packets are freed

    netcode_packet_queue_clear(*queue);

    check(queue.start_index == 0);
    check(queue.num_packets == 0);
    for 0..NETCODE_PACKET_QUEUE_SIZE-1 {
        check(queue.packet_data[it] == null);
    }
}

test_sequence :: () {
    check(netcode_sequence_number_bytes_required(0) == 1);
    check(netcode_sequence_number_bytes_required(0x11) == 1);
    check(netcode_sequence_number_bytes_required(0x1122) == 2);
    check(netcode_sequence_number_bytes_required(0x112233) == 3);
    check(netcode_sequence_number_bytes_required(0x11223344) == 4);
    check(netcode_sequence_number_bytes_required(0x1122334455) == 5);
    check(netcode_sequence_number_bytes_required(0x112233445566) == 6);
    check(netcode_sequence_number_bytes_required(0x11223344556677) == 7);
    check(netcode_sequence_number_bytes_required(0x1122334455667788) == 8);
}

test_address :: () {
    {
        address: netcode_address_t;
        check(netcode_parse_address("", *address) == NETCODE_ERROR);
        check(netcode_parse_address("[", *address) == NETCODE_ERROR);
        check(netcode_parse_address("[]", *address) == NETCODE_ERROR);
        check(netcode_parse_address("[]:", *address) == NETCODE_ERROR);
        check(netcode_parse_address(":", *address) == NETCODE_ERROR);
        check(netcode_parse_address("1", *address) == NETCODE_ERROR);
        check(netcode_parse_address("12", *address) == NETCODE_ERROR);
        check(netcode_parse_address("123", *address) == NETCODE_ERROR);
        check(netcode_parse_address("1234", *address) == NETCODE_ERROR);
        check(netcode_parse_address("1234.0.12313.0000", *address) == NETCODE_ERROR);
        check(netcode_parse_address("1234.0.12313.0000.0.0.0.0.0", *address) == NETCODE_ERROR);
        check(netcode_parse_address("1312313:123131:1312313:123131:1312313:123131:1312313:123131:1312313:123131:1312313:123131", *address) == NETCODE_ERROR);
        check(netcode_parse_address(".", *address) == NETCODE_ERROR);
        check(netcode_parse_address("..", *address) == NETCODE_ERROR);
        check(netcode_parse_address("...", *address) == NETCODE_ERROR);
        check(netcode_parse_address("....", *address) == NETCODE_ERROR);
        check(netcode_parse_address(".....", *address) == NETCODE_ERROR);
    }

    {
        address: netcode_address_t;
        check(netcode_parse_address("107.77.207.77", *address) == NETCODE_OK);
        check(address.type == NETCODE_ADDRESS_IPV4);
        check(address.port == 0);
        check(address.data.ipv4[0] == 107);
        check(address.data.ipv4[1] == 77);
        check(address.data.ipv4[2] == 207);
        check(address.data.ipv4[3] == 77);
    }

    {
        address: netcode_address_t;
        check(netcode_parse_address("127.0.0.1", *address) == NETCODE_OK);
        check(address.type == NETCODE_ADDRESS_IPV4);
        check(address.port == 0);
        check(address.data.ipv4[0] == 127);
        check(address.data.ipv4[1] == 0);
        check(address.data.ipv4[2] == 0);
        check(address.data.ipv4[3] == 1);
    }

    {
        address: netcode_address_t;
        check(netcode_parse_address("107.77.207.77:40000", *address) == NETCODE_OK);
        check(address.type == NETCODE_ADDRESS_IPV4);
        check(address.port == 40000);
        check(address.data.ipv4[0] == 107);
        check(address.data.ipv4[1] == 77);
        check(address.data.ipv4[2] == 207);
        check(address.data.ipv4[3] == 77);
    }

    {
        address: netcode_address_t;
        check(netcode_parse_address("127.0.0.1:40000", *address) == NETCODE_OK);
        check(address.type == NETCODE_ADDRESS_IPV4);
        check(address.port == 40000);
        check(address.data.ipv4[0] == 127);
        check(address.data.ipv4[1] == 0);
        check(address.data.ipv4[2] == 0);
        check(address.data.ipv4[3] == 1);
    }

    {
        address: netcode_address_t;
        check(netcode_parse_address("fe80::202:b3ff:fe1e:8329", *address) == NETCODE_OK);
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
        address: netcode_address_t;
        check(netcode_parse_address("::", *address) == NETCODE_OK);
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
        address: netcode_address_t;
        check(netcode_parse_address("::1", *address) == NETCODE_OK);
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
        address: netcode_address_t;
        check(netcode_parse_address("[fe80::202:b3ff:fe1e:8329]:40000", *address) == NETCODE_OK);
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
        address: netcode_address_t;
        check(netcode_parse_address("[::]:40000", *address) == NETCODE_OK);
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
        address: netcode_address_t;
        check(netcode_parse_address("[::1]:40000", *address) == NETCODE_OK);
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

TEST_PROTOCOL_ID          : u64 : 0x1122334455667788;
TEST_CLIENT_ID            : u64 : 0x1;
TEST_SERVER_PORT          :: 40000;
TEST_CONNECT_TOKEN_EXPIRY :: #run seconds_to_apollo(30);
TEST_TIMEOUT_SECONDS      :: #run seconds_to_apollo(15);

test_connect_token :: () {
    // generate a connect token

    server_address: netcode_address_t;
    server_address.type = NETCODE_ADDRESS_IPV4;
    server_address.data.ipv4[0] = 127;
    server_address.data.ipv4[1] = 0;
    server_address.data.ipv4[2] = 0;
    server_address.data.ipv4[3] = 1;
    server_address.port = TEST_SERVER_PORT;

    user_data: UserDataBuf;
    netcode_random_bytes(user_data);

    input_token: netcode_connect_token_private_t;

    netcode_generate_connect_token_private(*input_token, TEST_CLIENT_ID, TEST_TIMEOUT_SECONDS, .[ server_address ], user_data);

    check(input_token.client_id == TEST_CLIENT_ID);
    check(input_token.num_server_addresses == 1);
    check(array_equal(input_token.user_data, user_data) == true);
    check(netcode_address_equal(input_token.server_addresses[0], server_address));

    // write it to a buffer

    buffer: ConnectTokenPrivateDataBuf;
    netcode_write_connect_token_private(*input_token, buffer);

    // encrypt the buffer

    expire_timestamp := current_time_monotonic() + seconds_to_apollo(30);
    nonce: BigNonceBuf;
    netcode_generate_nonce(nonce);
    key: EncryptionKeyBuf;
    netcode_generate_key(key);

    check(netcode_encrypt_connect_token_private(buffer, NETCODE_VERSION_INFO, TEST_PROTOCOL_ID, expire_timestamp, nonce, key) == NETCODE_OK);

    // decrypt the buffer

    check(netcode_decrypt_connect_token_private(buffer, NETCODE_VERSION_INFO, TEST_PROTOCOL_ID, expire_timestamp, nonce, key) == NETCODE_OK);

    // read the connect token back in

    output_token: netcode_connect_token_private_t;

    check(netcode_read_connect_token_private(buffer, *output_token) == NETCODE_OK);

    // make sure that everything matches the original connect token

    check(output_token.client_id == input_token.client_id);
    check(output_token.timeout_seconds == input_token.timeout_seconds);
    check(output_token.num_server_addresses == input_token.num_server_addresses);
    check(netcode_address_equal(output_token.server_addresses[0], input_token.server_addresses[0]));
    check(array_equal(output_token.client_to_server_key, input_token.client_to_server_key) == true);
    check(array_equal(output_token.server_to_client_key, input_token.server_to_client_key) == true);
    check(array_equal(output_token.user_data, input_token.user_data) == true);
}

test_challenge_token :: () {
    // generate a challenge token

    input_token: netcode_challenge_token_t;

    input_token.client_id = TEST_CLIENT_ID;
    netcode_random_bytes(input_token.user_data);

    // write it to a buffer

    buffer: ChallengeTokenBuf;

    netcode_write_challenge_token(*input_token, buffer);

    // encrypt the buffer

    sequence: u64 = 1000;
    key: EncryptionKeyBuf;
    netcode_generate_key(key);

    check(netcode_encrypt_challenge_token(buffer, sequence, key) == NETCODE_OK);

    // decrypt the buffer

    check(netcode_decrypt_challenge_token(buffer, sequence, key) == NETCODE_OK);

    // read the challenge token back in

    output_token: netcode_challenge_token_t;

    check(netcode_read_challenge_token(buffer, *output_token) == NETCODE_OK);

    // make sure that everything matches the original challenge token

    check(output_token.client_id == input_token.client_id);
    check(array_equal(output_token.user_data, input_token.user_data) == true);
}

test_connection_request_packet :: () {
    // generate a connect token

    server_address: netcode_address_t;
    server_address.type = NETCODE_ADDRESS_IPV4;
    server_address.data.ipv4[0] = 127;
    server_address.data.ipv4[1] = 0;
    server_address.data.ipv4[2] = 0;
    server_address.data.ipv4[3] = 1;
    server_address.port = TEST_SERVER_PORT;

    user_data: UserDataBuf;
    netcode_random_bytes(user_data);

    input_token: netcode_connect_token_private_t;

    netcode_generate_connect_token_private(*input_token, TEST_CLIENT_ID, TEST_TIMEOUT_SECONDS, .[ server_address ], user_data);

    check(input_token.client_id == TEST_CLIENT_ID);
    check(input_token.num_server_addresses == 1);
    check(array_equal(input_token.user_data, user_data) == true);
    check(netcode_address_equal(input_token.server_addresses[0], server_address));

    // write the conect token to a buffer (non-encrypted)

    connect_token_data: ConnectTokenPrivateDataBuf;
    netcode_write_connect_token_private(*input_token, connect_token_data);

    // copy to a second buffer then encrypt it in place (we need the unencrypted token for verification later on)

    encrypted_connect_token_data: ConnectTokenPrivateDataBuf;
    array_copy(encrypted_connect_token_data, connect_token_data);

    connect_token_expire_timestamp := current_time_ms() + seconds_to_apollo(30);
    connect_token_nonce: BigNonceBuf;
    netcode_generate_nonce(connect_token_nonce);
    connect_token_key: EncryptionKeyBuf;
    netcode_generate_key(connect_token_key);

    check(netcode_encrypt_connect_token_private(encrypted_connect_token_data, NETCODE_VERSION_INFO, TEST_PROTOCOL_ID,
        connect_token_expire_timestamp, connect_token_nonce, connect_token_key) == NETCODE_OK);

    // setup a connection request packet wrapping the encrypted connect token

    input_packet: netcode_connection_request_packet_t;

    assert(input_packet.type == NETCODE_CONNECTION_REQUEST_PACKET);
    array_copy(input_packet.version_info, NETCODE_VERSION_INFO);
    input_packet.protocol_id = TEST_PROTOCOL_ID;
    input_packet.connect_token_expire_timestamp = connect_token_expire_timestamp;
    array_copy(input_packet.connect_token_nonce, connect_token_nonce);
    array_copy(input_packet.connect_token_data, encrypted_connect_token_data);

    // write the connection request packet to a buffer

    buffer: [2048] u8;
    packet_key: EncryptionKeyBuf;
    netcode_generate_key(packet_key);
    bytes_written := netcode_write_packet(*input_packet, buffer, 1000, packet_key, TEST_PROTOCOL_ID);

    check(bytes_written > 0);

    // read the connection request packet back in from the buffer (the connect token data is decrypted as part of the read packet validation)

    allowed_packet_types: AllowedPacketsBuf;
    array_fill_byte(allowed_packet_types, 1);

    output_packet, sequence := netcode_read_packet(.{ bytes_written, buffer.data }, packet_key, TEST_PROTOCOL_ID, current_time_monotonic(), *connect_token_key, allowed_packet_types, null);

    check(output_packet != null);

    // make sure the read packet matches what was written

    check(output_packet.type == NETCODE_CONNECTION_REQUEST_PACKET);
    p := cast(*netcode_connection_request_packet_t) output_packet;
    check(array_equal(p.version_info, input_packet.version_info) == true);
    check(p.protocol_id == input_packet.protocol_id);
    check(p.connect_token_expire_timestamp == input_packet.connect_token_expire_timestamp);
    check(array_equal(p.connect_token_nonce, input_packet.connect_token_nonce) == true);
    check(array_equal(p.connect_token_data, connect_token_data) == true);

    free(output_packet);
}

test_connection_denied_packet :: () {
    // setup a connection denied packet

    input_packet: netcode_connection_denied_packet_t;
    assert(input_packet.type == NETCODE_CONNECTION_DENIED_PACKET);

    // write the packet to a buffer

    buffer: [NETCODE_MAX_PACKET_BYTES] u8;

    packet_key: EncryptionKeyBuf;

    netcode_generate_key(packet_key);

    bytes_written := netcode_write_packet(*input_packet, buffer, 1000, packet_key, TEST_PROTOCOL_ID);

    check(bytes_written > 0);

    // read the packet back in from the buffer

    allowed_packet_types: AllowedPacketsBuf;
    array_fill_byte(allowed_packet_types, 1);

    output_packet, sequence := netcode_read_packet(.{ bytes_written, buffer.data }, packet_key, TEST_PROTOCOL_ID, current_time_monotonic(), null, allowed_packet_types, null);

    check(output_packet != null);

    // make sure the read packet matches what was written

    check(output_packet.type == NETCODE_CONNECTION_DENIED_PACKET);

    free(output_packet);
}

test_connection_challenge_packet :: () {
    // setup a connection challenge packet

    input_packet: netcode_connection_challenge_packet_t;
    assert(input_packet.type == NETCODE_CONNECTION_CHALLENGE_PACKET);
    input_packet.challenge_token_sequence = 0;
    netcode_random_bytes(input_packet.challenge_token_data);

    // write the packet to a buffer

    buffer: [NETCODE_MAX_PACKET_BYTES] u8;

    packet_key: EncryptionKeyBuf;

    netcode_generate_key(packet_key);

    bytes_written := netcode_write_packet(*input_packet, buffer, 1000, packet_key, TEST_PROTOCOL_ID);

    check(bytes_written > 0);

    // read the packet back in from the buffer

    allowed_packet_types: AllowedPacketsBuf;
    array_fill_byte(allowed_packet_types, 1);

    output_packet, sequence := netcode_read_packet(.{ bytes_written, buffer.data }, packet_key, TEST_PROTOCOL_ID, current_time_monotonic(), null, allowed_packet_types, null);

    check(output_packet != null);

    // make sure the read packet packet matches what was written

    check(output_packet.type == NETCODE_CONNECTION_CHALLENGE_PACKET);
    p := cast(*netcode_connection_challenge_packet_t) output_packet;
    check(p.challenge_token_sequence == input_packet.challenge_token_sequence);
    check(array_equal(p.challenge_token_data, input_packet.challenge_token_data) == true);

    free(output_packet);
}

test_connection_response_packet :: () {
    // setup a connection response packet

    input_packet: netcode_connection_response_packet_t;
    assert(input_packet.type == NETCODE_CONNECTION_RESPONSE_PACKET);
    input_packet.challenge_token_sequence = 0;
    netcode_random_bytes(input_packet.challenge_token_data);

    // write the packet to a buffer

    buffer: [NETCODE_MAX_PACKET_BYTES] u8;

    packet_key: EncryptionKeyBuf;
    netcode_generate_key(packet_key);

    bytes_written := netcode_write_packet(*input_packet, buffer, 1000, packet_key, TEST_PROTOCOL_ID);

    check(bytes_written > 0);

    // read the packet back in from the buffer

    allowed_packet_types: AllowedPacketsBuf;
    array_fill_byte(allowed_packet_types, 1);

    output_packet, sequence :=  netcode_read_packet(.{ bytes_written, buffer.data }, packet_key, TEST_PROTOCOL_ID, current_time_monotonic(), null, allowed_packet_types, null);

    check(output_packet != null);

    // make sure the read packet matches what was written

    check(output_packet.type == NETCODE_CONNECTION_RESPONSE_PACKET);
    p := cast(*netcode_connection_response_packet_t) output_packet;
    check(p.challenge_token_sequence == input_packet.challenge_token_sequence);
    check(array_equal(p.challenge_token_data, input_packet.challenge_token_data) == true);

    free(output_packet);
}

test_connection_keep_alive_packet :: () {
    // setup a connection keep alive packet

    input_packet: netcode_connection_keep_alive_packet_t;
    assert(input_packet.type == NETCODE_CONNECTION_KEEP_ALIVE_PACKET);
    input_packet.client_index = 10;
    input_packet.max_clients = 16;

    // write the packet to a buffer

    buffer: [NETCODE_MAX_PACKET_BYTES] u8;

    packet_key: EncryptionKeyBuf;
    netcode_generate_key(packet_key);

    bytes_written := netcode_write_packet(*input_packet, buffer, 1000, packet_key, TEST_PROTOCOL_ID);

    check(bytes_written > 0);

    // read the packet back in from the buffer

    allowed_packet_types: AllowedPacketsBuf;
    array_fill_byte(allowed_packet_types, 1);

    output_packet, sequence :=  netcode_read_packet(.{ bytes_written, buffer.data }, packet_key, TEST_PROTOCOL_ID, current_time_monotonic(), null, allowed_packet_types, null);

    check(output_packet != null);

    // make sure the read packet matches what was written

    check(output_packet.type == NETCODE_CONNECTION_KEEP_ALIVE_PACKET);
    p := cast(*netcode_connection_keep_alive_packet_t) output_packet;
    check(p.client_index == input_packet.client_index);
    check(p.max_clients == input_packet.max_clients);

    free(output_packet);
}

test_connection_payload_packet :: () {
    // setup a connection payload packet

    input_packet := netcode_create_payload_packet(NETCODE_MAX_PAYLOAD_BYTES);

    check(input_packet.type == NETCODE_CONNECTION_PAYLOAD_PACKET);
    check(input_packet.payload_data.count == NETCODE_MAX_PAYLOAD_BYTES);

    netcode_random_bytes(input_packet.payload_data);

    // write the packet to a buffer

    buffer: [NETCODE_MAX_PACKET_BYTES] u8;

    packet_key: EncryptionKeyBuf;
    netcode_generate_key(packet_key);

    bytes_written := netcode_write_packet(input_packet, buffer, 1000, packet_key, TEST_PROTOCOL_ID);

    check(bytes_written > 0);

    // read the packet back in from the buffer

    allowed_packet_types: AllowedPacketsBuf;
    array_fill_byte(allowed_packet_types, 1);

    output_packet, sequence :=  netcode_read_packet(.{ bytes_written, buffer.data }, packet_key, TEST_PROTOCOL_ID, current_time_monotonic(), null, allowed_packet_types, null);

    check(output_packet != null);

    // make sure the read packet matches what was written

    check(output_packet.type == NETCODE_CONNECTION_PAYLOAD_PACKET);
    p := cast(*netcode_connection_payload_packet_t) output_packet;
    check(p.payload_data.count == input_packet.payload_data.count);
    check(memcmp(p.payload_data.data, input_packet.payload_data.data, input_packet.payload_data.count) == 0);

    free(input_packet);
    free(output_packet);
}

test_connection_disconnect_packet :: () {
    // setup a connection disconnect packet

    input_packet: netcode_connection_disconnect_packet_t;
    assert(input_packet.type == NETCODE_CONNECTION_DISCONNECT_PACKET);

    // write the packet to a buffer

    buffer: [NETCODE_MAX_PACKET_BYTES] u8;

    packet_key: EncryptionKeyBuf;
    netcode_generate_key(packet_key);

    bytes_written := netcode_write_packet(*input_packet, buffer, 1000, packet_key, TEST_PROTOCOL_ID);

    check(bytes_written > 0);

    // read the packet back in from the buffer

    allowed_packet_types: AllowedPacketsBuf;
    array_fill_byte(allowed_packet_types, 1);

    output_packet, sequence := netcode_read_packet(.{ bytes_written, buffer.data }, packet_key, TEST_PROTOCOL_ID, current_time_monotonic(), null, allowed_packet_types, null);

    check(output_packet != null);

    // make sure the read packet matches what was written

    check(output_packet.type == NETCODE_CONNECTION_DISCONNECT_PACKET);

    free(output_packet);
}

test_connect_token_public :: () {
    // generate a private connect token

    server_address: netcode_address_t;
    server_address.type = NETCODE_ADDRESS_IPV4;
    server_address.data.ipv4[0] = 127;
    server_address.data.ipv4[1] = 0;
    server_address.data.ipv4[2] = 0;
    server_address.data.ipv4[3] = 1;
    server_address.port = TEST_SERVER_PORT;

    user_data: UserDataBuf;
    netcode_random_bytes(user_data);

    connect_token_private: netcode_connect_token_private_t;
    netcode_generate_connect_token_private(*connect_token_private, TEST_CLIENT_ID, TEST_TIMEOUT_SECONDS, .[ server_address ], user_data);

    check(connect_token_private.client_id == TEST_CLIENT_ID);
    check(connect_token_private.num_server_addresses == 1);
    check(array_equal(connect_token_private.user_data, user_data) == true);
    check(netcode_address_equal(connect_token_private.server_addresses[0], server_address));

    // write it to a buffer

    connect_token_private_data: ConnectTokenPrivateDataBuf;
    netcode_write_connect_token_private(*connect_token_private, connect_token_private_data);

    // encrypt the buffer

    // NOTE(dlb): Timestamps get truncated to the nearest millisecond when being sent over the wire
    create_timestamp := current_time_ms();
    expire_timestamp := create_timestamp + seconds_to_apollo(30);
    connect_token_nonce: BigNonceBuf;
    netcode_generate_nonce(connect_token_nonce);
    key: EncryptionKeyBuf;
    netcode_generate_key(key);
    check(netcode_encrypt_connect_token_private(connect_token_private_data, NETCODE_VERSION_INFO, TEST_PROTOCOL_ID,
        expire_timestamp, connect_token_nonce, key) == NETCODE_OK);

    // wrap a public connect token around the private connect token data

    input_connect_token: netcode_connect_token_t;
    array_copy(input_connect_token.version_info, NETCODE_VERSION_INFO);
    input_connect_token.protocol_id = TEST_PROTOCOL_ID;
    input_connect_token.create_timestamp = create_timestamp;
    input_connect_token.expire_timestamp = expire_timestamp;
    array_copy(input_connect_token.nonce, connect_token_nonce);
    array_copy(input_connect_token.private_data, connect_token_private_data);
    input_connect_token.num_server_addresses = 1;
    input_connect_token.server_addresses[0] = server_address;
    array_copy(input_connect_token.client_to_server_key, connect_token_private.client_to_server_key);
    array_copy(input_connect_token.server_to_client_key, connect_token_private.server_to_client_key);
    input_connect_token.timeout_seconds = TEST_TIMEOUT_SECONDS;

    // write the connect token to a buffer

    buffer: ConnectTokenBuf;
    netcode_write_connect_token(*input_connect_token, buffer);

    // read the buffer back in

    output_connect_token: netcode_connect_token_t;
    check(netcode_read_connect_token(buffer, *output_connect_token) == NETCODE_OK);

    // make sure the public connect token matches what was written

    check(array_equal(output_connect_token.version_info, input_connect_token.version_info) == true);
    check(output_connect_token.protocol_id == input_connect_token.protocol_id);
    check(output_connect_token.create_timestamp == input_connect_token.create_timestamp);
    check(output_connect_token.expire_timestamp == input_connect_token.expire_timestamp);
    check(array_equal(output_connect_token.nonce, input_connect_token.nonce) == true);
    check(array_equal(output_connect_token.private_data, input_connect_token.private_data) == true);
    check(output_connect_token.num_server_addresses == input_connect_token.num_server_addresses);
    check(netcode_address_equal(output_connect_token.server_addresses[0], input_connect_token.server_addresses[0]));
    check(array_equal(output_connect_token.client_to_server_key, input_connect_token.client_to_server_key) == true);
    check(array_equal(output_connect_token.server_to_client_key, input_connect_token.server_to_client_key) == true);
    check(output_connect_token.timeout_seconds == input_connect_token.timeout_seconds);
}

test_encryption_manager :: () {
    encryption_manager: netcode_encryption_manager_t;

    netcode_encryption_manager_reset(*encryption_manager);

    time := seconds_to_apollo(100);

    // generate some test encryption mappings

    encryption_mapping_t :: struct {
        address     : netcode_address_t;
        send_key    : EncryptionKeyBuf;
        receive_key : EncryptionKeyBuf;
    }

    NUM_ENCRYPTION_MAPPINGS :: 5;

    encryption_mapping: [NUM_ENCRYPTION_MAPPINGS] encryption_mapping_t;

    for * encryption_mapping {
        it.address.type = NETCODE_ADDRESS_IPV6;
        it.address.data.ipv6[7] = 1;
        it.address.port = cast(u16) (20000 + it_index);
        netcode_generate_key(it.send_key);
        netcode_generate_key(it.receive_key);
    }

    // add the encryption mappings to the manager and make sure they can be looked up by address

    for * encryption_mapping {
        encryption_index := netcode_encryption_manager_find_encryption_mapping(*encryption_manager, it.address, time);

        check(encryption_index == -1);

        check(netcode_encryption_manager_get_send_key(*encryption_manager, encryption_index) == null);
        check(netcode_encryption_manager_get_receive_key(*encryption_manager, encryption_index) == null);

        check(netcode_encryption_manager_add_encryption_mapping(*encryption_manager, it.address, it.send_key, it.receive_key, time, seconds_to_apollo(-1), TEST_TIMEOUT_SECONDS));

        encryption_index = netcode_encryption_manager_find_encryption_mapping(*encryption_manager, it.address, time);

        send_key := netcode_encryption_manager_get_send_key(*encryption_manager, encryption_index);
        receive_key := netcode_encryption_manager_get_receive_key(*encryption_manager, encryption_index);

        check(send_key != null);
        check(receive_key != null);

        check(array_equal(send_key.*, it.send_key) == true);
        check(array_equal(receive_key.*, it.receive_key) == true);
    }

    // removing an encryption mapping that doesn't exist should return 0
    {
        address: netcode_address_t;
        address.type = NETCODE_ADDRESS_IPV6;
        address.data.ipv6[7] = 1;
        address.port = 50000;

        check(netcode_encryption_manager_remove_encryption_mapping(*encryption_manager, address, time) == false);
    }

    // remove the first and last encryption mappings

    check(netcode_encryption_manager_remove_encryption_mapping(*encryption_manager, encryption_mapping[0].address, time) == true);

    check(netcode_encryption_manager_remove_encryption_mapping(*encryption_manager, encryption_mapping[NUM_ENCRYPTION_MAPPINGS-1].address, time) == true);

    // make sure the encryption mappings that were removed can no longer be looked up by address

    for * encryption_mapping {
        encryption_index := netcode_encryption_manager_find_encryption_mapping(*encryption_manager, it.address, time);

        send_key := netcode_encryption_manager_get_send_key(*encryption_manager, encryption_index);
        receive_key := netcode_encryption_manager_get_receive_key(*encryption_manager, encryption_index);

        if it_index > 0 && it_index < NUM_ENCRYPTION_MAPPINGS - 1 {
            check(send_key != null);
            check(receive_key != null);

            check(array_equal(send_key.*, it.send_key) == true);
            check(array_equal(receive_key.*, it.receive_key) == true);
        } else {
            check(send_key == null);
            check(receive_key == null);
        }
    }

    // add the encryption mappings back in

    check(netcode_encryption_manager_add_encryption_mapping(
        *encryption_manager,
        encryption_mapping[0].address,
        encryption_mapping[0].send_key,
        encryption_mapping[0].receive_key,
        time,
        seconds_to_apollo(-1),
        TEST_TIMEOUT_SECONDS) == true
    );

    check(netcode_encryption_manager_add_encryption_mapping(
        *encryption_manager,
        encryption_mapping[NUM_ENCRYPTION_MAPPINGS-1].address,
        encryption_mapping[NUM_ENCRYPTION_MAPPINGS-1].send_key,
        encryption_mapping[NUM_ENCRYPTION_MAPPINGS-1].receive_key,
        time,
        seconds_to_apollo(-1),
        TEST_TIMEOUT_SECONDS) == true
    );

    // all encryption mappings should be able to be looked up by address again

    for * encryption_mapping {
        encryption_index := netcode_encryption_manager_find_encryption_mapping(*encryption_manager, it.address, time);

        send_key := netcode_encryption_manager_get_send_key(*encryption_manager, encryption_index);
        receive_key := netcode_encryption_manager_get_receive_key(*encryption_manager, encryption_index);

        check(send_key != null);
        check(receive_key != null);

        check(array_equal(send_key.*, it.send_key) == true);
        check(array_equal(receive_key.*, it.receive_key) == true);
    }

    // check that encryption mappings time out properly

    time += TEST_TIMEOUT_SECONDS * 2;

    for * encryption_mapping {
        encryption_index := netcode_encryption_manager_find_encryption_mapping(*encryption_manager, it.address, time);

        send_key := netcode_encryption_manager_get_send_key(*encryption_manager, encryption_index);
        receive_key := netcode_encryption_manager_get_receive_key(*encryption_manager, encryption_index);

        check(send_key == null);
        check(receive_key == null);
    }

    // add the same encryption mappings after timeout

    for * encryption_mapping {
        encryption_index := netcode_encryption_manager_find_encryption_mapping(*encryption_manager, it.address, time);

        check(encryption_index == -1);

        check(netcode_encryption_manager_get_send_key(*encryption_manager, encryption_index) == null);
        check(netcode_encryption_manager_get_receive_key(*encryption_manager, encryption_index) == null);

        check(netcode_encryption_manager_add_encryption_mapping(
            *encryption_manager,
            it.address,
            it.send_key,
            it.receive_key,
            time,
            seconds_to_apollo(-1),
            TEST_TIMEOUT_SECONDS) == true
        );

        encryption_index = netcode_encryption_manager_find_encryption_mapping(*encryption_manager, it.address, time);

        send_key := netcode_encryption_manager_get_send_key(*encryption_manager, encryption_index);
        receive_key := netcode_encryption_manager_get_receive_key(*encryption_manager, encryption_index);

        check(send_key != null);
        check(receive_key != null);

        check(array_equal(send_key.*, it.send_key) == true);
        check(array_equal(receive_key.*, it.receive_key) == true);
    }

    // reset the encryption mapping and verify that all encryption mappings have been removed

    netcode_encryption_manager_reset(*encryption_manager);

    for * encryption_mapping {
        encryption_index := netcode_encryption_manager_find_encryption_mapping(*encryption_manager, it.address, time);

        send_key := netcode_encryption_manager_get_send_key(*encryption_manager, encryption_index);
        receive_key := netcode_encryption_manager_get_receive_key(*encryption_manager, encryption_index);

        check(send_key == null);
        check(receive_key == null);
    }

    // test the expire time for encryption mapping works as expected

    check(netcode_encryption_manager_add_encryption_mapping(
        *encryption_manager,
        encryption_mapping[0].address,
        encryption_mapping[0].send_key,
        encryption_mapping[0].receive_key,
        time,
        time + seconds_to_apollo(1),
        TEST_TIMEOUT_SECONDS)
    );

    encryption_index := netcode_encryption_manager_find_encryption_mapping(*encryption_manager, encryption_mapping[0].address, time);

    check(encryption_index != -1);

    check(netcode_encryption_manager_find_encryption_mapping(*encryption_manager, encryption_mapping[0].address, time + milliseconds_to_apollo(1100)) == -1);

    netcode_encryption_manager_set_expire_time(*encryption_manager, encryption_index, seconds_to_apollo(-1));

    check(netcode_encryption_manager_find_encryption_mapping(*encryption_manager, encryption_mapping[0].address, time) == encryption_index);
}

test_replay_protection :: () {
    replay_protection: netcode_replay_protection_t;

    for 0..1 {
        netcode_replay_protection_reset(*replay_protection);

        check(replay_protection.most_recent_sequence == 0);

        // the first time we receive packets, they should not be already received

        MAX_SEQUENCE :: NETCODE_REPLAY_PROTECTION_BUFFER_SIZE * 4;

        for 0..MAX_SEQUENCE-1 {
            sequence := cast(u64) it;
            check(netcode_replay_protection_already_received(*replay_protection, sequence) == false);
            netcode_replay_protection_advance_sequence(*replay_protection, sequence);
        }

        // old packets outside buffer should be considered already received

        check(netcode_replay_protection_already_received(*replay_protection, 0) == true);

        // packets received a second time should be flagged already received

        for MAX_SEQUENCE-10..MAX_SEQUENCE-1 {
            sequence := cast(u64) it;
            check(netcode_replay_protection_already_received(*replay_protection, sequence) == true);
        }

        // jumping ahead to a much higher sequence should be considered not already received

        check(netcode_replay_protection_already_received(*replay_protection, MAX_SEQUENCE + NETCODE_REPLAY_PROTECTION_BUFFER_SIZE) == false);

        // old packets should be considered already received

        for 0..MAX_SEQUENCE-1 {
            sequence := cast(u64) it;
            check(netcode_replay_protection_already_received(*replay_protection, sequence) == true);
        }
    }
}

// This seems cool in theory, but is the complexity actually worth the aesthetic? Meh.
RUN_TEST :: (test: $T, $call := #caller_code, loc := #caller_location) {
    assert(type_info(T).info.type == .PROCEDURE);

    arg0_name :: #run -> string {
        Compiler :: #import "Compiler";
        root := Compiler.compiler_get_nodes(call);
        assert(root.kind == .PROCEDURE_CALL);
        run_test_call := cast(*Compiler.Code_Procedure_Call) root;
        arg0 := cast(*Compiler.Code_Ident) run_test_call.arguments_sorted[0];
        return arg0.name;
    };

    log("[Test] %\n", arg0_name);
    test();
}

#scope_export

netcode_test :: () {
    address_tests_running = true;
    defer address_tests_running = false;

    log("--------------------------------------------------------------------------------\n");
    log("[Netcode] Running tests...\n");
    RUN_TEST(test_queue);
    RUN_TEST(test_sequence);
    RUN_TEST(test_address);
    RUN_TEST(test_connect_token);
    RUN_TEST(test_challenge_token);
    RUN_TEST(test_connection_request_packet);
    RUN_TEST(test_connection_denied_packet);
    RUN_TEST(test_connection_challenge_packet);
    RUN_TEST(test_connection_response_packet);
    RUN_TEST(test_connection_keep_alive_packet);
    RUN_TEST(test_connection_payload_packet);
    RUN_TEST(test_connection_disconnect_packet);
    RUN_TEST(test_connect_token_public);
    RUN_TEST(test_encryption_manager);
    RUN_TEST(test_replay_protection);
    // RUN_TEST(test_client_create);
    // RUN_TEST(test_server_create);
    // RUN_TEST(test_client_server_connect);
    // RUN_TEST(test_client_server_ipv4_socket_connect);
    // RUN_TEST(test_client_server_ipv6_socket_connect);
    // RUN_TEST(test_client_server_keep_alive);
    // RUN_TEST(test_client_server_multiple_clients);
    // RUN_TEST(test_client_server_multiple_servers);
    // RUN_TEST(test_client_error_connect_token_expired);
    // RUN_TEST(test_client_error_invalid_connect_token);
    // RUN_TEST(test_client_error_connection_timed_out);
    // RUN_TEST(test_client_error_connection_response_timeout);
    // RUN_TEST(test_client_error_connection_request_timeout);
    // RUN_TEST(test_client_error_connection_denied);
    // RUN_TEST(test_client_side_disconnect);
    // RUN_TEST(test_server_side_disconnect);
    // RUN_TEST(test_client_reconnect);
    // RUN_TEST(test_disable_timeout);
    // RUN_TEST(test_loopback);
    // RUN_TEST(test_address_map);
    log("Passed!\n");
    log("--------------------------------------------------------------------------------\n");
}
