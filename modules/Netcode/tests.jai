#scope_file

// Keep "check" for semantics of a test check vs. a test assert, but actually just use assert for now.
check :: assert;

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
    log("--------------------------------------------------------------------------------\n");
    log("[Netcode] Running tests...\n");
    RUN_TEST(test_queue);
    RUN_TEST(test_sequence);
    // RUN_TEST(test_address);
    // RUN_TEST(test_connect_token);
    // RUN_TEST(test_challenge_token);
    // RUN_TEST(test_connection_request_packet);
    // RUN_TEST(test_connection_denied_packet);
    // RUN_TEST(test_connection_challenge_packet);
    // RUN_TEST(test_connection_response_packet);
    // RUN_TEST(test_connection_payload_packet);
    // RUN_TEST(test_connection_disconnect_packet);
    // RUN_TEST(test_connect_token_public);
    // RUN_TEST(test_encryption_manager);
    // RUN_TEST(test_replay_protection);
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
