ENABLE_LOGGING :: true;
SOAK :: 0;

// TODO(dlb)[cleanup]: Use Assertive asserts.
check :: assert;

main :: () {
    random_seed(cast,no_check(u64) to_milliseconds(current_time_consensus()));

    iters := 0;
    while iters < 1 {
        #if !SOAK {
            iters += 1;
        }

        yojimbo_test();
    }
}

yojimbo_test :: () {
    serialize_test();
    netcode_test();
    reliable_test();

    log("\n--- Yojimbo --------------------------------------------------------------------\n");
    log("Running tests...\n");

    TEST(test_queue);
    TEST(test_address);
    TEST(test_bit_array);
    // TEST(test_sequence_buffer);
    // TEST(test_allocator_tlsf);

    // TEST(test_connection_reliable_ordered_messages);
    // TEST(test_connection_reliable_ordered_blocks);
    // TEST(test_connection_reliable_ordered_messages_and_blocks);
    // TEST(test_connection_reliable_ordered_messages_and_blocks_multiple_channels);
    // TEST(test_connection_unreliable_unordered_messages);
    // TEST(test_connection_unreliable_unordered_blocks);

    // TEST(test_client_server_messages);
    // TEST(test_client_server_start_stop_restart);
    // TEST(test_client_server_message_failed_to_serialize_reliable_ordered);
    // TEST(test_client_server_message_failed_to_serialize_unreliable_unordered);
    // TEST(test_client_server_message_exhaust_stream_allocator);
    // TEST(test_client_server_message_receive_queue_overflow);

    // TEST(test_single_message_type_reliable);
    // TEST(test_single_message_type_reliable_blocks);
    // TEST(test_single_message_type_unreliable);

    // TEST(test_client_server_messages_network_sim_leak);

    log("Passed!\n");
    reset_temporary_storage();
}

#load "yojimbo_test_shared.jai";

#import "Bit_Array";
#import "Assertive";
#import "Reliable";

TEST :: (test: (), call := #caller_code) #expand {
    if !yojimbo_init() {
        log("error: failed to initialize yojimbo\n");
        exit(1);
    }
    assert_test(test, ENABLE_LOGGING, call);
    yojimbo_shutdown();
}

test_queue :: () {
    QueueSize :: 1024;

    queue: Queue(int);
    queue_init(*queue, QueueSize);

    assert_equal(queue_empty(queue), true);
    assert_equal(queue_full(queue), false);
    assert_equal(queue.count, 0);
    assert_equal(queue.entries.count, QueueSize);

    NumEntries :: 100;

    for 0..NumEntries-1 {
        queue_push(*queue, it);
    }

    assert_equal(queue_empty(queue), false);
    assert_equal(queue_full(queue), false);
    assert_equal(queue.count, NumEntries);
    assert_equal(queue.entries.count, QueueSize);

    for 0..NumEntries-1 {
        assert_equal(queue[it], it);
    }

    for 0..NumEntries-1 {
        assert_equal(queue_pop(*queue), it);
    }

    assert_equal(queue_empty(queue), true);
    assert_equal(queue_full(queue), false);
    assert_equal(queue.count, 0);
    assert_equal(queue.entries.count, QueueSize);

    for 0..QueueSize-1 {
        queue_push(*queue, it);
    }

    assert_equal(queue_empty(queue), false);
    assert_equal(queue_full(queue), true);
    assert_equal(queue.count, QueueSize);
    assert_equal(queue.entries.count, QueueSize);

    queue_clear(*queue);

    assert_equal(queue_empty(queue), true);
    assert_equal(queue_full(queue), false);
    assert_equal(queue.count, 0);
    assert_equal(queue.entries.count, QueueSize);
}

test_address :: () {
    assert_equal(address_init_auto_detect("").type, IPType.None);
    assert_equal(address_init_auto_detect("[").type, IPType.None);
    assert_equal(address_init_auto_detect("[]").type, IPType.None);
    assert_equal(address_init_auto_detect("[]:").type, IPType.None);
    assert_equal(address_init_auto_detect(":").type, IPType.None);
    assert_equal(address_init_auto_detect("1").type, IPType.None);
    assert_equal(address_init_auto_detect("12").type, IPType.None);
    assert_equal(address_init_auto_detect("123").type, IPType.None);
    assert_equal(address_init_auto_detect("1234").type, IPType.None);
    assert_equal(address_init_auto_detect("1234.0.12313.0000").type, IPType.None);
    assert_equal(address_init_auto_detect("1234.0.12313.0000.0.0.0.0.0").type, IPType.None);
    assert_equal(address_init_auto_detect("1312313:123131:1312313:123131:1312313:123131:1312313:123131:1312313:123131:1312313:123131").type, IPType.None);
    assert_equal(address_init_auto_detect(".").type, IPType.None);
    assert_equal(address_init_auto_detect("..").type, IPType.None);
    assert_equal(address_init_auto_detect("...").type, IPType.None);
    assert_equal(address_init_auto_detect("....").type, IPType.None);
    assert_equal(address_init_auto_detect(".....").type, IPType.None);

    {
        address := address_init_auto_detect("107.77.207.77");
        assert_equal(address.type, IPType.IPv4);
        assert_equal(address.port, 0);
        assert_equal(address.data.v4[0], 107);
        assert_equal(address.data.v4[1], 77);
        assert_equal(address.data.v4[2], 207);
        assert_equal(address.data.v4[3], 77);
        check(!address_is_loopback(address));
    }

    {
        address := address_init_auto_detect("127.0.0.1");
        assert_equal(address.type, IPType.IPv4);
        assert_equal(address.port, 0);
        assert_equal(address.data.v4[0], 127);
        assert_equal(address.data.v4[1], 0);
        assert_equal(address.data.v4[2], 0);
        assert_equal(address.data.v4[3], 1);
        check(address_is_loopback(address));
    }

    {
        address := address_init_auto_detect("107.77.207.77:40000");
        assert_equal(address.type, IPType.IPv4);
        assert_equal(address.port, 40000);
        assert_equal(address.data.v4[0], 107);
        assert_equal(address.data.v4[1], 77);
        assert_equal(address.data.v4[2], 207);
        assert_equal(address.data.v4[3], 77);
        check(!address_is_loopback(address));
    }

    {
        address := address_init_auto_detect("127.0.0.1:40000");
        assert_equal(address.type, IPType.IPv4);
        assert_equal(address.port, 40000);
        assert_equal(address.data.v4[0], 127);
        assert_equal(address.data.v4[1], 0);
        assert_equal(address.data.v4[2], 0);
        assert_equal(address.data.v4[3], 1);
        check(address_is_loopback(address));
    }

    {
        address := address_init_auto_detect("fe80::202:b3ff:fe1e:8329");
        assert_equal(address.type, IPType.IPv6);
        assert_equal(address.port, 0);
        assert_equal(address.data.v6[0], 0xfe80);
        assert_equal(address.data.v6[1], 0x0000);
        assert_equal(address.data.v6[2], 0x0000);
        assert_equal(address.data.v6[3], 0x0000);
        assert_equal(address.data.v6[4], 0x0202);
        assert_equal(address.data.v6[5], 0xb3ff);
        assert_equal(address.data.v6[6], 0xfe1e);
        assert_equal(address.data.v6[7], 0x8329);
        check(!address_is_loopback(address));
    }

    {
        address := address_init_auto_detect("::");
        assert_equal(address.type, IPType.IPv6);
        assert_equal(address.port, 0);
        assert_equal(address.data.v6[0], 0x0000);
        assert_equal(address.data.v6[1], 0x0000);
        assert_equal(address.data.v6[2], 0x0000);
        assert_equal(address.data.v6[3], 0x0000);
        assert_equal(address.data.v6[4], 0x0000);
        assert_equal(address.data.v6[5], 0x0000);
        assert_equal(address.data.v6[6], 0x0000);
        assert_equal(address.data.v6[7], 0x0000);
        check(!address_is_loopback(address));
    }

    {
        address := address_init_auto_detect("::1");
        assert_equal(address.type, IPType.IPv6);
        assert_equal(address.port, 0);
        assert_equal(address.data.v6[0], 0x0000);
        assert_equal(address.data.v6[1], 0x0000);
        assert_equal(address.data.v6[2], 0x0000);
        assert_equal(address.data.v6[3], 0x0000);
        assert_equal(address.data.v6[4], 0x0000);
        assert_equal(address.data.v6[5], 0x0000);
        assert_equal(address.data.v6[6], 0x0000);
        assert_equal(address.data.v6[7], 0x0001);
        check(address_is_loopback(address));
    }

    {
        address := address_init_auto_detect("[fe80::202:b3ff:fe1e:8329]:40000");
        assert_equal(address.type, IPType.IPv6);
        assert_equal(address.port, 40000);
        assert_equal(address.data.v6[0], 0xfe80);
        assert_equal(address.data.v6[1], 0x0000);
        assert_equal(address.data.v6[2], 0x0000);
        assert_equal(address.data.v6[3], 0x0000);
        assert_equal(address.data.v6[4], 0x0202);
        assert_equal(address.data.v6[5], 0xb3ff);
        assert_equal(address.data.v6[6], 0xfe1e);
        assert_equal(address.data.v6[7], 0x8329);
        check(!address_is_loopback(address));
    }

    {
        address := address_init_auto_detect("[::]:40000");
        assert_equal(address.type, IPType.IPv6);
        assert_equal(address.port, 40000);
        assert_equal(address.data.v6[0], 0x0000);
        assert_equal(address.data.v6[1], 0x0000);
        assert_equal(address.data.v6[2], 0x0000);
        assert_equal(address.data.v6[3], 0x0000);
        assert_equal(address.data.v6[4], 0x0000);
        assert_equal(address.data.v6[5], 0x0000);
        assert_equal(address.data.v6[6], 0x0000);
        assert_equal(address.data.v6[7], 0x0000);
        check(!address_is_loopback(address));
    }

    {
        address := address_init_auto_detect("[::1]:40000");
        assert_equal(address.type, IPType.IPv6);
        assert_equal(address.port, 40000);
        assert_equal(address.data.v6[0], 0x0000);
        assert_equal(address.data.v6[1], 0x0000);
        assert_equal(address.data.v6[2], 0x0000);
        assert_equal(address.data.v6[3], 0x0000);
        assert_equal(address.data.v6[4], 0x0000);
        assert_equal(address.data.v6[5], 0x0000);
        assert_equal(address.data.v6[6], 0x0000);
        assert_equal(address.data.v6[7], 0x0001);
        check(address_is_loopback(address));
    }

    {
        address6: [8] u16 = .[0xFE80, 0x0000, 0x0000, 0x0000, 0x0202, 0xB3FF, 0xFE1E, 0x8329];

        address := address_init_v6(address6[0], address6[1], address6[2], address6[2],
                         address6[4], address6[5], address6[6], address6[7]);

        assert_equal(address.type, IPType.IPv6);
        assert_equal(address.port, 0);

        for address.data.v6
            assert_equal(it, address6[it_index]);

        assert_equal(address_to_string(address,, temp), "fe80:0:0:0:202:b3ff:fe1e:8329");
    }

    {
        address6: [8] u16 = .[0xFE80, 0x0000, 0x0000, 0x0000, 0x0202, 0xB3FF, 0xFE1E, 0x8329];

        address := address_init_v6(address6);

        assert_equal(address.type, IPType.IPv6);
        assert_equal(address.port, 0);

        for address.data.v6
            assert_equal(it, address6[it_index]);

        assert_equal(address_to_string(address,, temp), "fe80:0:0:0:202:b3ff:fe1e:8329");
    }

    {
        address6: [8] u16 = .[0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0001];

        address := address_init_v6(address6);

        assert_equal(address.type, IPType.IPv6);
        assert_equal(address.port, 0);

        for address.data.v6
            assert_equal(it, address6[it_index]);

        assert_equal(address_to_string(address,, temp), "0:0:0:0:0:0:0:1");
    }

    {
        address6: [8] u16 = .[0xFE80, 0x0000, 0x0000, 0x0000, 0x0202, 0xB3FF, 0xFE1E, 0x8329];

        address := address_init_v6(address6[0], address6[1], address6[2], address6[2],
                         address6[4], address6[5], address6[6], address6[7], 65535);

        assert_equal(address.type, IPType.IPv6);
        assert_equal(address.port, 65535);

        for address.data.v6
            assert_equal(it, address6[it_index]);

        assert_equal(address_to_string(address,, temp), "[fe80:0:0:0:202:b3ff:fe1e:8329]:65535");
    }

    {
        address6: [8] u16 = .[0xFE80, 0x0000, 0x0000, 0x0000, 0x0202, 0xB3FF, 0xFE1E, 0x8329];

        address := address_init_v6(address6, 65535);

        assert_equal(address.type, IPType.IPv6);
        assert_equal(address.port, 65535);

        for address.data.v6
            assert_equal(it, address6[it_index]);

        assert_equal(address_to_string(address,, temp), "[fe80:0:0:0:202:b3ff:fe1e:8329]:65535");
    }

    {
        address6: [8] u16 = .[0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0001];

        address := address_init_v6(address6, 65535);

        assert_equal(address.type, IPType.IPv6);
        assert_equal(address.port, 65535);

        for address.data.v6
            assert_equal(it, address6[it_index]);

        assert_equal(address_to_string(address,, temp), "[0:0:0:0:0:0:0:1]:65535");
    }

    {
        address := address_init_auto_detect("fe80::202:b3ff:fe1e:8329");
        assert_equal(address.type, IPType.IPv6);
        assert_equal(address.port, 0);
        assert_equal(address_to_string(address,, temp), "fe80:0:0:0:202:b3ff:fe1e:8329");
    }

    {
        address := address_init_auto_detect("::1");
        assert_equal(address.type, IPType.IPv6);
        assert_equal(address.port, 0);
        assert_equal(address_to_string(address,, temp), "0:0:0:0:0:0:0:1");
    }

    {
        address := address_init_auto_detect("[fe80::202:b3ff:fe1e:8329]:65535");
        assert_equal(address.type, IPType.IPv6);
        assert_equal(address.port, 65535);
        assert_equal(address_to_string(address,, temp), "[fe80:0:0:0:202:b3ff:fe1e:8329]:65535");
    }

    {
        address := address_init_auto_detect("[::1]:65535");
        assert_equal(address.type, IPType.IPv6);
        assert_equal(address.port, 65535);
        assert_equal(address_to_string(address,, temp), "[0:0:0:0:0:0:0:1]:65535");
    }
}

// NOTE(dlb): This is kinda silly, cus we didn't port Yojimbo's BitArray class and are using the Jai module, but hey,
// the more tests the better, right?
test_bit_array :: () {
    Size := 300;

    bit_array := make_bit_array(Size);

    // verify initial conditions

    check(bit_array.count == Size);

    for bit_array {
        check(it == false);
    }

    // set every third bit and verify correct bits are set on read

    for bit_array {
        if (it_index % 3) == 0 {
            bit_array[it_index] = true;
        }
    }

    for bit_array {
        if (it_index % 3) == 0 {
            check(it == true);
        } else {
            check(it == false);
        }
    }

    // now clear every third bit to zero and verify all bits are zero

    for bit_array {
        if (it_index % 3) == 0 {
            bit_array[it_index] = false;
        }
    }

    for bit_array {
        check(it == false);
    }

    // now set some more bits

    for bit_array {
        if (it_index % 10) == 0 {
            bit_array[it_index] = true;
        }
    }

    for bit_array {
        if (it_index % 10) == 0 {
            check(it == true);
        } else {
            check(it == false);
        }
    }

    // clear and verify all bits are zero

    clear_all_bits(*bit_array);

    for bit_array {
        check(it == false);
    }
}