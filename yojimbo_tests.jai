// TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO
// ----------------------------------------------------------------------
// Check all the pump call params for the last two values
// ----------------------------------------------------------------------
// TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO

#import "Unmapping_Allocator";

ENABLE_LOGGING :: true;
SOAK :: 0;

// TODO(dlb)[cleanup]: Use Assertive asserts.
check :: assert;

main :: () {
    push_allocator(get_unmapping_allocator());

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
    address_test();
    serialize_test();
    netcode_test();
    reliable_test();

    log("\n--- Yojimbo --------------------------------------------------------------------\n");
    log("Running tests...\n");

    TEST(test_queue);
    TEST(test_address);
    TEST(test_bit_array);
    TEST(test_sequence_buffer);

    TEST(test_connection_reliable_ordered_messages);
    TEST(test_connection_reliable_ordered_blocks);
    TEST(test_connection_reliable_ordered_messages_and_blocks);
    TEST(test_connection_reliable_ordered_messages_and_blocks_multiple_channels);
    TEST(test_connection_unreliable_unordered_messages);
    TEST(test_connection_unreliable_unordered_blocks);

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

test_sequence_buffer :: () {
    TestSequenceData :: struct {
        sequence: u16 = 0xFFFF;
    };

    Size :: 256;

    sequence_buffer: SequenceBuffer(TestSequenceData);
    sequence_buffer_init(*sequence_buffer, Size);

    for 0..Size-1 {
        entry := sequence_buffer_find(*sequence_buffer, xx it);
        assert_null(entry);
    }

    for 0..Size*4 {
        entry := sequence_buffer_insert(*sequence_buffer, xx it);
        entry.sequence = xx it;
        assert_equal(sequence_buffer_get_next_sequence(*sequence_buffer), cast(u16) it + 1);
    }

    for 0..Size {
        entry := sequence_buffer_insert(*sequence_buffer, xx it);
        assert_null(entry);
    }

    index := Size * 4;
    for 0..Size-1 {
        entry := sequence_buffer_find(*sequence_buffer, xx index);
        assert_not_null(entry);
        assert_equal(entry.sequence, xx index);
        index -= 1;
    }

    for 0..Size {
        entry := sequence_buffer_insert(*sequence_buffer, xx it, true);
        assert_not_null(entry);
        entry.sequence = xx it;
        assert_equal(sequence_buffer_get_next_sequence(*sequence_buffer), cast(u16) it + 1);
    }

    sequence_buffer_reset(*sequence_buffer);

    assert_equal(sequence_buffer_get_next_sequence(*sequence_buffer), 0);

    for 0..Size-1 {
        assert_null(sequence_buffer_find(*sequence_buffer, xx it));
    }
}

APOLLO_100_MS :: #run milliseconds_to_apollo(100);

pump_connection_update :: (connectionConfig: ConnectionConfig, time: *Apollo_Time, sender: *Connection,
                           receiver: *Connection, senderSequence: *u16, receiverSequence: *u16,
                           deltaTime: Apollo_Time = APOLLO_100_MS, packetLossPercent := 0) { //90) {

    packetData := NewArray(connectionConfig.maxPacketSize, u8,, temp);

    if connection_generate_packet(sender, senderSequence.*, packetData, *packetData.count) {
        if yojimbo_random_int(0, 100) >= packetLossPercent {
            connection_process_packet(receiver, senderSequence.*, packetData);
            connection_process_acks(sender, .[senderSequence.*]);
        }
    }

    packetData.count = connectionConfig.maxPacketSize;

    if connection_generate_packet(receiver, receiverSequence.*, packetData, *packetData.count) {
        if yojimbo_random_int(0, 100) >= packetLossPercent {
            connection_process_packet(sender, receiverSequence.*, packetData);
            connection_process_acks(receiver, .[receiverSequence.*]);
        }
    }

    time.* += deltaTime;

    connection_advance_time(sender, time);
    connection_advance_time(receiver, time);

    senderSequence.* += 1;
    receiverSequence.* += 1;
}

test_connection_reliable_ordered_messages :: () {
    sender: Connection;
    receiver: Connection;
    connectionConfig: ConnectionConfig;
    time := seconds_to_apollo(100);

    connection_init(*sender, TestMessageFactory, connectionConfig, time);
    connection_init(*receiver, TestMessageFactory, connectionConfig, time);

    NumMessagesSent :: 64;

    for 0..NumMessagesSent-1 {
        message := cast(*TestMessage) TestMessageFactory[TEST_MESSAGE].create();
        assert_not_null(message);
        message.sequence = xx it;
        connection_send_message(*sender, 0, message);
    }

    SenderPort :: 10000;
    ReceiverPort :: 10001;

    senderAddress := address_init_auto_detect("::1", SenderPort);
    receiverAddress := address_init_auto_detect("::1", ReceiverPort);

    senderSequence: u16;
    receiverSequence: u16;

    NumIterations :: 1000;
    numMessagesReceived := 0;

    for 0..NumIterations-1 {
        pump_connection_update(connectionConfig, *time, *sender, *receiver, *senderSequence, *receiverSequence);

        while true {
            message := connection_receive_message(*receiver, 0);
            if message == null {
                break;
            }

            assert_equal(message.id, xx numMessagesReceived);
            assert_equal(message.type, xx TEST_MESSAGE);

            testMessage := cast(*TestMessage) message;
            assert_equal(testMessage.sequence, xx numMessagesReceived);

            message_release(message);
            numMessagesReceived += 1;
        }

        if numMessagesReceived == NumMessagesSent {
            break;
        }
    }

    assert_equal(numMessagesReceived, NumMessagesSent);
}

test_connection_reliable_ordered_blocks :: () {
    sender: Connection;
    receiver: Connection;
    connectionConfig: ConnectionConfig;
    time := seconds_to_apollo(100);

    connection_init(*sender, TestMessageFactory, connectionConfig, time);
    connection_init(*receiver, TestMessageFactory, connectionConfig, time);

    NumMessagesSent :: 32;

    for msgIndex: 0..NumMessagesSent-1 {
        message := cast(*TestBlockMessage) TestMessageFactory[TEST_BLOCK_MESSAGE].create();
        assert_not_null(message);
        message.sequence = xx msgIndex;

        blockSize := 1 + ((msgIndex * 901) % 3333);
        blockData := NewArray(blockSize, u8);
        for * blockData {
            it.* = cast,no_check(u8) (msgIndex + it_index);
        }
        message.blockData = blockData;
        connection_send_message(*sender, 0, message);
    }

    SenderPort :: 10000;
    ReceiverPort :: 10001;

    senderAddress := address_init_auto_detect("::1", SenderPort);
    receiverAddress := address_init_auto_detect("::1", ReceiverPort);

    senderSequence: u16;
    receiverSequence: u16;

    NumIterations :: 10000;
    numMessagesReceived := 0;

    for iter: 0..NumIterations-1 {
        pump_connection_update(connectionConfig, *time, *sender, *receiver, *senderSequence, *receiverSequence);

        while true {
            message := connection_receive_message(*receiver, 0);
            if message == null {
                break;
            }

            assert_equal(message.id, xx numMessagesReceived);
            assert_equal(message.type, xx TEST_BLOCK_MESSAGE);

            blockMessage := cast(*TestBlockMessage) message;
            assert_equal(blockMessage.sequence, xx numMessagesReceived);

            blockSize := blockMessage.blockData.count;
            assert_equal(blockSize, 1 + ((numMessagesReceived * 901) % 3333));

            assert_not_null(blockMessage.blockData.data);

            for blockMessage.blockData {
                assert_equal(it, cast,no_check(u8) (numMessagesReceived + it_index));
            }

            message_release(message);
            numMessagesReceived += 1;
        }

        if numMessagesReceived == NumMessagesSent {
            break;
        }
    }

    assert_equal(numMessagesReceived, NumMessagesSent);
}

test_connection_reliable_ordered_messages_and_blocks :: () {
    sender: Connection;
    receiver: Connection;
    connectionConfig: ConnectionConfig;
    time := seconds_to_apollo(100);

    connection_init(*sender, TestMessageFactory, connectionConfig, time);
    connection_init(*receiver, TestMessageFactory, connectionConfig, time);

    NumMessagesSent :: 32;

    for msgIndex: 0..NumMessagesSent-1 {
        if yojimbo_random_int(0, 1) == 1 {
            message := cast(*TestMessage) TestMessageFactory[TEST_MESSAGE].create();
            assert_not_null(message);
            message.sequence = xx msgIndex;
            connection_send_message(*sender, 0, message);
        } else {
            message := cast(*TestBlockMessage) TestMessageFactory[TEST_BLOCK_MESSAGE].create();
            assert_not_null(message);
            message.sequence = xx msgIndex;
            blockSize := 1 + ((msgIndex * 901) % 3333);
            blockData := NewArray(blockSize, u8);
            for * blockData {
                it.* = cast,no_check(u8) (msgIndex + it_index);
            }
            message.blockData = blockData;
            connection_send_message(*sender, 0, message);
        }
    }

    SenderPort :: 10000;
    ReceiverPort :: 10001;

    senderAddress := address_init_auto_detect("::1", SenderPort);
    receiverAddress := address_init_auto_detect("::1", ReceiverPort);

    senderSequence: u16;
    receiverSequence: u16;

    NumIterations :: 10000;
    numMessagesReceived := 0;

    for iter: 0..NumIterations-1 {
        pump_connection_update(connectionConfig, *time, *sender, *receiver, *senderSequence, *receiverSequence);

        while true {
            message := connection_receive_message(*receiver, 0);
            if message == null {
                break;
            }

            assert_equal(message.id, xx numMessagesReceived);

            if cast(TestMessageType) message.type == {
                case TEST_MESSAGE;
                    testMessage := cast(*TestMessage) message;

                    assert_equal(testMessage.sequence, xx numMessagesReceived);

                    numMessagesReceived += 1;
                case TEST_BLOCK_MESSAGE;
                    blockMessage := cast(*TestBlockMessage) message;

                    assert_equal(blockMessage.sequence, xx numMessagesReceived);
                    assert_equal(blockMessage.blockData.count, 1 + ((numMessagesReceived * 901) % 3333));
                    assert_not_null(blockMessage.blockData.data);

                    for blockMessage.blockData {
                        assert_equal(it, cast,no_check(u8) (numMessagesReceived + it_index));
                    }

                    numMessagesReceived += 1;
            }

            message_release(message);
        }

        if numMessagesReceived == NumMessagesSent {
            break;
        }
    }

    assert_equal(numMessagesReceived, NumMessagesSent);
}

test_connection_reliable_ordered_messages_and_blocks_multiple_channels :: () {
    NumChannels :: 2;

    sender: Connection;
    receiver: Connection;
    connectionConfig: ConnectionConfig;
    connectionConfig.numChannels = NumChannels;
    connectionConfig.channel[0].type = .ReliableOrdered;
    connectionConfig.channel[0].maxMessagesPerPacket = 8;
    connectionConfig.channel[1].type = .ReliableOrdered;
    connectionConfig.channel[1].maxMessagesPerPacket = 8;
    time := seconds_to_apollo(100);

    connection_init(*sender, TestMessageFactory, connectionConfig, time);
    connection_init(*receiver, TestMessageFactory, connectionConfig, time);

    NumMessagesSent :: 32;

    for channelIndex: 0..NumChannels-1 {
        for msgIndex: 0..NumMessagesSent-1 {
            if yojimbo_random_int(0, 1) == 1 {
                message := cast(*TestMessage) TestMessageFactory[TEST_MESSAGE].create();
                assert_not_null(message);
                message.sequence = xx msgIndex;
                connection_send_message(*sender, channelIndex, message);
            } else {
                message := cast(*TestBlockMessage) TestMessageFactory[TEST_BLOCK_MESSAGE].create();
                assert_not_null(message);
                message.sequence = xx msgIndex;
                blockSize := 1 + ((msgIndex * 901) % 3333);
                blockData := NewArray(blockSize, u8);
                for * blockData {
                    it.* = cast,no_check(u8) (msgIndex + it_index);
                }
                message.blockData = blockData;
                connection_send_message(*sender, channelIndex, message);
            }
        }
    }

    SenderPort :: 10000;
    ReceiverPort :: 10001;

    senderAddress := address_init_auto_detect("::1", SenderPort);
    receiverAddress := address_init_auto_detect("::1", ReceiverPort);

    senderSequence: u16;
    receiverSequence: u16;

    NumIterations :: 10000;
    numMessagesReceived: [NumChannels] int;

    for iter: 0..NumIterations-1 {
        pump_connection_update(connectionConfig, *time, *sender, *receiver, *senderSequence, *receiverSequence);

        for channelIndex: 0..NumChannels-1 {
            while true {
                message := connection_receive_message(*receiver, channelIndex);
                if message == null {
                    break;
                }

                assert_equal(message.id, xx numMessagesReceived[channelIndex]);

                if cast(TestMessageType) message.type == {
                    case TEST_MESSAGE;
                        testMessage := cast(*TestMessage) message;

                        assert_equal(testMessage.sequence, xx numMessagesReceived[channelIndex]);

                        numMessagesReceived[channelIndex] += 1;
                    case TEST_BLOCK_MESSAGE;
                        blockMessage := cast(*TestBlockMessage) message;

                        assert_equal(blockMessage.sequence, xx numMessagesReceived[channelIndex]);

                        assert_equal(blockMessage.blockData.count, 1 + ((numMessagesReceived[channelIndex] * 901) % 3333));
                        assert_not_null(blockMessage.blockData.data);

                        for blockMessage.blockData {
                            assert_equal(it, cast,no_check(u8) (numMessagesReceived[channelIndex] + it_index));
                        }

                        numMessagesReceived[channelIndex] += 1;
                }

                message_release(message);
            }
        }

        receivedAllMessages := true;

        for channelIndex: 0..NumChannels-1 {
            if numMessagesReceived[channelIndex] != NumMessagesSent {
                receivedAllMessages = false;
                break;
            }
        }

        if receivedAllMessages {
            break;
        }
    }

    for channelIndex: 0..NumChannels-1 {
        assert_equal(numMessagesReceived[channelIndex], NumMessagesSent);
    }
}

test_connection_unreliable_unordered_messages :: () {
    sender: Connection;
    receiver: Connection;
    connectionConfig: ConnectionConfig;
    connectionConfig.numChannels = 1;
    connectionConfig.channel[0].type = .UnreliableUnordered;
    time := seconds_to_apollo(100);

    connection_init(*sender, TestMessageFactory, connectionConfig, time);
    connection_init(*receiver, TestMessageFactory, connectionConfig, time);

    NumMessagesSent :: 16;

     for 0..NumMessagesSent-1 {
        message := cast(*TestMessage) TestMessageFactory[TEST_MESSAGE].create();
        assert_not_null(message);
        message.sequence = xx it;
        connection_send_message(*sender, 0, message);
    }

    SenderPort :: 10000;
    ReceiverPort :: 10001;

    senderAddress := address_init_auto_detect("::1", SenderPort);
    receiverAddress := address_init_auto_detect("::1", ReceiverPort);

    senderSequence: u16;
    receiverSequence: u16;

    NumIterations :: 256;
    numMessagesReceived := 0;

    for 0..NumIterations-1 {
        pump_connection_update(connectionConfig, *time, *sender, *receiver, *senderSequence, *receiverSequence, APOLLO_100_MS, 0);

        while true {
            message := connection_receive_message(*receiver, 0);
            if message == null {
                break;
            }

            assert_equal(message.type, xx TEST_MESSAGE);

            testMessage := cast(*TestMessage) message;
            assert_equal(testMessage.sequence, xx numMessagesReceived);

            message_release(message);
            numMessagesReceived += 1;
        }

        if numMessagesReceived == NumMessagesSent {
            break;
        }
    }

    assert_equal(numMessagesReceived, NumMessagesSent);
}

test_connection_unreliable_unordered_blocks :: () {
    sender: Connection;
    receiver: Connection;
    connectionConfig: ConnectionConfig;
    connectionConfig.numChannels = 1;
    connectionConfig.channel[0].type = .UnreliableUnordered;
    time := seconds_to_apollo(100);

    connection_init(*sender, TestMessageFactory, connectionConfig, time);
    connection_init(*receiver, TestMessageFactory, connectionConfig, time);

    NumMessagesSent :: 8;

    for msgIndex: 0..NumMessagesSent-1 {
        message := cast(*TestBlockMessage) TestMessageFactory[TEST_BLOCK_MESSAGE].create();
        assert_not_null(message);
        message.sequence = xx msgIndex;

        blockSize := 1 + (msgIndex * 7);
        blockData := NewArray(blockSize, u8);
        for * blockData {
            it.* = cast,no_check(u8) (msgIndex + it_index);
        }
        message.blockData = blockData;
        connection_send_message(*sender, 0, message);
    }

    SenderPort :: 10000;
    ReceiverPort :: 10001;

    senderAddress := address_init_auto_detect("::1", SenderPort);
    receiverAddress := address_init_auto_detect("::1", ReceiverPort);

    senderSequence: u16;
    receiverSequence: u16;

    NumIterations :: 256;
    numMessagesReceived := 0;

    for iter: 0..NumIterations-1 {
        pump_connection_update(connectionConfig, *time, *sender, *receiver, *senderSequence, *receiverSequence, APOLLO_100_MS, 0);

        while true {
            message := connection_receive_message(*receiver, 0);
            if message == null {
                break;
            }

            assert_equal(message.type, xx TEST_BLOCK_MESSAGE);

            blockMessage := cast(*TestBlockMessage) message;
            assert_equal(blockMessage.sequence, xx numMessagesReceived);

            blockSize := blockMessage.blockData.count;
            assert_equal(blockSize, 1 + (numMessagesReceived * 7));

            assert_not_null(blockMessage.blockData.data);

            for blockMessage.blockData {
                assert_equal(it, cast,no_check(u8) (numMessagesReceived + it_index));
            }

            message_release(message);
            numMessagesReceived += 1;
        }

        if numMessagesReceived == NumMessagesSent {
            break;
        }
    }

    assert_equal(numMessagesReceived, NumMessagesSent);
}

pump_client_server_update :: (time: *Apollo_Time, clients: [] *Client, servers: [] *Server, deltaTime: Apollo_Time = APOLLO_100_MS) {
    for clients {
        client_send_packets(it);
    }
    for servers {
        server_send_packets(it);
    }

    for clients {
        client_receive_packets(it);
    }
    for servers {
        server_receive_packets(it);
    }

    time.* += deltaTime;

    for clients {
        client_advance_time(it, time.*);
    }
    for servers {
        server_advance_time(it, time.*);
    }

    sleep_milliseconds(0);  // Don't ask me.. it was already here. Maybe it helps yield to WinSock.. idk.
}

send_client_to_server_messages :: (client: *Client, numMessagesToSend: int, channelIndex := 0) {
    for msgIndex: 0..numMessagesToSend-1 {
        if !client_can_send_message(client, channelIndex) {
            break;
        }

        // 90% normal, 10% blocks
        if (yojimbo_random_int(1, 10) != 1) {
            message := cast(*TestMessage) TestMessageFactory[TEST_MESSAGE].create();
            assert_not_null(message);
            message.sequence = xx msgIndex;
            client_send_message(client, channelIndex, message);
        } else {
            message := cast(*TestBlockMessage) TestMessageFactory[TEST_BLOCK_MESSAGE].create();
            assert_not_null(message);
            message.sequence = xx msgIndex;

            blockSize := 1 + ((msgIndex * 901) % 1001);
            blockData := NewArray(blockSize, u8);
            for * blockData {
                it.* = cast,no_check(u8) (msgIndex + it_index);
            }
            message.blockData = blockData;
            client_send_message(client, channelIndex, message);
        }
    }
}

send_server_to_client_messages :: (server: *Server, clientIndex: int, numMessagesToSend: int, channelIndex := 0) {
    for msgIndex: 0..numMessagesToSend-1 {
        if !server_can_send_message(server, clientIndex, channelIndex) {
            break;
        }

        // 90% normal, 10% blocks
        if (yojimbo_random_int(1, 10) != 1) {
            message := cast(*TestMessage) TestMessageFactory[TEST_MESSAGE].create();
            assert_not_null(message);
            message.sequence = xx msgIndex;
            server_send_message(server, clientIndex, channelIndex, message);
        } else {
             message := cast(*TestBlockMessage) TestMessageFactory[TEST_BLOCK_MESSAGE].create();
            assert_not_null(message);
            message.sequence = xx msgIndex;

            blockSize := 1 + ((msgIndex * 901) % 1001);
            blockData := NewArray(blockSize, u8);
            for * blockData {
                it.* = cast,no_check(u8) (msgIndex + it_index);
            }
            message.blockData = blockData;
            server_send_message(server, clientIndex, channelIndex, message);
        }
    }
}

process_server_to_client_messages :: (client: *Client, numMessagesReceivedFromServer: *int) {
    while true {
        message := client_receive_message(client, 0);
        if message == null {
            break;
        }

        assert_equal(message.id, xx numMessagesReceivedFromServer.*);

        if cast(TestMessageType) message.type == {
            case TEST_MESSAGE;
                assert_equal(message.blockData.count, 0);
                testMessage := cast(*TestMessage) message;

                assert_equal(testMessage.sequence, xx numMessagesReceivedFromServer.*);
                numMessagesReceivedFromServer.* += 1;
            case TEST_BLOCK_MESSAGE;
                blockMessage := cast(*TestBlockMessage) message;
                assert_equal(blockMessage.sequence, xx numMessagesReceivedFromServer.*);

                assert_equal(blockMessage.blockData.count, 1 + ((numMessagesReceivedFromServer.* * 901) % 1001));
                assert_not_null(blockMessage.blockData.data);
                for * blockMessage.blockData {
                    it.* = cast,no_check(u8) (numMessagesReceivedFromServer.* + it_index);
                }
                numMessagesReceivedFromServer.* += 1;
        }

        client_release_message(client, message);
    }
}

process_client_to_server_messages :: (server: *Server, clientIndex: int, numMessagesReceivedFromClient: *int) {
    while true {
        message := server_receive_message(server, clientIndex, 0);
        if message == null {
            break;
        }

        assert_equal(message.id, xx numMessagesReceivedFromClient.*);

        if cast(TestMessageType) message.type == {
            case TEST_MESSAGE;
                assert_equal(message.blockData.count, 0);
                testMessage := cast(*TestMessage) message;

                assert_equal(testMessage.sequence, xx numMessagesReceivedFromClient.*);
                numMessagesReceivedFromClient.* += 1;
            case TEST_BLOCK_MESSAGE;
                blockMessage := cast(*TestBlockMessage) message;
                assert_equal(blockMessage.sequence, xx numMessagesReceivedFromClient.*);

                assert_equal(blockMessage.blockData.count, 1 + ((numMessagesReceivedFromClient.* * 901) % 1001));
                assert_not_null(blockMessage.blockData.data);
                for * blockMessage.blockData {
                    it.* = cast,no_check(u8) (numMessagesReceivedFromClient.* + it_index);
                }
                numMessagesReceivedFromClient.* += 1;
        }

        server_release_message(server, clientIndex, message);
    }
}