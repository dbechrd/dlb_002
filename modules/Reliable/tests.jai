#scope_file

test_endian :: () {
    value: u32 = 0x11223344;

    bytes := cast(*u8) *value;

    #if LITTLE_ENDIAN {
        assert(bytes[2] == 0x22);
        assert(bytes[1] == 0x33);
        assert(bytes[0] == 0x44);
        assert(bytes[3] == 0x11);
    } else {
        assert(bytes[3] == 0x44);
        assert(bytes[2] == 0x33);
        assert(bytes[1] == 0x22);
        assert(bytes[0] == 0x11);
    }
}

test_sequence_data_t :: struct {
    sequence: u16;
}

TEST_SEQUENCE_BUFFER_SIZE :: 256;

test_sequence_buffer :: () {
    sequence_buffer := reliable_sequence_buffer_create(TEST_SEQUENCE_BUFFER_SIZE, size_of(test_sequence_data_t));

    assert(sequence_buffer != null);
    assert(sequence_buffer.sequence == 0);
    assert(sequence_buffer.num_entries == TEST_SEQUENCE_BUFFER_SIZE);
    assert(sequence_buffer.entry_stride == size_of(test_sequence_data_t));

    // Check that all buffer slots are initially empty
    for 0..TEST_SEQUENCE_BUFFER_SIZE-1 {
        assert(reliable_sequence_buffer_find(sequence_buffer, (cast(u16) it)) == null);
    }

    // Insert enough things to overwrite the buffer entries multiple times, ensuring sequence # keeps going up
    for 0..TEST_SEQUENCE_BUFFER_SIZE*4 {
        entry := cast(*test_sequence_data_t) reliable_sequence_buffer_insert(sequence_buffer, cast(u16) it);
        assert(entry != null);
        entry.sequence = cast(u16) it;
        assert(sequence_buffer.sequence == it + 1);
    }

    // Check that older sequenced things do not get inserted into the buffer
    for 0..TEST_SEQUENCE_BUFFER_SIZE {
        entry := cast(*test_sequence_data_t) reliable_sequence_buffer_insert(sequence_buffer, cast(u16) it);
        assert(entry == null);
    }

    // Check that the N (where N == BUFFER_SIZE) most recent entries are in the buffer and have the last N sequence numbers
    sequence := TEST_SEQUENCE_BUFFER_SIZE * 4;
    for 0..TEST_SEQUENCE_BUFFER_SIZE-1 {
        entry := cast(*test_sequence_data_t) reliable_sequence_buffer_find(sequence_buffer, cast(u16) sequence);
        assert(entry != null);
        assert(entry.sequence == cast(u32) sequence);
        sequence -= 1;
    }

    reliable_sequence_buffer_reset(sequence_buffer);

    assert(sequence_buffer != null);
    assert(sequence_buffer.sequence == 0);
    assert(sequence_buffer.num_entries == TEST_SEQUENCE_BUFFER_SIZE);
    assert(sequence_buffer.entry_stride == size_of(test_sequence_data_t));

    // Check that all of the entries were cleared
    for 0..TEST_SEQUENCE_BUFFER_SIZE-1 {
        assert(reliable_sequence_buffer_find(sequence_buffer, cast(u16) it) == null);
    }

    reliable_sequence_buffer_destroy(sequence_buffer);
}

test_generate_ack_bits :: () {
     sequence_buffer := reliable_sequence_buffer_create(TEST_SEQUENCE_BUFFER_SIZE, size_of(test_sequence_data_t));

    ack, ack_bits := reliable_sequence_buffer_generate_ack_bits(sequence_buffer);
    assert(ack == 0xFFFF);
    assert(ack_bits == 0);

    for 0..TEST_SEQUENCE_BUFFER_SIZE {
        reliable_sequence_buffer_insert(sequence_buffer, cast(u16) it);
    }

    ack, ack_bits = reliable_sequence_buffer_generate_ack_bits(sequence_buffer);
    assert(ack == TEST_SEQUENCE_BUFFER_SIZE);
    assert(ack_bits == 0xFFFFFFFF);

    reliable_sequence_buffer_reset(sequence_buffer);

    input_acks: [] u16 = .[ 1, 5, 9, 11 ];
    for input_acks {
        reliable_sequence_buffer_insert(sequence_buffer, it);
    }

    ack, ack_bits = reliable_sequence_buffer_generate_ack_bits(sequence_buffer);

    assert(ack == 11);
    assert(ack_bits == ( 1 | (1<<(11-9)) | (1<<(11-5)) | (1<<(11-1)) ));

    reliable_sequence_buffer_destroy(sequence_buffer);
}

test_packet_header :: () {
    write_sequence: u16;
    write_ack: u16;
    write_ack_bits: u32;

    packet_data: [RELIABLE_MAX_PACKET_HEADER_BYTES] u8;

    // worst case, sequence and ack are far apart, no packets acked.

    write_sequence = 10000;
    write_ack = 100;
    write_ack_bits = 0;

    bytes_written := reliable_write_packet_header(packet_data, write_sequence, write_ack, write_ack_bits);
    assert(bytes_written == RELIABLE_MAX_PACKET_HEADER_BYTES);

    bytes_read, read_sequence, read_ack, read_ack_bits := reliable_read_packet_header("test_packet_header", .{ bytes_written, packet_data.data });
    assert(bytes_read == bytes_written);
    assert(read_sequence == write_sequence);
    assert(read_ack == write_ack);
    assert(read_ack_bits == write_ack_bits);

    // rare case. sequence and ack are far apart, significant # of acks are missing

    write_sequence = 10000;
    write_ack = 100;
    write_ack_bits = 0xFEFEFFFE;

    bytes_written = reliable_write_packet_header(packet_data, write_sequence, write_ack, write_ack_bits);
    assert(bytes_written == 1 + 2 + 2 + 3);

    bytes_read, read_sequence, read_ack, read_ack_bits = reliable_read_packet_header("test_packet_header", .{ bytes_written, packet_data.data });
    assert(bytes_read == bytes_written);
    assert(read_sequence == write_sequence);
    assert(read_ack == write_ack);
    assert(read_ack_bits == write_ack_bits);

    // common case under packet loss. sequence and ack are close together, some acks are missing

    write_sequence = 200;
    write_ack = 100;
    write_ack_bits = 0xFFFEFFFF;

    bytes_written = reliable_write_packet_header(packet_data, write_sequence, write_ack, write_ack_bits);
    assert(bytes_written == 1 + 2 + 1 + 1);

    bytes_read, read_sequence, read_ack, read_ack_bits = reliable_read_packet_header("test_packet_header", .{ bytes_written, packet_data.data });
    assert(bytes_read == bytes_written);
    assert(read_sequence == write_sequence);
    assert(read_ack == write_ack);
    assert(read_ack_bits == write_ack_bits);

    // ideal case. no packet loss.

    write_sequence = 200;
    write_ack = 100;
    write_ack_bits = 0xFFFFFFFF;

    bytes_written = reliable_write_packet_header(packet_data, write_sequence, write_ack, write_ack_bits);
    assert(bytes_written == 1 + 2 + 1);

    bytes_read, read_sequence, read_ack, read_ack_bits = reliable_read_packet_header("test_packet_header", .{ bytes_written, packet_data.data });
    assert(bytes_read == bytes_written);
    assert(read_sequence == write_sequence);
    assert(read_ack == write_ack);
    assert(read_ack_bits == write_ack_bits);
}

test_context_t :: struct {
    drop          : int;
    allow_packets : int = -1;
    sender        : *reliable_endpoint_t;
    receiver      : *reliable_endpoint_t;
}

test_transmit_packet_function :: (_ctx: *void, id: u64, sequence: u16, packet_data: [] u8) {
    ctx := cast (*test_context_t) _ctx;

    if ctx.drop {
        return;
    }

    if ctx.allow_packets >= 0 {
        if ctx.allow_packets == 0 {
            return;
        }

        ctx.allow_packets -= 1;
    }

    if id == 0 {
        reliable_endpoint_receive_packet(ctx.receiver, packet_data);
    } else if id == 1 {
        reliable_endpoint_receive_packet(ctx.sender, packet_data);
    }
}

test_process_packet_function :: (_ctx: *void, id: u64, sequence: u16, packet_data: [] u8) -> int {
    return 1;
}

TEST_ACKS_NUM_ITERATIONS :: 256;

test_acks :: () {
    time := seconds_to_apollo(100);

    ctx: test_context_t;

    sender_config: reliable_config_t;
    receiver_config: reliable_config_t;

    sender_config.ctx = *ctx;
    sender_config.id = 0;
    sender_config.transmit_packet_function = test_transmit_packet_function;
    sender_config.process_packet_function = test_process_packet_function;

    receiver_config.ctx = *ctx;
    receiver_config.id = 1;
    receiver_config.transmit_packet_function = test_transmit_packet_function;
    receiver_config.process_packet_function = test_process_packet_function;

    ctx.sender = reliable_endpoint_create(*sender_config, time);
    ctx.receiver = reliable_endpoint_create(*receiver_config, time);

    delta_time := milliseconds_to_apollo(10);

    for 0..TEST_ACKS_NUM_ITERATIONS-1 {
        dummy_packet: [8] u8;

        reliable_endpoint_send_packet(ctx.sender, dummy_packet);
        reliable_endpoint_send_packet(ctx.receiver, dummy_packet);

        reliable_endpoint_update(ctx.sender, time);
        reliable_endpoint_update(ctx.receiver, time);

        time += delta_time;
    }

    sender_acked_packet: [TEST_ACKS_NUM_ITERATIONS] bool;
    sender_acks := reliable_endpoint_get_acks(ctx.sender);
    for sender_acks {
        if it < TEST_ACKS_NUM_ITERATIONS {
            sender_acked_packet[it] = true;
        }
    }
    for 0..(TEST_ACKS_NUM_ITERATIONS/2)-1 {
        assert(sender_acked_packet[it]);
    }

    receiver_acked_packet: [TEST_ACKS_NUM_ITERATIONS] bool;
    receiver_acks := reliable_endpoint_get_acks(ctx.receiver);
    for receiver_acks {
        if it < TEST_ACKS_NUM_ITERATIONS {
            receiver_acked_packet[it] = true;
        }
    }
    for 0..(TEST_ACKS_NUM_ITERATIONS/2)-1 {
        assert(receiver_acked_packet[it]);
    }

    reliable_endpoint_destroy(ctx.sender);
    reliable_endpoint_destroy(ctx.receiver);
}

test_acks_packet_loss :: () {}

test_process_packet_function_validate :: () {}

test_process_packet_function_validate_large :: () {}

test_packets :: () {}

test_large_packets :: () {}

test_sequence_buffer_rollover :: () {}

test_tracking_allocate_function :: () {}

test_tracking_free_function :: () {}

test_fragment_cleanup :: () {}

#scope_export

#if RUN_TESTS {
    #run reliable_test();
}

reliable_test :: () {
    print("--------------------------------------------------------------------------------\n");
    print("[Reliable] Running tests...\n");
    test_endian();
    test_sequence_buffer();
    test_generate_ack_bits();
    test_packet_header();

    // NOTE(dlb): The commented test functions are not tests, they are helper functions.
    // TODO(dlb): Rename the helper functions?

    // test_default_context();
    // test_transmit_packet_function();
    // test_process_packet_function();
    test_acks();
    test_acks_packet_loss();

    // test_process_packet_function_validate();
    // test_process_packet_function_validate_large();
    test_packets();
    test_large_packets();

    test_sequence_buffer_rollover();

    // test_tracking_allocate_function();
    // test_tracking_free_function();
    test_fragment_cleanup();

    print("Passed!\n");
    print("--------------------------------------------------------------------------------\n");
}
