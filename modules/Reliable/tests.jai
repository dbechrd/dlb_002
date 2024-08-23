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

    for 0..TEST_SEQUENCE_BUFFER_SIZE-1 {
        assert(reliable_sequence_buffer_find(sequence_buffer, (cast(u16) it)) == null);
    }                                                                      

    for 0..TEST_SEQUENCE_BUFFER_SIZE*4 {
        entry := cast(*test_sequence_data_t) reliable_sequence_buffer_insert(sequence_buffer, cast(u16) it);
        assert(entry != null);
        entry.sequence = cast(u16) it;
        assert(sequence_buffer.sequence == it + 1);
    }

    for 0..TEST_SEQUENCE_BUFFER_SIZE {
        entry := cast(*test_sequence_data_t) reliable_sequence_buffer_insert(sequence_buffer, cast(u16) it);
        assert(entry == null);
    }    

    index := TEST_SEQUENCE_BUFFER_SIZE * 4;
    for 0..TEST_SEQUENCE_BUFFER_SIZE-1 {
        entry := cast(*test_sequence_data_t) reliable_sequence_buffer_find(sequence_buffer, cast(u16) index);
        assert(entry != null);
        assert(entry.sequence == cast(u32) index);
        index -= 1;
    }

    reliable_sequence_buffer_reset(sequence_buffer);

    assert(sequence_buffer != null);
    assert(sequence_buffer.sequence == 0);
    assert(sequence_buffer.num_entries == TEST_SEQUENCE_BUFFER_SIZE);
    assert(sequence_buffer.entry_stride == size_of(test_sequence_data_t));

    for 0..TEST_SEQUENCE_BUFFER_SIZE-1 {
        assert(reliable_sequence_buffer_find(sequence_buffer, cast(u16) it) == null);
    }

    reliable_sequence_buffer_destroy(sequence_buffer);
}

test_generate_ack_bits :: () {}

test_packet_header :: () {}

test_default_context :: () {}

test_transmit_packet_function :: () {}

test_process_packet_function :: () {}

test_acks :: () {}

test_acks_packet_loss :: () {}

test_process_packet_function_validate :: () {}

test_process_packet_function_validate_large :: () {}

test_packets :: () {}

test_large_packets :: () {}

test_sequence_buffer_rollover :: () {}

test_tracking_allocate_function :: () {}

test_tracking_free_function :: () {}

test_fragment_cleanup :: () {}

reliable_test :: () {
    print("--------------------------------------------------------------------------------\n");
    print("[Reliable] Running tests... ");
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
