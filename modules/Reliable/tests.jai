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

main :: () {
    print("--------------------------------------------------------------------------------\n");
    print("[Reliable] Running tests... ");
    test_endian();
    print("Passed!\n");
    print("--------------------------------------------------------------------------------\n");
}

#run main();