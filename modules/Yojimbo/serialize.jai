#scope_module

/*
Serialize a sequence number relative to another (read/write/measure).
@param stream The stream object. May be a read, write or measure stream.
@param sequence1 The first sequence number to serialize relative to.
@param sequence2 The second sequence number to be encoded relative to the first.
*/
serialize_sequence_relative :: (stream: *Stream, sequence1: u16, sequence2: *u16) -> bool {
    if stream.IsWriting {
        a: u32 = sequence1;
        b: u32 = sequence2.* + ifx sequence1 > sequence2.* then 65536 else 0;
        serialize_int_relative(stream, a, b);
    } else {
        a: u32 = sequence1;
        b: u32 = 0;
        serialize_int_relative(stream, a, b);
        if b >= 65536 {
            b -= 65536;
        }
        sequence2.* = cast(u16) b;
    }
}