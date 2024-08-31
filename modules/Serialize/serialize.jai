/*
Native port of Glenn Fielder's serialize library, as of this commit:
https://github.com/mas-bandwidth/serialize/commit/cc75300b1bce50246374709bf1d29baee41f9587

------------------------------------------------------------------------------------------------------------------------
| Original BSD-3 license
------------------------------------------------------------------------------------------------------------------------
    serialize

    Copyright © 2016 - 2024, Mas Bandwidth LLC.

    Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

        1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

        2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer
           in the documentation and/or other materials provided with the distribution.

        3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived
           from this software without specific prior written permission.

    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
    INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
    DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
    SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
    SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
    WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
    USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
---------------------------------------------------------------------------------------------------------------------
*/

#module_parameters(
    ENABLE_LOGGING := false,
    LITTLE_ENDIAN := true
);

/*
Calculates the log base 2 of an unsigned 32 bit integer.
@param x The input integer value.
@returns The log base 2 of the input.
*/
log2 :: inline (x: u32) -> u32 {
    a: u32 = x | (x >> 1);
    b: u32 = a | (a >> 2);
    c: u32 = b | (b >> 4);
    d: u32 = c | (c >> 8);
    e: u32 = d | (d >> 16);
    f: u32 = e >> 1;
    return popcount(f);
}

/*
Calculates the number of bits required to serialize an integer in range [min,max].
@param min The minimum value.
@param max The maximum value.
@returns The number of bits required to serialize the integer.
*/
bits_required :: inline (min: u32, max: u32) -> u32 {
    /*
    #ifdef __GNUC__ {
        return ( min == max ) ? 0 : 32 - __builtin_clz( max - min );
    } else {
        return ( min == max ) ? 0 : log2(max - min) + 1;
    }
    */

    return ifx min == max then 0 else log2(max - min) + 1;
}

/*
Convert an integer value from local byte order to network byte order.
IMPORTANT: Because most machines are little endian, serialize defines network byte order to be little endian.
@param value The input value in local byte order. Supported integer types: uint64_t, uint32_t, uint16_t.
@returns The input value converted to network byte order. If this processor is little endian the output is the same as the input. If the processor is big endian, the output is the input byte swapped.
*/
host_to_network :: inline ($T value) -> T {
    #if LITTLE_ENDIAN {
        return value;
    } else {
        return byte_swap(value);
    }
}

/*
Convert an integer value from network byte order to local byte order.
IMPORTANT: Because most machines are little endian, serialize defines network byte order to be little endian.
@param value The input value in network byte order. Supported integer types: uint64_t, uint32_t, uint16_t.
@returns The input value converted to local byte order. If this processor is little endian the output is the same as the input. If the processor is big endian, the output is the input byte swapped.
*/
network_to_host :: inline ($T value) -> T {
    #if LITTLE_ENDIAN {
        return value;
    } else {
        return byte_swap(value);
    }
}

/*
Convert a signed integer to an unsigned integer with zig-zag encoding.
0,-1,+1,-2,+2... becomes 0,1,2,3,4 ...
@param n The input value.
@returns The input value converted from signed to unsigned with zig-zag encoding.
*/
signed_to_unsigned :: inline (n: s32) -> u32 {
    return (n << 1) ^ (n >> 31);
}

/*
Convert an unsigned integer to as signed integer with zig-zag encoding.
0,1,2,3,4... becomes 0,-1,+1,-2,+2...
@param n The input value.
@returns The input value converted from unsigned to signed with zig-zag encoding.
*/
unsigned_to_signed :: inline (n: u32) -> s32 {
    return ( n >> 1 ) ^ ( -int32_t( n & 1 ) );
}

/*
Bitpacks unsigned integer values to a buffer.
Integer bit values are written to a 64 bit scratch value from right to left.
Once the low 32 bits of the scratch is filled with bits it is flushed to memory as a dword and the scratch value is shifted right by 32.
The bit stream is written to memory in little endian order, which is considered network byte order for this library.
*/
BitWriter :: struct {
    data        : [] u32;  // The buffer we are writing to, as a uint32_t * because we're writing dwords at a time.
    scratch     : u64;     // The scratch value where we write bits to (right to left). 64 bit for overflow. Once # of bits in scratch is >= 32, the low 32 bits are flushed to memory.
    numBits     : int;     // The number of bits in the buffer. This is equivalent to the size of the buffer in bytes multiplied by 8. Note that the buffer size must always be a multiple of 4.
    bitsWritten : int;     // The number of bits written so far.
    wordIndex   : int;     // The current word index. The next word flushed to memory will be at this index in data.
    scratchBits : int;     // The number of bits in scratch. When this is >= 32, the low 32 bits of scratch is flushed to memory as a dword and scratch is shifted right by 32.

/*
Bit writer constructor.
Creates a bit writer object to write to the specified buffer.
@param buffer The buffer to fill with bitpacked data. Length must be a multiple of 4, because the bitpacker reads and writes memory as dwords, not bytes.
*/
bit_writer_init :: (using writer: *BitWriter, buffer: [] u8) {
    assert(buffer.count > 0);
    assert(buffer.count % 4 == 0);

    data = .{ buffer.count / 4, buffer.data };
    numBits = buffer.count * 32;
}

/*
Write bits to the buffer.
Bits are written to the buffer as-is, without padding to nearest byte. Will assert if you try to write past the end of the buffer.
A boolean value writes just 1 bit to the buffer, a value in range [0,31] can be written with just 5 bits and so on.
IMPORTANT: When you have finished writing to your buffer, take care to call bit_writer_flush_bits, otherwise the last dword of data will not get flushed to memory!
@param value The integer value to write to the buffer. Must be in [0,(1<<bits)-1].
@param bits The number of bits to encode in [1,32].
*/
bit_writer_write_bits :: (using writer: *BitWriter, value: u32, bits: int) {
    assert(bits > 0);
    assert(bits <= 32);
    assert(bitsWritten + bits <= numBits);
    assert(cast(u64) value <= ((1 << bits) - 1));

    scratch |= (cast(u64) value) << scratchBits;
    scratchBits += bits;

    if scratchBits >= 32 {
        assert(wordIndex < data.count);
        data[wordIndex] = host_to_network(cast(u32) (scratch & 0xFFFFFFFF));
        scratch >>= 32;
        scratchBits -= 32;
        wordIndex += 1;
    }

    bitsWritten += bits;
}

/*
Write an alignment to the bit stream, padding zeros so the bit index becomes is a multiple of 8.
This is useful if you want to write some data to a packet that should be byte aligned. For example, an array of bytes, or a string.
IMPORTANT: If the current bit index is already a multiple of 8, nothing is written.
*/
bit_writer_align :: (writer: *BitWriter) {
    remainderBits := writer.bitsWritten % 8;

    if remainderBits != 0 {
        zero: u32 = 0;
        bit_writer_write_bits(writer, zero, 8 - remainderBits);
        assert((m_bitsWritten % 8) == 0);
    }
}

/*
Write an array of bytes to the bit stream.
Use this when you have to copy a large block of data into your bitstream.
Faster than just writing each byte to the bit stream via bit_writer_write_bits(writer, value, 8), because it aligns to byte index and copies into the buffer without bitpacking.
@param data The byte array data to write to the bit stream.
@param bytes The number of bytes to write.
*/
bit_writer_write_bytes :: (using writer: *BitWriter, bytes: [] u8) {
    assert(bit_writer_get_align_bits(writer) == 0);
    assert(bitsWritten + bytes.count * 8 <= numBits);

    headBytes := (4 - (bitsWritten % 32) / 8) % 4;
    if headBytes > bytes.count {
        headBytes = bytes.count;
    }
    for 0..headBytes-1 {
        bit_writer_write_bits(writer, bytes[it], 8);
    }
    if headBytes == bytes.count {
        return;
    }

    bit_writer_flush_bits(writer);
    assert(bit_writer_get_align_bits(writer) == 0);

    numWords := (bytes.count - headBytes) / 4;
    if numWords > 0 {
        assert((bitsWritten % 32) == 0);

        memcpy(*data[wordIndex], bytes.data + headBytes, numWords * 4);

        bitsWritten += numWords * 32;
        wordIndex += numWords;
        scratch = 0;
    }
    assert(bit_writer_get_align_bits(writer) == 0);

    tailStart := headBytes + numWords * 4;
    tailBytes := bytes.count - tailStart;
    assert(tailBytes >= 0 && tailBytes < 4);
    for 0..tailBytes-1 {
        bit_writer_write_bits(writer, bytes[tailStart + it], 8);
    }
    assert(writer.bit_writer_get_align_bits(writer) == 0);

    assert(headBytes + numWords * 4 + tailBytes == bytes.count);
}

/*
Flush any remaining bits to memory.
Call this once after you've finished writing bits to flush the last dword of scratch to memory!
*/
bit_writer_flush_bits :: (using writer: *BitWriter) {
    if scratchBits != 0 {
        assert(scratchBits <= 32);
        assert(wordIndex < m_numWords);

        data[wordIndex] = host_to_network(cast(u32) (scratch & 0xFFFFFFFF));
        scratch >>= 32;
        scratchBits = 0;
        wordIndex += 1;
    }
}

/*
How many align bits would be written, if we were to write an align right now?
@returns Result in [0,7], where 0 is zero bits required to align (already aligned) and 7 is worst case.
*/
bit_writer_get_align_bits :: (using writer: *BitWriter) {
    return (8 - (bitsWritten % 8)) % 8;
}

/*
The number of bytes flushed to memory.
This is effectively the size of the packet that you should send after you have finished bitpacking values with this class.
The returned value is not always a multiple of 4, even though we flush dwords to memory. You won't miss any data in this case because the order of bits written is designed to work with the little endian memory layout.
IMPORTANT: Make sure you call bit_writer_flush_bits before calling this method, otherwise you risk missing the last dword of data.
*/
bit_writer_get_bytes_written :: (using writer: *BitWriter) -> int {
    return (bitsWritten + 7) / 8;
}

/*
Reads bit packed integer values from a buffer.
Relies on the user reconstructing the exact same set of bit reads as bit writes when the buffer was written. This is an unattributed bitpacked binary stream!
Implementation: 32 bit dwords are read in from memory to the high bits of a scratch value as required. The user reads off bit values from the scratch value from the right, after which the scratch value is shifted by the same number of bits.
*/
BitReader :: struct {
    data        : [] u32;  // The bitpacked data we're reading as a dword array.
    scratch     : u64;     // The scratch value. New data is read in 32 bits at a top to the left of this buffer, and data is read off to the right.
    numBits     : int;     // Number of bits to read in the buffer. Of course, we can't *really* know this so it's actually data.count * 32.
    bitsRead    : int;     // Number of bits read from the buffer so far.
    scratchBits : int;     // Number of bits currently in the scratch value. If the user wants to read more bits than this, we have to go fetch another dword from memory.
    wordIndex   : int;     // Index of the next word to read from memory.
}

/*
Bit reader constructor.
@param buffer The buffer of bitpacked data to read. Length must be a multiple of 4, because the bitpacker reads and writes memory as dwords, not bytes.
@see BitWriter
*/
bit_reader_init :: (using reader: *BitReader, buffer: [] u8) {
    assert(buffer.count > 0);
    assert(buffer.count % 4 == 0);

    data = .{ buffer.count / 4, buffer.data };
    numBits = buffer.count * 32;
}

/**
Would the bit reader would read past the end of the buffer if it read this many bits?
@param bits The number of bits that would be read.
@returns True if reading the number of bits would read past the end of the buffer.
*/
bit_reader_would_read_past_end :: (using reader: *BitReader, int bits) -> bool {
    return bitsRead + bits > numBits;
}

/*
Read bits from the bit buffer.
This function will assert in debug builds if this read would read past the end of the buffer.
In production situations, the higher level ReadStream takes care of checking all packet data and never calling this function if it would read past the end of the buffer.
@param bits The number of bits to read in [1,32].
@returns The integer value read in range [0,(1<<bits)-1].
@see BitReader::WouldReadPastEnd
@see BitWriter::WriteBits
*/
bit_reader_read_bits :: (using reader: *BitReader, bits: int) -> u32 {
    assert(bits > 0);
    assert(bits <= 32);
    assert(m_bitsRead + bits <= m_numBits);

    m_bitsRead += bits;

    assert(scratchBits >= 0 && scratchBits <= 64);

    if scratchBits < bits {
        scratch |= (cast(u64) network_to_host(data[m_wordIndex])) << scratchBits;
        scratchBits += 32;
        wordIndex += 1;
    }

    assert(scratchBits >= bits);

    value := cast(u32) (scratch & (((cast(u64) 1) << bits) - 1));
    scratch >>= bits;
    scratchBits -= bits;
    return value;
}

/*
Read an align.
Call this on read to correspond to a WriteAlign call when the bitpacked buffer was written.
This makes sure we skip ahead to the next aligned byte index. As a safety check, we verify that the padding to next byte is zero bits and return false if that's not the case.
This will typically abort packet read. Just another safety measure...
@returns True if we successfully read an align and skipped ahead past zero pad, false otherwise (probably means, no align was written to the stream).
@see BitWriter::WriteAlign
*/
bit_reader_align :: (using reader: *BitReader) -> bool {
    remainderBits := bitsRead % 8;
    if remainderBits != 0 {
        value := bit_reader_read_bits(8 - remainderBits);
        assert(bitsRead % 8 == 0);
        if value != 0 {
            return false;
        }
    }
    return true;
}

/**
Read bytes from the bitpacked data.
@see BitWriter::WriteBytes
*/
bit_reader_read_bytes :: (using reader: *BitReader, bytes: [] u8) {
    assert(bit_reader_get_align_bits(reader) == 0);
    assert(bitsRead + bytes.count * 8 <= numBits);

    headBytes := (4 - (bitsRead % 32) / 8) % 4;
    if headBytes > bytes.count {
        headBytes = bytes.count;
    }
    for 0..headBytes-1 {
        bytes[it] = cast(u8) bit_reader_read_bits(reader, 8);
    }
    if headBytes == bytes.count {
        return;
    }
    assert(bit_reader_get_align_bits(reader) == 0);

    numWords := (bytes.count - headBytes) / 4;
    if numWords > 0 {
        assert((bitsRead % 32) == 0);

        memcpy(bytes.data + headBytes, *data[wordIndex], numWords * 4);

        bitsRead += numWords * 32;
        wordIndex += numWords;
        scratchBits = 0;
    }
    assert(bit_reader_get_align_bits(reader) == 0);

    tailStart := headBytes + numWords * 4;
    tailBytes := bytes.count - tailStart;
    assert(tailBytes >= 0 && tailBytes < 4);
    for 0..tailBytes-1 {
        bytes[tailStart + it] = cast(u8) bit_reader_read_bits(reader, 8);
    }
    assert(bit_reader_get_align_bits(reader) == 0);

    assert(headBytes + numWords * 4 + tailBytes == bytes.count);
}

/*
How many align bits would be read, if we were to read an align right now?
@returns Result in [0,7], where 0 is zero bits required to align (already aligned) and 7 is worst case.
*/
bit_reader_get_align_bits :: (using reader: *BitReader) -> int {
    return (8 - bitsRead % 8) % 8;
}

/*
Stream class for writing bitpacked data.
This class is a wrapper around the bit writer class. Its purpose is to provide unified interface for reading and writing.
You can determine if you are writing to a stream by calling Stream::IsWriting inside your templated serialize method.
This is evaluated at compile time, letting the compiler generate optimized serialize functions without the hassle of maintaining separate read and write functions.
IMPORTANT: Generally, you don't call methods on this class directly. Use the serialize_* macros instead.
@see BitWriter
*/
WriteStream :: struct {
    isWriting :: true;
    isReading :: false;

    writer: BitWriter;  // The bit writer used for all bitpacked write operations.
};

/*
Write stream constructor.
@param buffer The buffer to write to.
@param bytes The number of bytes in the buffer. Must be a multiple of four.
*/
stream_init :: (using stream: *WriteStream, buffer: [] u8) {
    bit_writer_init(writer, buffer);
}

/*
Serialize an integer (write).
@param value The integer value in [min,max].
@param min The minimum value.
@param max The maximum value.
@returns Always returns true. All checking is performed by debug asserts only on write.
*/
stream_serialize_integer :: (using stream: *WriteStream, value: s32, min: s32, max: s32) -> bool {
    assert(min < max);
    assert(value >= min);
    assert(value <= max);

    bits := bits_required(min, max);
    unsigned_value = cast(u32) (value - min);
    bit_writer_write_bits(writer, unsigned_value, bits);
    return true;
}

/*
Serialize a number of bits (write).
@param value The unsigned integer value to serialize. Must be in range [0,(1<<bits)-1].
@param bits The number of bits to write in [1,32].
@returns Always returns true. All checking is performed by debug asserts on write.
*/
stream_serialize_bits :: (using stream: *WriteStream, value: *u32, bits: int) -> bool {
    assert(bits > 0);
    assert(bits <= 32);

    bit_writer_write_bits(writer, value.*, bits);
    return true;
}

/*
Serialize an array of bytes (write).
@param data Array of bytes to be written.
@param bytes The number of bytes to write.
@returns Always returns true. All checking is performed by debug asserts on write.
*/
stream_serialize_bytes :: (using stream: *WriteStream, bytes: [] u8) -> bool {
    assert(bytes.count > 0);

    stream_align(stream);
    bit_writer_write_bytes(writer, bytes);
    return true;
}

/*
Serialize an align (write).
*/
stream_align :: (using stream: *WriteStream) {
    bit_writer_align(writer);
}

/*
If we were to write an align right now, how many bits would be required?
@returns The number of zero pad bits required to achieve byte alignment in [0,7].
*/
stream_get_align_bits :: (using stream: *WriteStream) {
    return bit_writer_get_align_bits(writer);
}

/*
Flush the stream to memory after you finish writing.
Always call this after you finish writing and before you call WriteStream::GetData, or you'll potentially truncate the last dword of data you wrote.
@see BitWriter::FlushBits
*/
stream_flush :: (using stream: *WriteStream) {
    bit_writer_flush_bits(writer);
}

/*
Get a pointer to the data written by the stream.
IMPORTANT: Call WriteStream::Flush before you call this function!
@returns A pointer to the data written by the stream
*/
stream_get_data :: (using stream: *WriteStream) -> [] u8 {
    return writer.data;
}

/*
How many bytes have been written so far?
@returns Number of bytes written. This is effectively the packet size.
*/
stream_get_bytes_processed :: (using stream: *WriteStream) -> int {
    return bit_writer_get_bytes_written(writer);
}

/*
Get number of bits written so far.
@returns Number of bits written.
*/
stream_get_bits_processed :: (using stream: *WriteStream) -> int {
    return writer.bitsWritten;
}

/**
Stream class for reading bitpacked data.
This class is a wrapper around the bit reader class. Its purpose is to provide unified interface for reading and writing.
You can determine if you are reading from a stream by calling Stream::IsReading inside your templated serialize method.
This is evaluated at compile time, letting the compiler generate optimized serialize functions without the hassle of maintaining separate read and write functions.
IMPORTANT: Generally, you don't call methods on this class directly. Use the serialize_* macros instead.
@see BitReader
*/
ReadStream :: struct {
    isWriting :: false;
    isReading :: true;

    reader: BitReader;  // The bit reader used for all bitpacked read operations.
};

/*
Read stream constructor.
@param buffer The buffer to read from.
@param bytes The number of bytes in the buffer. May be a non-multiple of four, however if it is, the underlying buffer allocated should be large enough to read the any remainder bytes as a dword.
@param allocator The allocator to use for stream allocations. This lets you dynamically allocate memory as you read and write packets.
*/
stream_init :: (using stream: *ReadStream, buffer: [] u8) {
    bit_reader_init(reader, buffer);
}

/*
Serialize an integer (read).
@param value The integer value read is stored here. It is guaranteed to be in [min,max] if this function succeeds.
@param min The minimum allowed value.
@param max The maximum allowed value.
@returns Returns true if the serialize succeeded and the value is in the correct range. False otherwise.
*/
stream_serialize_integer :: (using stream: *ReadStream, value: *s32, min: s32, max: s32) -> bool {
    assert(min < max);

    bits := bits_required(min, max);
    if bit_reader_would_read_past_end(reader, bits) {
        return false;
    }

    bit_reader_read_bits(reader, bits);
    unsigned_value := bit_reader_read_bits(reader, bits);
    value.* = (cast(s32) unsigned_value) + min;
    return true;
}

/*
Serialize a number of bits (read).
@param value The integer value read is stored here. Will be in range [0,(1<<bits)-1].
@param bits The number of bits to read in [1,32].
@returns Returns true if the serialize read succeeded, false otherwise.
*/
stream_serialize_bits :: (using stream: *ReadStream, value: *u32, bits: int) -> bool {
    assert(bits > 0);
    assert(bits <= 32);

    if bit_reader_would_read_past_end(reader, bits) {
        return false;
    }

    value.* = bit_reader_read_bits(reader, bits);
    return true;
}

/*
Serialize an array of bytes (read).
@param data Array of bytes to read.
@param bytes The number of bytes to read.
@returns Returns true if the serialize read succeeded. False otherwise.
*/
stream_serialize_bytes :: (using stream: *ReadStream, bytes: [] u8) -> bool {
    if !stream_align(stream) {
        return false;
    }
    if bit_reader_would_read_past_end(reader, bytes.count * 8) {
        return false;
    }

    bit_reader_read_bytes(reader, bytes);
    return true;
}

/*
Serialize an align (read).
@returns Returns true if the serialize read succeeded. False otherwise.
*/
stream_align :: (using stream: *ReadStream) -> {
    alignBits := bit_reader_get_align_bits(reader);
    if bit_reader_would_read_past_end(reader, alignBits) {
        return false;
    }
    if !bit_reader_align(reader) {
        return false;
    }

    return true;
}

/*
If we were to read an align right now, how many bits would we need to read?
@returns The number of zero pad bits required to achieve byte alignment in [0,7].
*/
stream_get_align_bits :: (using stream: *ReadStream) -> int {
    return bit_reader_get_align_bits(reader);
}

/*
Get number of bits read so far.
@returns Number of bits read.
*/
stream_get_bits_processed :: (using stream: *ReadStream) -> int {
    return reader.bitsRead;
}

/*
How many bytes have been read so far?
@returns Number of bytes read. Effectively this is the number of bits read, rounded up to the next byte where necessary.
*/
stream_get_bytes_processed :: (using stream: *ReadStream) -> int {
    return (reader.bitsRead + 7) / 8;
}

/*
Stream class for estimating how many bits it would take to serialize something.
This class acts like a bit writer (IsWriting is 1, IsReading is 0), but instead of writing data, it counts how many bits would be written.
Note that when the serialization includes alignment to byte (see MeasureStream::SerializeAlign), this is an estimate and not an exact measurement. The estimate is guaranteed to be conservative.
@see BitWriter
@see BitReader
*/
MeasureStream :: struct {
    isWriting :: true;
    isReading :: false;

    bitsWritten: int;  // Counts the number of bits written.
};

/*
Serialize an integer (measure).
@param value The integer value to write. Not actually used or checked.
@param min The minimum value.
@param max The maximum value.
@returns Always returns true. All checking is performed by debug asserts only on measure.
*/
stream_serialize_integer :: (using stream: *MeasureStream, value: s32, min: s32, max: s32) -> bool {
    assert(min < max);
    assert(value >= min);
    assert(value <= max);

    bits := bits_required(min, max);
    bitsWritten += bits;
    return true;
}

/*
Serialize a number of bits (write).
@param value The unsigned integer value to serialize. Not actually used or checked.
@param bits The number of bits to write in [1,32].
@returns Always returns true. All checking is performed by debug asserts on write.
*/
stream_serialize_bits :: (using stream: *MeasureStream, value: *u32, bits: int) -> bool {
    assert(bits > 0);
    assert(bits <= 32);

    bitsWritten += bits;
    return true;
}

/*
Serialize an array of bytes (measure).
@param data Array of bytes to 'write'. Not actually used.
@param bytes The number of bytes to 'write'.
@returns Always returns true. All checking is performed by debug asserts on write.
*/
stream_serialize_bytes :: (using stream: *MeasureStream, bytes: [] u8) -> bool {
    stream_align(stream);
    bitsWritten += bytes.count * 8;
    return true;
}

/*
Serialize an align (measure).
@returns Always returns true. All checking is performed by debug asserts on write.
*/
stream_align :: (using stream: *MeasureStream) -> bool {
    alignBits := stream_get_align_bits(stream);
    bitsWritten += alignBits;
    return true;
}

/*
If we were to write an align right now, how many bits would be required?
IMPORTANT: Since the number of bits required for alignment depends on where an object is written in the final bit stream, this measurement is conservative.
@returns Always returns worst case 7 bits.
*/
stream_get_align_bits :: (using stream: *MeasureStream) -> int {
    return 7;
}

/*
// TODO(dlb)[cleanup]: I don't think anyone calls this.
/*
Serialize a safety check to the stream (measure).
@returns Always returns true. All checking is performed by debug asserts on write.
*/
stream_serialize_check :: (using stream: *MeasureStream) -> bool {
    #if YOJIMBO_SERIALIZE_CHECKS {
        stream_align(stream);
        bitsWritten += 32;
    }
    return true;
}
*/

/*
Get number of bits written so far.
@returns Number of bits written.
*/
stream_get_bits_proccessed :: (using stream: *MeasureStream) -> int {
    return bitsWritten;
}

/*
How many bytes have been written so far?
@returns Number of bytes written.
*/
stream_get_bytes_proccessed :: (using stream: *MeasureStream) -> int {
    return (bitsWritten + 7) / 8;
}

/*
Serialize integer value (read/write/measure).
This is a helper macro to make writing unified serialize functions easier.
Serialize macros returns false on error so we don't need to use exceptions for error handling on read. This is an important safety measure because packet data comes from the network and may be malicious.
IMPORTANT: This macro must be called inside a function with a bool return value.
@param stream The stream object. May be a read, write or measure stream.
@param value The integer value to serialize in [min,max].
@param min The minimum value.
@param max The maximum value.
*/
serialize_int :: (stream: *$S, value: *$T, min: T, max: T) #expand {
    assert(size_of(T) <= 4);
    assert(min < max);

    s32_value: s32;
    if stream.isWriting {
        assert(cast(s64) value.* >= cast(s64) min);
        assert(cast(s64) value.* <= cast(s64) max);
        s32_value = cast(s32) value.*;
    }
    if !stream_serialize_integer(stream, s32_value, min, max) {
        `return false;
    }
    if stream.isReading {
        value.* = cast(T) s32_value;
        if cast(s64) value.* < cast(s64) min || cast(s64) value.* > cast(s64) max {
            `return false;
        }
    }
}

/*
Serialize bits to the stream (read/write/measure).
This is a helper macro to make writing unified serialize functions easier.
Serialize macros returns false on error so we don't need to use exceptions for error handling on read. This is an important safety measure because packet data comes from the network and may be malicious.
IMPORTANT: This macro must be called inside a function with a bool return value.
@param stream The stream object. May be a read, write or measure stream.
@param value The unsigned integer value to serialize.
@param bits The number of bits to serialize in [1,32].
*/
serialize_bits :: (stream: *$S, value: *$T, bits: int) #expand {
    assert(size_of(T) <= 8);
    assert(bits > 0);
    assert(bits <= 64);

    if bits <= 32 {
        u32_value: u32;
        if stream.isWriting {
            u32_value = cast(u32) value.*;
        }
        if !stream_serialize_bits(stream, *u32_value, bits) {
            `return false;
        }
        if stream.isReading {
            value.* = cast(T) u32_value;
        }
    } else {
        hi, lo: u32;
        if stream.isWriting {
            lo = cast(u32) ((cast(u64) value.*) & 0xFFFFFFFF);
            hi = cast(u32) ((cast(u64) value.*) >> 32);
        }
        if !stream_serialize_bits(stream, *lo, 32) {
            `return false;
        }
        if !stream_serialize_bits(stream, *hi, bits - 32) {
            `return false;
        }
        if stream.isReading {
            value.* = cast(T) (((cast(u64) hi) << 32) | lo);
        }
    }
}

/*
Serialize a boolean value to the stream (read/write/measure).
This is a helper macro to make writing unified serialize functions easier.
Serialize macros returns false on error so we don't need to use exceptions for error handling on read. This is an important safety measure because packet data comes from the network and may be malicious.
IMPORTANT: This macro must be called inside a function with a bool return value.
@param stream The stream object. May be a read, write or measure stream.
@param value The boolean value to serialize.
*/
serialize_bool :: (stream: *$S, value: *bool) #expand {
    u32_value: u32;
    if stream.isWriting {
        u32_value = ifx value.* then 1 else 0;
    }
    if !stream_serialize_bits(stream, *u32_value, 1) {
        `return false;
    }
    if stream.isReading {
        value.* = ifx u32_value then true else false;
    }
}

/*
Serialize floating point value (read/write/measure).
This is a helper macro to make writing unified serialize functions easier.
Serialize macros returns false on error so we don't need to use exceptions for error handling on read. This is an important safety measure because packet data comes from the network and may be malicious.
IMPORTANT: This macro must be called inside a function with a bool return value.
@param stream The stream object. May be a read, write or measure stream.
@param value The float value to serialize.
*/
serialize_float :: (stream: *$S, value: *float) #expand {
    u32_value: u32;
    if stream.isWriting {
        memcpy(*u32_value, value.*, 4);
    }
    if !stream_serialize_bits(stream, *u32_value, 32) {
        `return false;
    }
    if stream.isReading {
        memcpy(value.*, *u32_value, 4);
    }
}

/*
Serialize compressed floating point value (read/write/measure).
This is a helper macro to make writing unified serialize functions easier.
Serialize macros returns false on error so we don't need to use exceptions for error handling on read. This is an important safety measure because packet data comes from the network and may be malicious.
IMPORTANT: This macro must be called inside a function with a bool return value.
@param stream The stream object. May be a read, write or measure stream.
@param value The float value to serialize.
*/
serialize_compressed_float :: (stream: *$S, value: *float, min: float, max: float, res: float) #expand {
    delta := max - min;
    values := delta / res;

    maxIntegerValue := cast(u32) Math.ceil(values);

    bits := bits_required(0, maxIntegerValue);

    integerValue: u32;

    if stream.isWriting {
        normalizedValue := clamp((value.* - min) / delta, 0.0, 1.0);
        integerValue = cast(u32) Math.floor(normalizedValue * maxIntegerValue + 0.5);
    }
    if !stream_serialize_bits(stream, *integerValue, bits) {
        `return false;
    }
    if stream.isReading {
        normalizedValue := integerValue / cast(float) maxIntegerValue;
        value.* = normalizedValue * delta + min;
    }
}

/*
Serialize double precision floating point value to the stream (read/write/measure).
This is a helper macro to make writing unified serialize functions easier.
Serialize macros returns false on error so we don't need to use exceptions for error handling on read. This is an important safety measure because packet data comes from the network and may be malicious.
IMPORTANT: This macro must be called inside a function with a bool return value.
@param stream The stream object. May be a read, write or measure stream.
@param value The double precision floating point value to serialize.
*/
serialize_float64 :: (stream: *$S, value: *float64) #expand {
    u64_value: u64;
    if stream.isWriting {
        memcpy(*u64_value, value.*, 8);
    }
    if !serialize_bits(stream, *u64_value, 64) {
        `return false;
    }
    if stream.isReading {
        memcpy(value.*, *u64_value, 8);
    }
}

/*
Serialize an array of bytes to the stream (read/write/measure).
This is a helper macro to make unified serialize functions easier.
Serialize macros returns false on error so we don't need to use exceptions for error handling on read. This is an important safety measure because packet data comes from the network and may be malicious.
IMPORTANT: This macro must be called inside a function with a bool return value.
@param stream The stream object. May be a read, write or measure stream.
@param data Pointer to the data to be serialized.
@param bytes The number of bytes to serialize.
*/
serialize_bytes :: (stream: *$S, bytes: [] u8) #expand {
    if !stream_serialize_bytes(stream, bytes) {
        `return false;
    }
}

/*
Serialize a string to the stream (read/write/measure).
This is a helper macro to make writing unified serialize functions easier.
Serialize macros returns false on error so we don't need to use exceptions for error handling on read. This is an important safety measure because packet data comes from the network and may be malicious.
IMPORTANT: This macro must be called inside a function with a bool return value.
@param stream The stream object. May be a read, write or measure stream.
@param string The string to serialize write/measure. Pointer to buffer to be filled on read.
@param buffer_size The size of the string buffer. String with terminating null character must fit into this buffer.
*/
serialize_string :: (stream: *$S, str: *string, max_length: s32) #expand {
    length: s32;
    if stream.isWriting {
        length = cast(s32) str.count;
        assert(length <= max_length);
    }
    serialize_int(stream, *length, 0, max_length);
    if stream.isReading {
        str.data = NewArray(length, u8);
        str.count = length;
    }
    serialize_bytes(stream, .{ str.count, str.data });
    return true;
}

/*
Serialize an alignment to the stream (read/write/measure).
This is a helper macro to make writing unified serialize functions easier.
Serialize macros returns false on error so we don't need to use exceptions for error handling on read. This is an important safety measure because packet data comes from the network and may be malicious.
IMPORTANT: This macro must be called inside a function with a bool return value.
@param stream The stream object. May be a read, write or measure stream.
*/
serialize_align :: (stream: *$S) #expand {
    if !stream_align(stream) {
        `return false;
    }
}

serialize_int_relative_internal :: (stream: *$S, previous: $T, current: *T) -> bool {
    assert(size_of(T) <= 4);

    difference: u32;
    if stream.isWriting {
        assert(previous < current);
        difference = current - previous;
    }

    oneBit := false;
    if stream.isWriting {
        oneBit = difference == 1;
    }
    serialize_bool(stream, *oneBit);
    if oneBit {
        if stream.isReading {
            current = previous + 1;
        }
        return true;
    }

    twoBits := false;
    if stream.isWriting {
        twoBits = difference <= 6;
    }
    serialize_bool(stream, *twoBits);
    if twoBits {
        serialize_int(stream, *difference, 2, 6);
        if stream.isReading {
            current = previous + difference;
        }
        return true;
    }

    fourBits := false;
    if stream.isWriting {
        fourBits = difference <= 23;
    }
    serialize_bool(stream, *fourBits);
    if fourBits {
        serialize_int(stream, *difference, 7, 23);
        if stream.isReading {
            current = previous + difference;
        }
        return true;
    }

    eightBits := false;
    if stream.isWriting {
        eightBits = difference <= 280;
    }
    serialize_bool(stream, *eightBits);
    if eightBits {
        serialize_int(stream, *difference, 24, 280);
        if stream.isReading {
            current = previous + difference;
        }
        return true;
    }

    twelveBits := false;
    if stream.isWriting {
        twelveBits = difference <= 4377;
    }
    serialize_bool(stream, *twelveBits);
    if twelveBits {
        serialize_int(stream, *difference, 281, 4377);
        if stream.isReading {
            current = previous + difference;
        }
        return true;
    }

    sixteenBits := false;
    if stream.isWriting {
        sixteenBits = difference <= 69914;
    }
    serialize_bool(stream, *sixteenBits);
    if sixteenBits {
        serialize_int(stream, *difference, 4378, 69914);
        if stream.isReading {
            current = previous + difference;
        }
        return true;
    }

    value := cast(u32) current;
    serialize_bits(stream, *value, 32);
    if stream.isReading {
        current = cast(T) value;
    }

    return true;
}

/*
Serialize an integer value relative to another (read/write/measure).
This is a helper macro to make writing unified serialize functions easier.
Serialize macros returns false on error so we don't need to use exceptions for error handling on read. This is an important safety measure because packet data comes from the network and may be malicious.
IMPORTANT: This macro must be called inside a function with a bool return value.
@param stream The stream object. May be a read, write or measure stream.
@param previous The previous integer value.
@param current The current integer value.
*/
serialize_int_relative :: (stream: *$S, previous: $T, current: *T) #expand {
    if !serialize_int_relative_internal(stream, previous, current) {
        `return false;
    }
}

/*
Serialize a sequence number relative to another (read/write/measure).
@param stream The stream object. May be a read, write or measure stream.
@param sequence1 The first sequence number to serialize relative to.
@param sequence2 The second sequence number to be encoded relative to the first.
*/
serialize_sequence_relative :: (stream: *$S, sequence1: u16, sequence2: *u16) -> bool {
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

#scope_file

#import "Basic";
#import "Bit_Operations";
Math :: #import "Math";