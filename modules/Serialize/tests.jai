#scope_module

inline void SerializeCheckHandler( const char * condition,
                                   const char * function,
                                   const char * file,
                                   int line )
{
    printf( "check failed: ( %s ), function %s, file %s, line %d\n", condition, function, file, line );
#ifndef NDEBUG
    #if defined( __GNUC__ )
        __builtin_trap();
    #elif defined( _MSC_VER )
        __debugbreak();
    #endif
#endif
    exit( 1 );
}

#define serialize_check( condition )                                                    \
do                                                                                      \
{                                                                                       \
    if ( !(condition) )                                                                 \
    {                                                                                   \
        SerializeCheckHandler( #condition, __FUNCTION__, __FILE__, __LINE__ );          \
    }                                                                                   \
} while(0)

inline void test_endian()
{
    uint32_t value = 0x11223344;

    const char * bytes = (const char*) &value;

#if SERIALIZE_LITTLE_ENDIAN

    serialize_check( bytes[0] == 0x44 );
    serialize_check( bytes[1] == 0x33 );
    serialize_check( bytes[2] == 0x22 );
    serialize_check( bytes[3] == 0x11 );

#else // #if SERIALIZE_LITTLE_ENDIAN

    serialize_check( bytes[3] == 0x44 );
    serialize_check( bytes[2] == 0x33 );
    serialize_check( bytes[1] == 0x22 );
    serialize_check( bytes[0] == 0x11 );

#endif // #if SERIALIZE_LITTLE_ENDIAN
}

inline void test_bitpacker()
{
    const int BufferSize = 256;

    uint8_t buffer[BufferSize];

    serialize::BitWriter writer( buffer, BufferSize );

    serialize_check( writer.data == buffer );
    serialize_check( writer.bitsWritten == 0 );
    serialize_check( writer.GetBytesWritten() == 0 );
    serialize_check( writer.numBits - writer.bitsWritten == BufferSize * 8 );

    writer.WriteBits( 0, 1 );
    writer.WriteBits( 1, 1 );
    writer.WriteBits( 10, 8 );
    writer.WriteBits( 255, 8 );
    writer.WriteBits( 1000, 10 );
    writer.WriteBits( 50000, 16 );
    writer.WriteBits( 9999999, 32 );
    writer.FlushBits();

    const int bitsWritten = 1 + 1 + 8 + 8 + 10 + 16 + 32;

    serialize_check( writer.GetBytesWritten() == 10 );
    serialize_check( writer.GetBitsWritten() == bitsWritten );
    serialize_check( writer.numBits - writer.bitsWritten == BufferSize * 8 - bitsWritten );

    const int bytesWritten = writer.GetBytesWritten();

    serialize_check( bytesWritten == 10 );

    memset( buffer + bytesWritten, 0, BufferSize - bytesWritten );

    serialize::BitReader reader( buffer, bytesWritten );

    serialize_check( reader.GetBitsRead() == 0 );
    serialize_check( reader.GetBitsRemaining() == bytesWritten * 8 );

    uint32_t a = reader.ReadBits( 1 );
    uint32_t b = reader.ReadBits( 1 );
    uint32_t c = reader.ReadBits( 8 );
    uint32_t d = reader.ReadBits( 8 );
    uint32_t e = reader.ReadBits( 10 );
    uint32_t f = reader.ReadBits( 16 );
    uint32_t g = reader.ReadBits( 32 );

    serialize_check( a == 0 );
    serialize_check( b == 1 );
    serialize_check( c == 10 );
    serialize_check( d == 255 );
    serialize_check( e == 1000 );
    serialize_check( f == 50000 );
    serialize_check( g == 9999999 );

    serialize_check( reader.GetBitsRead() == bitsWritten );
    serialize_check( reader.GetBitsRemaining() == bytesWritten * 8 - bitsWritten );
}

inline void test_bits_required()
{
    serialize_check( serialize::bits_required( 0, 0 ) == 0 );
    serialize_check( serialize::bits_required( 0, 1 ) == 1 );
    serialize_check( serialize::bits_required( 0, 2 ) == 2 );
    serialize_check( serialize::bits_required( 0, 3 ) == 2 );
    serialize_check( serialize::bits_required( 0, 4 ) == 3 );
    serialize_check( serialize::bits_required( 0, 5 ) == 3 );
    serialize_check( serialize::bits_required( 0, 6 ) == 3 );
    serialize_check( serialize::bits_required( 0, 7 ) == 3 );
    serialize_check( serialize::bits_required( 0, 8 ) == 4 );
    serialize_check( serialize::bits_required( 0, 255 ) == 8 );
    serialize_check( serialize::bits_required( 0, 65535 ) == 16 );
    serialize_check( serialize::bits_required( 0, 4294967295 ) == 32 );
}

const int MaxItems = 11;

struct TestData
{
    TestData()
    {
        memset( this, 0, sizeof( TestData ) );
    }

    int a,b,c;
    uint32_t d : 8;
    uint32_t e : 8;
    uint32_t f : 8;
    bool g;
    uint32_t v32;
    uint64_t v64;
    int numItems;
    int items[MaxItems];
    float float_value;
    float compressed_float_value;
    double double_value;
    uint64_t uint64_value;
    int int_relative;
    uint8_t bytes[17];
    char string[256];
};

struct TestContext
{
    int min;
    int max;
};

struct TestObject
{
    TestData data;

    void Init()
    {
        data.a = 1;
        data.b = -2;
        data.c = 150;
        data.d = 55;
        data.e = 255;
        data.f = 127;
        data.g = true;

        data.numItems = MaxItems / 2;
        for ( int i = 0; i < data.numItems; ++i )
            data.items[i] = i + 10;

        data.compressed_float_value = 2.13f;
        data.float_value = 3.1415926f;
        data.double_value = 1 / 3.0;
        data.uint64_value = 0x1234567898765432L;
        data.int_relative = 5;

        for ( int i = 0; i < (int) sizeof( data.bytes ); ++i )
            data.bytes[i] = rand() % 255;

        serialize_copy_string( data.string, "hello world!", sizeof(data.string) - 1 );
    }

    template <typename Stream> bool Serialize( Stream & stream )
    {
        const TestContext & context = *(const TestContext*) stream.GetContext();

        serialize_int( stream, data.a, context.min, context.max );
        serialize_int( stream, data.b, context.min, context.max );

        serialize_int( stream, data.c, -100, 10000 );

        serialize_bits( stream, data.d, 6 );
        serialize_bits( stream, data.e, 8 );
        serialize_bits( stream, data.f, 7 );

        serialize_align( stream );

        serialize_bool( stream, data.g );

        serialize_int( stream, data.numItems, 0, MaxItems - 1 );
        for ( int i = 0; i < data.numItems; ++i )
            serialize_bits( stream, data.items[i], 8 );

        serialize_float( stream, data.float_value );

        serialize_compressed_float( stream, data.compressed_float_value, 0, 10, 0.01 );

        serialize_double( stream, data.double_value );

        serialize_bits( stream, data.uint64_value, 64 );

        serialize_int_relative( stream, data.a, data.int_relative );

        serialize_bytes( stream, data.bytes, sizeof( data.bytes ) );

        serialize_string( stream, data.string, sizeof( data.string ) );

        return true;
    }

    bool operator == ( const TestObject & other ) const
    {
        return memcmp( &data, &other.data, sizeof( TestData ) ) == 0;
    }

    bool operator != ( const TestObject & other ) const
    {
        return ! ( *this == other );
    }
};

inline void test_stream()
{
    const int BufferSize = 1024;

    uint8_t buffer[BufferSize];

    TestContext context;
    context.min = -10;
    context.max = +10;

    serialize::WriteStream writeStream( buffer, BufferSize );

    TestObject writeObject;
    writeObject.Init();
    writeStream.SetContext( &context );
    writeObject.Serialize( writeStream );
    writeStream.Flush();

    const int bytesWritten = writeStream.GetBytesProcessed();

    memset( buffer + bytesWritten, 0, BufferSize - bytesWritten );

    TestObject readObject;
    serialize::ReadStream readStream( buffer, bytesWritten );
    readStream.SetContext( &context );
    readObject.Serialize( readStream );

    serialize_check( readObject == writeObject );
}

#define SERIALIZE_RUN_TEST( test_function )                                 \
    do                                                                      \
    {                                                                       \
        printf( #test_function "\n" );                                      \
        test_function();                                                    \
    }                                                                       \
    while (0)

inline void serialize_test()
{
    // while ( 1 )
    {
        SERIALIZE_RUN_TEST( test_endian );
        SERIALIZE_RUN_TEST( test_bitpacker );
        SERIALIZE_RUN_TEST( test_bits_required );
        SERIALIZE_RUN_TEST( test_stream );
    }
}