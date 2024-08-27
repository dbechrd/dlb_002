#scope_module

/**
    A simple bit array class.
    You can create a bit array with a number of bits, set, clear and test if each bit is set.
    */

class BitArray
{
public:

    /**
        The bit array constructor.
        @param allocator The allocator to use.
        @param size The number of bits in the bit array.
        All bits are initially set to zero.
        */

    BitArray( Allocator & allocator, int size )
    {
        yojimbo_assert( size > 0 );
        m_allocator = &allocator;
        m_size = size;
        m_bytes = 8 * ( ( size / 64 ) + ( ( size % 64 ) ? 1 : 0 ) );
        yojimbo_assert( m_bytes > 0 );
        m_data = (uint64_t*) YOJIMBO_ALLOCATE( allocator, m_bytes );
        Clear();
    }

    /**
        The bit array destructor.
        */

    ~BitArray()
    {
        yojimbo_assert( m_data );
        yojimbo_assert( m_allocator );
        YOJIMBO_FREE( *m_allocator, m_data );
        m_allocator = NULL;
    }

    /**
        Clear all bit values to zero.
        */

    void Clear()
    {
        yojimbo_assert( m_data );
        memset( m_data, 0, m_bytes );
    }

    /**
        Set a bit to 1.
        @param index The index of the bit.
        */

    void SetBit( int index )
    {
        yojimbo_assert( index >= 0 );
        yojimbo_assert( index < m_size );
        const int data_index = index >> 6;
        const int bit_index = index & ( (1<<6) - 1 );
        yojimbo_assert( bit_index >= 0 );
        yojimbo_assert( bit_index < 64 );
        m_data[data_index] |= uint64_t(1) << bit_index;
    }

    /**
        Clear a bit to 0.
        @param index The index of the bit.
        */

    void ClearBit( int index )
    {
        yojimbo_assert( index >= 0 );
        yojimbo_assert( index < m_size );
        const int data_index = index >> 6;
        const int bit_index = index & ( (1<<6) - 1 );
        m_data[data_index] &= ~( uint64_t(1) << bit_index );
    }

    /**
        Get the value of the bit.
        Returns 1 if the bit is set, 0 if the bit is not set.
        @param index The index of the bit.
        */

    uint64_t GetBit( int index ) const
    {
        yojimbo_assert( index >= 0 );
        yojimbo_assert( index < m_size );
        const int data_index = index >> 6;
        const int bit_index = index & ( (1<<6) - 1 );
        yojimbo_assert( bit_index >= 0 );
        yojimbo_assert( bit_index < 64 );
        return ( m_data[data_index] >> bit_index ) & 1;
    }

    /**
        Gets the size of the bit array, in number of bits.
        @returns The number of bits.
        */

    int GetSize() const
    {
        return m_size;
    }

private:

    Allocator * m_allocator;                            ///< Allocator passed in to the constructor.
    int m_size;                                         ///< The size of the bit array in bits.
    int m_bytes;                                        ///< The size of the bit array in bytes.
    uint64_t * m_data;                                  ///< The data backing the bit array is an array of 64 bit integer values.

    BitArray( const BitArray & other );
    BitArray & operator = ( const BitArray & other );
};
