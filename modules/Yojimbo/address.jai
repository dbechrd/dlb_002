#scope_module

/**
    Address type.
    @see Address::GetType.
    */

enum AddressType
{
    ADDRESS_NONE,                                                       ///< Not an address. Set by the default constructor.
    ADDRESS_IPV4,                                                       ///< An IPv4 address, eg: "146.95.129.237"
    ADDRESS_IPV6                                                        ///< An IPv6 address, eg: "48d9:4a08:b543:ae31:89d8:3226:b92c:cbba"
};

/**
    An IP address and port number.
    Supports both IPv4 and IPv6 addresses.
    Identifies where a packet came from, and where a packet should be sent.
    */

class Address
{
    AddressType m_type;                                                 ///< The address type: IPv4 or IPv6.
    union
    {
        uint8_t ipv4[4];                                                ///< IPv4 address data. Valid if type is ADDRESS_IPV4.
        uint16_t ipv6[8];                                               ///< IPv6 address data. Valid if type is ADDRESS_IPV6.
    } m_address;
    uint16_t m_port;                                                    ///< The IP port. Valid for IPv4 and IPv6 address types.

public:

    /**
        Address default constructor.
        Designed for convenience so you can have address members of classes and initialize them via assignment.
        An address created by the default constructor will have address type set to ADDRESS_NONE. Address::IsValid will return false.
        @see IsValid
        */

    Address();

    /**
        Create an IPv4 address.
        IMPORTANT: Pass in port in local byte order. The address class handles the conversion to network order for you.
        @param a The first field of the IPv4 address.
        @param b The second field of the IPv4 address.
        @param c The third field of the IPv4 address.
        @param d The fourth field of the IPv4 address.
        @param port The IPv4 port (local byte order).
        */

    Address( uint8_t a, uint8_t b, uint8_t c, uint8_t d, uint16_t port = 0 );

    /**
        Create an IPv4 address.
        @param address Array of four address fields for the IPv4 address.
        @param port The port number (local byte order).
        */

    Address( const uint8_t address[], uint16_t port = 0 );

    /**
        Create an IPv6 address.
        IMPORTANT: Pass in address fields and the port in local byte order. The address class handles the conversion to network order for you.
        @param a First field of the IPv6 address (local byte order).
        @param b Second field of the IPv6 address (local byte order).
        @param c Third field of the IPv6 address (local byte order).
        @param d Fourth field of the IPv6 address (local byte order).
        @param e Fifth field of the IPv6 address (local byte order).
        @param f Sixth field of the IPv6 address (local byte order).
        @param g Seventh field of the IPv6 address (local byte order).
        @param h Eighth field of the IPv6 address (local byte order).
        @param port The port number (local byte order).
        */

    Address( uint16_t a, uint16_t b, uint16_t c, uint16_t d, uint16_t e, uint16_t f, uint16_t g, uint16_t h, uint16_t port = 0 );

    /**
        Create an IPv6 address.
        IMPORTANT: Pass in address fields and the port in local byte order. The address class handles the conversion to network order for you.
        @param address Array of 8 16 bit address fields for the IPv6 address (local byte order).
        @param port The IPv6 port (local byte order).
        */

    Address( const uint16_t address[], uint16_t port = 0 );

    /**
        Parse a string to an address.
        This versions supports parsing a port included in the address string. For example, "127.0.0.1:4000" and "[::1]:40000".
        Parsing is performed via inet_pton once the port # has been extracted from the string, so you may specify any IPv4 or IPv6 address formatted in any valid way, and it should work as you expect.
        Depending on the type of data in the string the address will become ADDRESS_TYPE_IPV4 or ADDRESS_TYPE_IPV6.
        If the string is not recognized as a valid address, the address type is set to ADDRESS_TYPE_NONE, causing Address::IsValid to return false. Please check that after creating an address from a string.
        @param address The string to parse to create the address.
        @see Address::IsValid
        @see Address::GetType
        */

    explicit Address( const char * address );

    /**
        Parse a string to an address.
        This versions overrides any port read in the address with the port parameter. This lets you parse "127.0.0.1" and "[::1]" and pass in the port you want programmatically.
        Parsing is performed via inet_pton once the port # has been extracted from the string, so you may specify any IPv4 or IPv6 address formatted in any valid way, and it should work as you expect.
        Depending on the type of data in the string the address will become ADDRESS_TYPE_IPV4 or ADDRESS_TYPE_IPV6.
        If the string is not recognized as a valid address, the address type is set to ADDRESS_TYPE_NONE, causing Address::IsValid to return false. Please check that after creating an address from a string.
        @param address The string to parse to create the address.
        @param port Overrides the port number read from the string (if any).
        @see Address::IsValid
        @see Address::GetType
        */

    explicit Address( const char * address, uint16_t port );

    /**
        Clear the address.
        The address type is set to ADDRESS_TYPE_NONE.
        After this function is called Address::IsValid will return false.
        */

    void Clear();

    /**
        Get the IPv4 address data.
        @returns The IPv4 address as an array of bytes.
        */

    const uint8_t * GetAddress4() const;

    /**
        Get the IPv6 address data.
        @returns the IPv6 address data as an array of uint16_t (local byte order).
        */

    const uint16_t * GetAddress6() const;

    /**
        Set the port.
        This is useful when you want to programmatically set a server port, eg. try to open a server on ports 40000, 40001, etc...
        @param port The port number (local byte order). Works for both IPv4 and IPv6 addresses.
        */

    void SetPort( uint16_t port );

    /**
        Get the port number.
        @returns The port number (local byte order).
        */

    uint16_t GetPort() const;

    /**
        Get the address type.
        @returns The address type: ADDRESS_NONE, ADDRESS_IPV4 or ADDRESS_IPV6.
        */

    AddressType GetType() const;

    /**
        Convert the address to a string.
        @param buffer The buffer the address will be written to.
        @param bufferSize The size of the buffer in bytes. Must be at least MaxAddressLength.
        */

    const char * ToString( char buffer[], int bufferSize ) const;

    /**
        True if the address is valid.
        A valid address is any address with a type other than ADDRESS_TYPE_NONE.
        @returns True if the address is valid, false otherwise.
        */

    bool IsValid() const;

    /**
        Is this a loopback address?
        Corresponds to an IPv4 address of "127.0.0.1", or an IPv6 address of "::1".
        @returns True if this is the loopback address.
        */

    bool IsLoopback() const;

    /**
        Is this an IPv6 link local address?
        Corresponds to the first field of the address being 0xfe80
        @returns True if this address is a link local IPv6 address.
        */

    bool IsLinkLocal() const;

    /**
        Is this an IPv6 site local address?
        Corresponds to the first field of the address being 0xfec0
        @returns True if this address is a site local IPv6 address.
        */

    bool IsSiteLocal() const;

    /**
        Is this an IPv6 multicast address?
        Corresponds to the first field of the IPv6 address being 0xff00
        @returns True if this address is a multicast IPv6 address.
        */

    bool IsMulticast() const;

    /**
        Is this in IPv6 global unicast address?
        Corresponds to any IPv6 address that is not any of the following: Link Local, Site Local, Multicast or Loopback.
        @returns True if this is a global unicast IPv6 address.
        */

    bool IsGlobalUnicast() const;

    bool operator ==( const Address & other ) const;

    bool operator !=( const Address & other ) const;

protected:

    /**
        Helper function to parse an address string.
        Used by the constructors that take a string parameter.
        @param address The string to parse.
        */

    void Parse( const char * address );
};


#if YOJIMBO_PLATFORM == YOJIMBO_PLATFORM_WINDOWS

    #define NOMINMAX
    #define _WINSOCK_DEPRECATED_NO_WARNINGS
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <ws2ipdef.h>
    #pragma comment( lib, "WS2_32.lib" )

    #ifdef SetPort
    #undef SetPort
    #endif // #ifdef SetPort

#elif YOJIMBO_PLATFORM == YOJIMBO_PLATFORM_MAC || YOJIMBO_PLATFORM == YOJIMBO_PLATFORM_UNIX

    #include <netdb.h>
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <net/if.h>
    #include <fcntl.h>
    #include <netdb.h>
    #include <arpa/inet.h>
    #include <unistd.h>
    #include <errno.h>

#else

    #error yojimbo unknown platform!

#endif

#include <memory.h>
#include <string.h>

namespace yojimbo
{
    Address::Address()
    {
        Clear();
    }

    Address::Address( uint8_t a, uint8_t b, uint8_t c, uint8_t d, uint16_t port )
        : m_type( ADDRESS_IPV4 )
    {

        m_address.ipv4[0] = a;
        m_address.ipv4[1] = b;
        m_address.ipv4[2] = c;
        m_address.ipv4[3] = d;
        m_port = port;
    }

    Address::Address( const uint8_t address[], uint16_t port )
        : m_type( ADDRESS_IPV4 )
    {
        for ( int i = 0; i < 4; ++i )
            m_address.ipv4[i] = address[i];
        m_port = port;
    }

    Address::Address( uint16_t a, uint16_t b, uint16_t c, uint16_t d, uint16_t e, uint16_t f, uint16_t g, uint16_t h, uint16_t port )
        : m_type( ADDRESS_IPV6 )
    {
        m_address.ipv6[0] = a;
        m_address.ipv6[1] = b;
        m_address.ipv6[2] = c;
        m_address.ipv6[3] = d;
        m_address.ipv6[4] = e;
        m_address.ipv6[5] = f;
        m_address.ipv6[6] = g;
        m_address.ipv6[7] = h;
        m_port = port;
    }

    Address::Address( const uint16_t address[], uint16_t port )
        : m_type( ADDRESS_IPV6 )
    {
        for ( int i = 0; i < 8; ++i )
            m_address.ipv6[i] = address[i];
        m_port = port;
    }

    Address::Address( const char * address )
    {
        Parse( address );
    }

    Address::Address( const char * address, uint16_t port )
    {
        Parse( address );
        m_port = port;
    }

    void Address::Parse( const char * address_in )
    {
        // first try to parse as an IPv6 address:
        // 1. if the first character is '[' then it's probably an ipv6 in form "[addr6]:portnum"
        // 2. otherwise try to parse as raw IPv6 address, parse using inet_pton

        yojimbo_assert( address_in );

        char buffer[MaxAddressLength];
        char * address = buffer;
        yojimbo_copy_string( address, address_in, MaxAddressLength );

        int addressLength = (int) strlen( address );
        m_port = 0;
        if ( address[0] == '[' )
        {
            const int base_index = addressLength - 1;
            for ( int i = 0; i < 6; ++i )                 // note: no need to search past 6 characters as ":65535" is longest port value
            {
                const int index = base_index - i;
                if ( index < 3 )
                    break;
                if ( address[index] == ':' )
                {
                    m_port = uint16_t( atoi( &address[index + 1] ) );
                    address[index-1] = '\0';
                }
            }
            address += 1;
        }
        struct in6_addr sockaddr6;
        if ( inet_pton( AF_INET6, address, &sockaddr6 ) == 1 )
        {
            int i;
            for ( i = 0; i < 8; ++i )
            {
                m_address.ipv6[i] = ntohs( ( (uint16_t*) &sockaddr6 ) [i] );
            }
            m_type = ADDRESS_IPV6;
            return;
        }

        // otherwise it's probably an IPv4 address:
        // 1. look for ":portnum", if found save the portnum and strip it out
        // 2. parse remaining ipv4 address via inet_pton

        addressLength = (int) strlen( address );
        const int base_index = addressLength - 1;
        for ( int i = 0; i < 6; ++i )
        {
            const int index = base_index - i;
            if ( index < 0 )
                break;
            if ( address[index] == ':' )
            {
                m_port = (uint16_t) atoi( &address[index+1] );
                address[index] = '\0';
            }
        }

        struct sockaddr_in sockaddr4;
        if ( inet_pton( AF_INET, address, &sockaddr4.sin_addr ) == 1 )
        {
            m_type = ADDRESS_IPV4;
            m_address.ipv4[3] = (uint8_t) ( ( sockaddr4.sin_addr.s_addr & 0xFF000000 ) >> 24 );
            m_address.ipv4[2] = (uint8_t) ( ( sockaddr4.sin_addr.s_addr & 0x00FF0000 ) >> 16 );
            m_address.ipv4[1] = (uint8_t) ( ( sockaddr4.sin_addr.s_addr & 0x0000FF00 ) >> 8  );
            m_address.ipv4[0] = (uint8_t) ( ( sockaddr4.sin_addr.s_addr & 0x000000FF )       );
        }
        else
        {
            // Not a valid IPv4 address. Set address as invalid.
            Clear();
        }
    }

    void Address::Clear()
    {
        m_type = ADDRESS_NONE;
        memset( &m_address, 0, sizeof( m_address ) );
        m_port = 0;
    }

    const uint8_t * Address::GetAddress4() const
    {
        yojimbo_assert( m_type == ADDRESS_IPV4 );
        return m_address.ipv4;
    }

    const uint16_t * Address::GetAddress6() const
    {
        yojimbo_assert( m_type == ADDRESS_IPV6 );
        return m_address.ipv6;
    }

    void Address::SetPort( uint16_t port )
    {
        m_port = port;
    }

    uint16_t Address::GetPort() const
    {
        return m_port;
    }

    AddressType Address::GetType() const
    {
        return m_type;
    }

    const char * Address::ToString( char buffer[], int bufferSize ) const
    {
        yojimbo_assert( bufferSize >= MaxAddressLength );

        if ( m_type == ADDRESS_IPV4 )
        {
            const uint8_t a = m_address.ipv4[0];
            const uint8_t b = m_address.ipv4[1];
            const uint8_t c = m_address.ipv4[2];
            const uint8_t d = m_address.ipv4[3];
            if ( m_port != 0 )
                snprintf( buffer, bufferSize, "%d.%d.%d.%d:%d", a, b, c, d, m_port );
            else
                snprintf( buffer, bufferSize, "%d.%d.%d.%d", a, b, c, d );
            return buffer;
        }
        else if ( m_type == ADDRESS_IPV6 )
        {
            if ( m_port == 0 )
            {
                uint16_t address6[8];
                for ( int i = 0; i < 8; ++i )
                    address6[i] = ntohs( ((uint16_t*) &m_address.ipv6)[i] );
                inet_ntop( AF_INET6, address6, buffer, bufferSize );
                return buffer;
            }
            else
            {
                char addressString[INET6_ADDRSTRLEN];
                uint16_t address6[8];
                for ( int i = 0; i < 8; ++i )
                    address6[i] = ntohs( ((uint16_t*) &m_address.ipv6)[i] );
                inet_ntop( AF_INET6, address6, addressString, INET6_ADDRSTRLEN );
                snprintf( buffer, bufferSize, "[%s]:%d", addressString, m_port );
                return buffer;
            }
        }
        else
        {
            snprintf( buffer, bufferSize, "%s", "NONE" );
            return buffer;
        }
    }

    bool Address::IsValid() const
    {
        return m_type != ADDRESS_NONE;
    }

    bool Address::IsLinkLocal() const
    {
        return m_type == ADDRESS_IPV6 && m_address.ipv6[0] == 0xfe80;
    }

    bool Address::IsSiteLocal() const
    {
        return m_type == ADDRESS_IPV6 && m_address.ipv6[0] == 0xfec0;
    }

    bool Address::IsMulticast() const
    {
        return m_type == ADDRESS_IPV6 && m_address.ipv6[0] == 0xff00;
    }

    bool Address::IsLoopback() const
    {
        return ( m_type == ADDRESS_IPV4 && m_address.ipv4[0] == 127
                                        && m_address.ipv4[1] == 0
                                        && m_address.ipv4[2] == 0
                                        && m_address.ipv4[3] == 1 )
                                            ||
               ( m_type == ADDRESS_IPV6 && m_address.ipv6[0] == 0
                                        && m_address.ipv6[1] == 0
                                        && m_address.ipv6[2] == 0
                                        && m_address.ipv6[3] == 0
                                        && m_address.ipv6[4] == 0
                                        && m_address.ipv6[5] == 0
                                        && m_address.ipv6[6] == 0
                                        && m_address.ipv6[7] == 0x0001 );
    }

    bool Address::IsGlobalUnicast() const
    {
        return m_type == ADDRESS_IPV6 && m_address.ipv6[0] != 0xfe80
                                      && m_address.ipv6[0] != 0xfec0
                                      && m_address.ipv6[0] != 0xff00
                                      && !IsLoopback();
    }

    bool Address::operator ==( const Address & other ) const
    {
        if ( m_type != other.m_type )
            return false;
        if ( m_port != other.m_port )
            return false;
        if ( m_type == ADDRESS_IPV4 && memcmp( m_address.ipv4, other.m_address.ipv4, sizeof( m_address.ipv4 ) ) == 0 )
            return true;
        else if ( m_type == ADDRESS_IPV6 && memcmp( m_address.ipv6, other.m_address.ipv6, sizeof( m_address.ipv6 ) ) == 0 )
            return true;
        else
            return false;
    }

    bool Address::operator !=( const Address & other ) const
    {
        return !( *this == other );
    }
}
