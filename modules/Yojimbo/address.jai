#scope_module

AddressType :: enum u8 {
    None;  // Not an address. Set by the default constructor.
    IPv4;  // An IPv4 address, eg: "146.95.129.237"
    IPv6;  // An IPv6 address, eg: "48d9:4a08:b543:ae31:89d8:3226:b92c:cbba"
};

/*
An IP address and port number.

Supports both IPv4 and IPv6 addresses.
Identifies where a packet came from, and where a packet should be sent.
*/
Address :: struct {
    type: AddressType;  // The address type: IPv4 or IPv6.
    port: u16;          // The IP port. Valid for IPv4 and IPv6 address types. Local byte order.
    union {
        ipv4: [4] u8;   // IPv4 address data. Valid if type is ADDRESS_IPV4. Local byte order.
        ipv6: [8] u16;  // IPv6 address data. Valid if type is ADDRESS_IPV6. Local byte order.
    };
};

/*
Create an IPv4 address.

IMPORTANT: Pass in port in local byte order. The address class handles the conversion to network order for you.

@param a The first field of the IPv4 address.
@param b The second field of the IPv4 address.
@param c The third field of the IPv4 address.
@param d The fourth field of the IPv4 address.
@param port The IPv4 port (local byte order).
*/
address_create :: (a: u8, b: u8, c: u8, d: u8, port: u16 = 0) -> Address {
    address := Address.{
        type = .IPv4,
        ipv4[0] = a,
        ipv4[1] = b,
        ipv4[2] = c,
        ipv4[3] = d,
        port = port
    };
    return result;
}

/*
Create an IPv4 address.

@param address Array of four address fields for the IPv4 address.
@param port The port number (local byte order).
*/
address_create :: (ipv4_bytes: [4] u8, port: u16 = 0) -> Address {
    address := Address.{
        type = .IPv4,
        ipv4 = ipv4_bytes,
        port = port
    };
    return address;
}

/*
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
address_create :: (a: u16, b: u16, c: u16, d: u16, e: u16, f: u16, g: u16, h: u16, port: u16 = 0) -> Address {
    address := Address.{
        type = .IPv6,
        ipv6[0] = a,
        ipv6[1] = b,
        ipv6[2] = c,
        ipv6[3] = d,
        ipv6[4] = e,
        ipv6[5] = f,
        ipv6[6] = g,
        ipv6[7] = h,
        port = port
    };
    return address;
}

/*
Create an IPv6 address.
IMPORTANT: Pass in address fields and the port in local byte order. The address class handles the conversion to network order for you.

@param address Array of 8 16 bit address fields for the IPv6 address (local byte order).
@param port The IPv6 port (local byte order).
*/
address_create :: (ipv6_bytes: [8] u16, port: u16 = 0) -> Address {
    address := Address.{
        type = .IPv6,
        ipv6 = ipv6_bytes,
        port = port
    };
    return address;
}

/*
Parse a string to an address.
This versions supports parsing a port included in the address string. For example, "127.0.0.1:4000" and "[::1]:40000".
Parsing is performed via inet_pton once the port # has been extracted from the string, so you may specify any IPv4 or IPv6 address formatted in any valid way, and it should work as you expect.
Depending on the type of data in the string the address will become ADDRESS_TYPE_IPV4 or ADDRESS_TYPE_IPV6.
If the string is not recognized as a valid address, the address type is set to ADDRESS_TYPE_NONE, causing Address::IsValid to return false. Please check that after creating an address from a string.

@param address The string to parse to create the address.

@see Address::IsValid
@see Address::GetType
*/
address_create :: (address_str: string) -> Address {
    // first try to parse as an IPv6 address:
    // 1. if the first character is '[' then it's probably an ipv6 in form "[addr6]:portnum"
    // 2. otherwise try to parse as raw IPv6 address, parse using inet_pton

    address: Address;

    // I ported this logic.. but in hindsight, we should just always specify the port as its own parameter. Why complicate things?
    /*
    str := address_str;
    if address[0] == #char "[" {
        // Search bracketed IPv6 address for a port number (e.g. "[::1]:80").
        for 0..str.count-1 {
            if it == str.count-1 {
                if address[i] != #char "]" {
                    yojimbo_log(.ERROR, "IPv6 address starting with '[' must contain a closing bracket ']'.");
                    return address;
                }

                // '[' is the last character, no port follows. This is fine.
                break;
            }

            if address[it] == #char "]" {
                // End-of-address marker. The port should follow in ":80" format.
                it_delim = it + 1;  // index of ':' port delimiter
                it_port =  it + 2;  // index of first digit of port #

                // Check for weird cases to prevent out-of-bounds and provide a nicer error message.
                if address[it_delim] != #char ":" {
                    yojimbo_log(.ERROR, "Expected port delimiter ':', or nothing, after ']' in IPv6 address. Found '%' instead.", address[it_delim]);
                    return address;
                }
                if it_port >= str.count {
                    yojimbo_log(.ERROR, "Expected numeric port number to follow port delimiter ':'. Reached end of string instead.");
                    return address;
                }

                port_str := string.{ str.count - it_port, str.data + it_port };

                // Validate port only contains digits
                for 0..port_str.count-1 {
                    if !is_digit(address[it]) {
                        yojimbo_log(.ERROR, "Expected port number to contain digits. Found '%' instead.", port_str[it]);
                        return address;
                    }
                }

                // Attempt to parse port as integer
                port, success, remainder := to_integer(port_str);
                if !success {
                    yojimbo_log(.ERROR, "Failed to parse port string '%' as integer.", port_str);
                    return address;
                }
                if remainder.count {
                    yojimbo_log(.ERROR, "Successfully parsed port string '%' as integer '%', but there was unused trailing text '%'.", port_str, port, remainder);
                    return address;
                }
                if port <= 0 || port > 65535 {
                    yojimbo_log(.ERROR, "Successfully parsed port string '%' as integer '%', but the value was out of range (1-65535).", port_str, port);
                    return address;
                }

                // Wow.. we actually did it.
                address.port = cast (u16) port;
            }
        }
    }
    */
}

/*
Parse a string to an address.
This lets you parse "127.0.0.1" and "[::1]" and pass in the port you want programmatically.
Parsing is performed via inet_pton, so you may specify any IPv4 or IPv6 address formatted in any valid way, and it should work as you expect.
Depending on the type of data in the string the address will become ADDRESS_TYPE_IPV4 or ADDRESS_TYPE_IPV6.
If the string is not recognized as a valid address, the address type is set to ADDRESS_TYPE_NONE. Please check that after creating an address from a string.

@param address The string to parse to create the address.
@param port The port number.
*/
address_create :: (address: string, port: u16) -> Address {
    address: Address;

    struct in6_addr sockaddr6;
    if ( inet_pton( AF_INET6, str, &sockaddr6 ) == 1 )
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

// Convert the address to a string.
address_to_string :: (address: Address) -> string;

/*
Is this a loopback address?
Corresponds to an IPv4 address of "127.0.0.1", or an IPv6 address of "::1".

@returns True if this is the loopback address.
*/
address_is_loopback :: (address: Address) -> bool;

/*
Is this an IPv6 link local address?
Corresponds to the first field of the address being 0xfe80

@returns True if this address is a link local IPv6 address.
*/
address_is_link_local :: (address: Address) -> bool;

/*
Is this an IPv6 site local address?
Corresponds to the first field of the address being 0xfec0

@returns True if this address is a site local IPv6 address.
*/
address_is_site_local :: (address: Address) -> bool;

/*
Is this an IPv6 multicast address?
Corresponds to the first field of the IPv6 address being 0xff00

@returns True if this address is a multicast IPv6 address.
*/
address_is_multicast :: (address: Address) -> bool;

/*
Is this in IPv6 global unicast address?
Corresponds to any IPv6 address that is not any of the following: Link Local, Site Local, Multicast or Loopback.

@returns True if this is a global unicast IPv6 address.
*/
address_is_global_unicast :: (address: Address) -> bool;

/*
Check if two addresses are logically equivalent (same type, address and port).
*/
operator == :: (a: Address, b: Address) -> bool {
    if a.type != b.type return false;
    if a.port != b.port return false;
    if a.type == {
        case .IPv4;
            return array_equal(a.address.ipv4, b.address.ipv4);
        case .IPv6;
            return array_equal(a.address.ipv6, b.address.ipv6);
    }
    return false;
}

/*--------------------------------------------------------------------------------------------------------------------*/
                                                    #scope_file
/*--------------------------------------------------------------------------------------------------------------------*/

// #if YOJIMBO_PLATFORM == YOJIMBO_PLATFORM_WINDOWS

//     #define NOMINMAX
//     #define _WINSOCK_DEPRECATED_NO_WARNINGS
//     #include <winsock2.h>
//     #include <ws2tcpip.h>
//     #include <ws2ipdef.h>
//     #pragma comment( lib, "WS2_32.lib" )

//     #ifdef SetPort
//     #undef SetPort
//     #endif // #ifdef SetPort

// #elif YOJIMBO_PLATFORM == YOJIMBO_PLATFORM_MAC || YOJIMBO_PLATFORM == YOJIMBO_PLATFORM_UNIX

//     #include <netdb.h>
//     #include <sys/types.h>
//     #include <sys/socket.h>
//     #include <netinet/in.h>
//     #include <net/if.h>
//     #include <fcntl.h>
//     #include <netdb.h>
//     #include <arpa/inet.h>
//     #include <unistd.h>
//     #include <errno.h>

// #else

//     #error yojimbo unknown platform!

// #endif

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
