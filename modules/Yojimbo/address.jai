#scope_export

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
    port: u16;          // The IP port. Valid for IPv4 and IPv6 address types. Host byte order.
    union {
        ipv4: [4] u8;   // IPv4 address data. Valid if type is ADDRESS_IPV4. Network byte order.
        ipv6: [8] u16;  // IPv6 address data. Valid if type is ADDRESS_IPV6. Network byte order.
    };
};

/*
Create an IPv4 address.

IMPORTANT: Pass in port in Host byte order. The address class handles the conversion to network order for you.

@param a The first field of the IPv4 address.
@param b The second field of the IPv4 address.
@param c The third field of the IPv4 address.
@param d The fourth field of the IPv4 address.
@param port The IPv4 port (host byte order).
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
@param port The port number (host byte order).
*/
address_create :: (ipv4: [4] u8, port: u16 = 0) -> Address {
    address := Address.{
        type = .IPv4,
        ipv4 = ipv4,
        port = port
    };
    return address;
}

/*
Create an IPv6 address.
IMPORTANT: Pass in address fields and the port in host byte order. The address class handles the conversion to network order for you.

@param a First field of the IPv6 address (host byte order).
@param b Second field of the IPv6 address (host byte order).
@param c Third field of the IPv6 address (host byte order).
@param d Fourth field of the IPv6 address (host byte order).
@param e Fifth field of the IPv6 address (host byte order).
@param f Sixth field of the IPv6 address (host byte order).
@param g Seventh field of the IPv6 address (host byte order).
@param h Eighth field of the IPv6 address (host byte order).
@param port The port number (host byte order).
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
IMPORTANT: Pass in address fields and the port in host byte order. The address class handles the conversion to network order for you.

@param address Array of 8 16 bit address fields for the IPv6 address (host byte order).
@param port The IPv6 port (host byte order).
*/
address_create :: (ipv6: [8] u16, port: u16 = 0) -> Address {
    address := Address.{
        type = .IPv6,
        ipv6 = ipv6,
        port = port
    };
    return address;
}

/*
Converts a canonical IPv4 string (e.g. "127.0.0.1") to a network byte order array.

This function does not handle port numbers. It does return the remaining unused string after parsing an address,
though, so you can parse e.g. "127.0.0.1:80" and it will return an IPv4 Address + ":80" as the remainder string,
which you can parse yourself to retrieve the port number.

Implementation inspired by: https://git.musl-libc.org/cgit/musl/tree/src/network/inet_pton.c
*/
address_create_ipv4 :: (str: string, port: u16 = 0) -> result: Address, remainder: string {
    result := Address.{ type = .IPv4, port = port };

    octet_start := 0;
    for octet: 0..3 {
        digits := 0;
        value := 0;
        for 0..2 {
            if octet_start + digits == str.count
                break;

            c := str[octet_start + digits];
            if !is_digit(c)
                break;

            value *= 10;
            value += c - #char "0";
            digits += 1;
        }

        if digits == 0 {
            if octet_start == str.count {
                yojimbo_log(.ERROR, "Premature end-of-string in octet % while parsing '%' as IPv4 address. Expected digit (0-9).\n", octet + 1, str);
            } else {
                yojimbo_log(.ERROR, "Unexpected character '%' in octet % while parsing '%' as IPv4 address. Expected digit (0-9).\n", string.{ 1, str.data + octet_start }, octet + 1, str);
            }
            break;
        }
        if digits > 1 && str[octet_start] == #char "0" {
            // Note: Some tools (such as `ping` on Windows) will accept leading zeros and interpret the octect as
            // an octal (base-8) number. This seems exceptionally stupid and confusing to me, so let's just throw an error.
            yojimbo_log(.ERROR, "Illegal leading zero(s) in octet % ('%') while parsing '%' as IPv4 address.\n", octet + 1, string.{ digits, str.data + octet_start }, str);
            break;
        }
        if value > 255 {
            yojimbo_log(.ERROR, "Out-of-range value '%' in octet % ('%') while parsing '%' as IPv4 address. Expected octet in range (0-255).\n", value, octet + 1, string.{ digits, str.data + octet_start }, str);
            break;
        }

        result.ipv4[octet] = cast(u8) value;

        if octet == 3 {
            // Success!
            remainder := str;
            advance(*remainder, octet_start + digits);
            return result, remainder;
        }

        if octet_start + digits == str.count {
            yojimbo_log(.ERROR, "Premature end-of-string after octet % ('%') while parsing '%' as IPv4 address. Expected dot (.) separator.\n", octet + 1, string.{ digits, str.data + octet_start }, str);
            break;
        }
        if str[octet_start + digits] != #char "." {
            yojimbo_log(.ERROR, "Unexpected character '%' after octet % ('%') while parsing '%' as IPv4 address. Expected dot (.) separator.\n", string.{ 1, str.data + octet_start + digits }, octet + 1, string.{ digits, str.data + octet_start }, str);
            break;
        }
        octet_start += digits + 1;  // discard octet and dot separator
    }

    return .{}, str;
}

/*
Converts an IPv4 address to its corresponding IPv4-mapped IPv6 address.

For example, the string "127.0.0.1" can be converted to an IPv4 address by calling `string_to_ipv4`.
After checking for success, the resulting address can be passed into this function to convert it to an IPv6
address that is equivalent to the result of calling `string_to_ipv6("::FFFF:7F00:1")`, where 7F00:0001
is the hexademical representation of 127.0.0.1, and the preceding FFFF denotes an IPv4-mapped IPv6 address as
described in RFC 4291 Section 2.5.5.2 (https://datatracker.ietf.org/doc/html/rfc4291#section-2.5.5.2).
*/
address_ipv4_to_ipv6 :: (address: Address) -> result: Address {
    assert(address.type == .IPv4);

    if (address.type != .IPv4) {
        return .{};
    }

    result: Address;
    result.type = .IPv6;
    result.port = address.port;
    result.ipv6[5] = 0xFFFF;
    result.ipv6[6] = (cast(u16) address.ipv4[0]) << 8 | address.ipv4[1];
    result.ipv6[7] = (cast(u16) address.ipv4[2]) << 8 | address.ipv4[3];
    return result;
}

/*
Converts a canonical IPv6 string (e.g. "2001:db8:0000:0000:0000:0000:7777:8888") to a network byte order array.

We also handle the double-colon compression syntax for contiguous zeros; i.e."2001:db8::7777:8888" will result
in the same byte array as the full version of the address above.

We DO NOT handle IPv4-mapped IPv6 addresses in string format (e.g. "::ffff:127.0.0.1"). If you would like to create
such an address, call `string_to_ipv4` with the IPv4 string, check for success, then pass the resulting buffer of
bytes to `ipv4_to_ipv6` to create an IPv6 address.

Implementation inspired by: https://git.musl-libc.org/cgit/musl/tree/src/network/inet_pton.c
Some example IPv6 variants:

    2001:db8:0:0:1:0:0:1
    2001:0db8:0:0:1:0:0:1
    2001:db8::1:0:0:1
    2001:db8::0:1:0:0:1
    2001:0db8::1:0:0:1
    2001:db8:0:0:1::1
    2001:db8:0000:0:1::1
    2001:DB8:0:0:1::1

    See https://datatracker.ietf.org/doc/html/rfc5952#section-1 for more context.
*/
address_create_ipv6 :: (str: string, port: u16 = 0) -> result: Address, remainder: string {
    hexval :: (c: u8) -> int {
        if c == {
            case #char "0"; return 0;
            case #char "1"; return 1;
            case #char "2"; return 2;
            case #char "3"; return 3;
            case #char "4"; return 4;
            case #char "5"; return 5;
            case #char "6"; return 6;
            case #char "7"; return 7;
            case #char "8"; return 8;
            case #char "9"; return 9;
            case #char "A"; #through; case #char "a"; return 10;
            case #char "B"; #through; case #char "b"; return 11;
            case #char "C"; #through; case #char "c"; return 12;
            case #char "D"; #through; case #char "d"; return 13;
            case #char "E"; #through; case #char "e"; return 14;
            case #char "F"; #through; case #char "f"; return 15;
        }
        return -1;
    }

    s := str;
    result := Address.{ type = .IPv6, port = port };

    // Note: I'm calling double-colons, which eat an arbitrary number of IPv6 segments, the "worm" because they are
    // stretchy like a worm, force the parser to accept all kinds of garbage inputs (which I've dubbed "worm food"),
    // and can be represented as an emoji in discord via ":worm:" (which is what I imagine when I see a double colon
    // in an IPv6 address).
    //
    // And now, I present, the worm dance: "1111:2222:worm:6666:7777".
    worm_segment: int = -1;

    if s.count < 2 {
        yojimbo_log(.ERROR, "Unable to parse '%' as IPv6 address. Not enough characters.\n", str);
        return .{}, str;
    }

    if s[0] == #char ":" {
        if s[1] != #char ":" {
            yojimbo_log(.ERROR, "Unexpected character '%' while parsing '%' as IPv6 address. Addresses starting with a colon (:) must start with a double colon (::).\n", s[1], str);
            return .{}, str;
        }

        if s.count == 2 {
            // "::" is the IPv6 "unspecified address" (all zeros)
            return result, "";
        }

        // discard first colon of "::"
        advance(*s, 1);
    }

    segment := 0;
	while segment <= 7 {
		if s[0] == #char ":" && worm_segment < 0 {
			worm_segment = segment;
			result.ipv6[segment] = 0;

            // discard second colon of "::"
            advance(*s, 1);

            if segment == 7 {
                break;
            }
            segment += 1;
			continue;
		}

        digits := 0;
        value := 0;
        for 0..3 {
            if !s.count break;

            hex_value := hexval(s[0]);
            if hex_value < 0
                break;

            value *= 16;
            value += hex_value;

            digits += 1;
            advance(*s, 1);
        }

		if digits == 0 {
            if worm_segment >= 0 {
                // We're in :worm: mode, anything goes in :worm: mode.
                // Backtrack the last colon we read and assume it is part of the remainder string.
                s.data -= 1;
                s.count += 1;
                segment -= 1;
                break;
            }

            if !s.count {
                // ERROR: premature end of string before segment
                return .{}, str;
            } else {
                // ERROR: unexpected character in segment
                return .{}, str;
            }
        }

        result.ipv6[segment] = cast(u16) value;

        if segment == 7 {
            break;
        }

		if !s.count {
            if worm_segment >= 0 {
                // We reached a premature end-of-string, but the :worm: makes everything valid! It can stretch and fill
                // the gaps with its worm-like body.
                break;
            } else {
                // ERROR: Premature end-of-string after segment
                return .{}, str;
            }
        }

		if s[0] != #char ":" {
            if worm_segment >= 0 {
                // The next character isn't a delimiter, like we expect, but it's okay the :worm: is here to save the day!
                break;
            } else {
                //yojimbo_log(.ERROR, "Unexpected character '%' after octet % ('%') while parsing '%' as IPv4 address. Expected dot (.) separator.\n", string.{ 1, str.data + octet_start + digits }, octet + 1, string.{ digits, str.data + octet_start }, str);
                return .{}, str;
            }
            break;
        }

		advance(*s, 1);  // discard ':' separator
        segment += 1;
	}

    // Fill the :worm: hole with zeroes and shift the other segments accordingly
    // Note: If worm_segment is the last segment we read, we don't need to shift anything
    // (the code would work in that case, but why run it?)
	if worm_segment >= 0 && worm_segment < segment {
        // ::E:F | [0,E,F,0,0,0,0,0] -> [0:0:0:0:0:0:E:F] | worm_segment = 0, segment = 3
        // F::F  | [F,0,F,0,0,0,0,0] -> [F:0:0:0:0:0:0:F] | worm_segment = 1, segment = 3
        // F::   | [F,0,0,0,0,0,0,0] -> [F:0:0:0:0:0:0:0] | worm_segment = 1, segment = 2
        tail_start := worm_segment + 1;
        tail_length := segment - tail_start + 1;
        dest := 8 - tail_length;
        for < tail_length-1..0 {
            result.ipv6[dest + it] = result.ipv6[tail_start + it];
            result.ipv6[tail_start + it] = 0;
        }
	}

	return result, s;
}

/*
Converts the address to a human-readable string.
This does not include port, read that from the Address struct yourself if you want it.
This also doesn't collapse zeroes using :: syntax right now.
*/
address_to_string :: (address: Address, canonical := false) -> string {
    if address.type == {
        case .IPv4;
            a := address.ipv4[0];
            b := address.ipv4[1];
            c := address.ipv4[2];
            d := address.ipv4[3];

            builder: String_Builder;
            str := sprint("%.%.%.%", a, b, c, d);
            return str;
        case .IPv6;
            digits := ifx canonical then 4 else 1;
            words := cast,force([8] u16) address.ipv6;

            builder: String_Builder;
            print_to_builder(*builder, "%:%:%:%:%:%:%:%",
                formatInt(words[0], 16, digits),
                formatInt(words[1], 16, digits),
                formatInt(words[2], 16, digits),
                formatInt(words[3], 16, digits),
                formatInt(words[4], 16, digits),
                formatInt(words[5], 16, digits),
                formatInt(words[6], 16, digits),
                formatInt(words[7], 16, digits),
            );

            str := builder_to_string(*builder);
            return str;
        case;
            return "(ADDRESS_NONE)";
    }
}

/*
Is this a loopback address?
Corresponds to an IPv4 address of "127.*.*.*", or an IPv6 address of "::1".

@returns True if this is the loopback address.
*/
address_is_loopback :: (address: Address) -> bool {
    return (
        address.type == .IPv4
        && address.ipv4[0] == 127
    ) || (
        address.type == .IPv6
        && m_address.ipv6[0] == 0
        && m_address.ipv6[1] == 0
        && m_address.ipv6[2] == 0
        && m_address.ipv6[3] == 0
        && m_address.ipv6[4] == 0
        && m_address.ipv6[5] == 0
        && m_address.ipv6[6] == 0
        && m_address.ipv6[7] == 0x0001
    );
}

/*
Is this an IPv6 link local address?
Corresponds to the first field of the address being 0xfe80

@returns True if this address is a link local IPv6 address.
*/
address_is_link_local :: (address: Address) -> bool {
    assert(address.type == .IPv6);

    return address.type == .IPv6 && address.ipv6[0] == 0xfe80;
}

/*
Is this an IPv6 site local address?
Corresponds to the first field of the address being 0xfec0

@returns True if this address is a site local IPv6 address.
*/
address_is_site_local :: (address: Address) -> bool {
    assert(address.type == .IPv6);

    return address.type == .IPv6 && address.ipv6[0] == 0xfec0;
}

/*
Is this an IPv6 multicast address?
Corresponds to the first field of the IPv6 address being 0xff00

@returns True if this address is a multicast IPv6 address.
*/
address_is_multicast :: (address: Address) -> bool {
    assert(address.type == .IPv6);

    return address.type == .IPv6 && address.ipv6[0] == 0xff00;
}

/*
Is this in IPv6 global unicast address?
Corresponds to any IPv6 address that is not any of the following: Link Local, Site Local, Multicast or Loopback.

@returns True if this is a global unicast IPv6 address.
*/
address_is_global_unicast :: (address: Address) -> bool {
    assert(address.type == .IPv6);

    return address.type == .IPv6
        && !address_is_link_local(address)
        && !address_is_site_local(address)
        && !address_is_multicast(address)
        && !address_is_loopback(address);
}

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

#scope_file

#import "Basic";
