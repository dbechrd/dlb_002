/*
Native Jai port of Glenn Fiedler's "netcode" C library as of this commit:
https://github.com/mas-bandwidth/netcode/commit/3ffe69ad33416789bfb651bf687fdc619344e261

------------------------------------------------------------------------------------------------------------------------
| Original BSD-3 license
------------------------------------------------------------------------------------------------------------------------
    netcode

    Copyright © 2017 - 2024, Mas Bandwidth LLC

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

-----------------------------------------------------------------------------------------------------------------------
*/

#module_parameters(
    NETCODE_ENABLE_LOGGING := false
);

NETCODE_CONNECT_TOKEN_BYTES     :: 2048;
NETCODE_KEY_BYTES               :: 32;
NETCODE_MAC_BYTES               :: 16;
NETCODE_USER_DATA_BYTES         :: 256;
NETCODE_MAX_SERVERS_PER_CONNECT :: 32;

NETCODE_CLIENT_STATE_CONNECT_TOKEN_EXPIRED         :: -6;
NETCODE_CLIENT_STATE_INVALID_CONNECT_TOKEN         :: -5;
NETCODE_CLIENT_STATE_CONNECTION_TIMED_OUT          :: -4;
NETCODE_CLIENT_STATE_CONNECTION_RESPONSE_TIMED_OUT :: -3;
NETCODE_CLIENT_STATE_CONNECTION_REQUEST_TIMED_OUT  :: -2;
NETCODE_CLIENT_STATE_CONNECTION_DENIED             :: -1;
NETCODE_CLIENT_STATE_DISCONNECTED                  ::  0;
NETCODE_CLIENT_STATE_SENDING_CONNECTION_REQUEST    ::  1;
NETCODE_CLIENT_STATE_SENDING_CONNECTION_RESPONSE   ::  2;
NETCODE_CLIENT_STATE_CONNECTED                     ::  3;

NETCODE_MAX_CLIENTS     :: 256;
NETCODE_MAX_PACKET_SIZE :: 1200;

NETCODE_OK    :: 1;
NETCODE_ERROR :: 0;

NETCODE_ADDRESS_NONE :: 0;
NETCODE_ADDRESS_IPV4 :: 1;
NETCODE_ADDRESS_IPV6 :: 2;

netcode_init :: () -> int {
    assert(!netcode.initialized);

    if !socket_init() {
        return NETCODE_ERROR;
    }

    // TODO(dlb): We're ignoring Sodium for now.
    // if ( sodium_init() == -1 )
    //     return NETCODE_ERROR;

    netcode.initialized = true;
    return NETCODE_OK;
}

netcode_term :: () {
    assert(netcode.initialized);

    // TODO(dlb): Kill Socket here (though we can't actually do that because
    //            Socket doesn't have a term function that calls WSACleanup).

    netcode.initialized = false;
}

// ----------------------------------------------------------------

netcode_client_t :: struct {

}

netcode_client_config_t :: struct {
    network_simulator             : *netcode_network_simulator_t;
    callback_context              : *void;
    state_change_callback         : #type (*void, int, int);
    send_loopback_packet_callback : #type (*void, int, *u8, int, u64);
    override_send_and_receive     : int;
    send_packet_override          : #type (*void, *netcode_address_t, *u8, int);
    receive_packet_override       : #type (*void, *netcode_address_t, *u8, int) -> int;
};

netcode_default_client_config :: (config: *netcode_client_config_t) {

}

netcode_client_create :: (address: string, config: *netcode_client_config_t, time: Apollo_Time) -> *netcode_client_t {

}

netcode_client_destroy :: (client: *netcode_client_t) {

}

netcode_client_connect :: (client: *netcode_client_t, connect_token: *u8) {

}

netcode_client_update :: (client: *netcode_client_t, time: Apollo_Time) {

}

netcode_client_next_packet_sequence :: (client: *netcode_client_t) -> u64 {

}

netcode_client_send_packet :: (client: *netcode_client_t, packet_data: *u8, packet_bytes: int) {

}

netcode_client_receive_packet :: (client: *netcode_client_t, packet_bytes: *int, packet_sequence: *u64) -> *u8 {

}

netcode_client_free_packet :: (client: *netcode_client_t, packet: *void) {

}

netcode_client_disconnect :: (client: *netcode_client_t) {

}

netcode_client_state :: (client: *netcode_client_t) -> int {

}

netcode_client_index :: (client: *netcode_client_t) -> int {

}

netcode_client_max_clients :: (client: *netcode_client_t) -> int {

}

netcode_client_connect_loopback :: (client: *netcode_client_t, client_index: int, max_clients: int) {

}

netcode_client_disconnect_loopback :: (client: *netcode_client_t) {

}

netcode_client_process_packet :: (client: *netcode_client_t, from: *netcode_address_t, packet_data: *u8, packet_bytes: int) {

}

netcode_client_loopback :: (client: *netcode_client_t) -> int {

}

netcode_client_process_loopback_packet :: (client: *netcode_client_t, packet_data: *u8, packet_bytes: int, packet_sequence: u64) {

}

netcode_client_get_port :: (client: *netcode_client_t) -> u16 {

}

netcode_client_server_address :: (client: *netcode_client_t) -> *netcode_address_t {

}

netcode_generate_connect_token :: (
    num_server_addresses      : int,
    public_server_addresses   : [] string,
    internal_server_addresses : [] string,
    expire_seconds            : int,
    timeout_seconds           : int,
    client_id                 : u64,
    protocol_id               : u64,
    private_key               : *u8,
    user_data                 : *u8,
    connect_token             : *u8
) -> int {

}

// ----------------------------------------------------------------

netcode_server_t :: struct {

}

netcode_server_config_t :: struct {
    protocol_id                   : u64;
    private_key                   : [NETCODE_KEY_BYTES] u8;
    network_simulator             : *netcode_network_simulator_t;
    callback_context              : *void;
    connect_disconnect_callback   : #type (*void, int, int);
    send_loopback_packet_callback : #type (*void, int, *u8, int, u64);
    override_send_and_receive     : int;
    send_packet_override          : #type (*void, *netcode_address_t, *u8, int);
    receive_packet_override       : #type (*void, *netcode_address_t, *u8, int) -> int;
};

netcode_default_server_config :: (config: *netcode_server_config_t) {
    // TODO(dlb): Move this to the struct if possible
}

netcode_server_create :: (server_address: string, config: *netcode_server_config_t, time: Apollo_Time) -> *netcode_server_t {

}

netcode_server_destroy :: (server: *netcode_server_t) {

}

netcode_server_start :: (server: *netcode_server_t, max_clients: int) {

}

netcode_server_stop :: (server: *netcode_server_t) {

}

netcode_server_running :: (server: *netcode_server_t) -> int {

}

netcode_server_max_clients :: (server: *netcode_server_t) -> int {

}

netcode_server_update :: (server: *netcode_server_t, time: Apollo_Time) {

}

netcode_server_client_connected :: (server: *netcode_server_t, client_index: int) -> int {

}

netcode_server_client_id :: (server: *netcode_server_t, client_index: int) -> u64 {

}

netcode_server_client_address :: (server: *netcode_server_t, client_index: int) -> *netcode_address_t {

}

netcode_server_disconnect_client :: (server: *netcode_server_t, client_index: int) {

}

netcode_server_disconnect_all_clients :: (server: *netcode_server_t) {

}

netcode_server_next_packet_sequence :: (server: *netcode_server_t, client_index: int) -> u64 {

}

netcode_server_send_packet :: (server: *netcode_server_t, client_index: int, packet_data: *u8, packet_bytes: int) {

}

netcode_server_receive_packet :: (server: *netcode_server_t, client_index: int, packet_bytes: *int, packet_sequence: *u64) -> *u8 {

}

netcode_server_free_packet :: (server: *netcode_server_t, packet: *void) {

}

netcode_server_num_connected_clients :: (server: *netcode_server_t) -> int {

}

netcode_server_client_user_data :: (server: *netcode_server_t, client_index: int) -> *void {

}

netcode_server_process_packet :: (server: *netcode_server_t, from: *netcode_address_t, packet_data: *u8, packet_bytes: int) {

}

netcode_server_connect_loopback_client :: (server: *netcode_server_t, client_index: int, client_id: u64, user_data: *u8) {

}

netcode_server_disconnect_loopback_client :: (server: *netcode_server_t, client_index: int) {

}

netcode_server_client_loopback :: (server: *netcode_server_t, client_index: int) -> int {

}

netcode_server_process_loopback_packet :: (server: *netcode_server_t, client_index: int, packet_data: *u8, packet_bytes: int, packet_sequence: u64) {

}

netcode_server_get_port :: (server: *netcode_server_t) -> u16  {

}

netcode_network_simulator_t :: struct {

}

#scope_file

#import "Basic";
#import "Socket";
#import "dlb";

NETCODE_SOCKET_IPV6 :: 1;
NETCODE_SOCKET_IPV4 :: 2;

NETCODE_CONNECT_TOKEN_PRIVATE_BYTES   :: 1024;
NETCODE_CONNECT_TOKEN_NONCE_BYTES     :: 24;
NETCODE_CHALLENGE_TOKEN_BYTES         :: 300;
NETCODE_CHALLENGE_TOKEN_NONCE_BYTES   :: 12;
NETCODE_VERSION_INFO_BYTES            :: 13;
NETCODE_MAX_PACKET_BYTES              :: 1300;
NETCODE_MAX_PAYLOAD_BYTES             :: 1200;
NETCODE_MAX_ADDRESS_STRING_LENGTH     :: 256;
NETCODE_PACKET_QUEUE_SIZE             :: 256;
NETCODE_REPLAY_PROTECTION_BUFFER_SIZE :: 256;
NETCODE_CLIENT_MAX_RECEIVE_PACKETS    :: 64;
NETCODE_SERVER_MAX_RECEIVE_PACKETS    :: 64 * NETCODE_MAX_CLIENTS;
NETCODE_CLIENT_SOCKET_SNDBUF_SIZE     :: 256 * 1024;
NETCODE_CLIENT_SOCKET_RCVBUF_SIZE     :: 256 * 1024;
NETCODE_SERVER_SOCKET_SNDBUF_SIZE     :: 4 * 1024 * 1024;
NETCODE_SERVER_SOCKET_RCVBUF_SIZE     :: 4 * 1024 * 1024;

NETCODE_VERSION_INFO           :: "NETCODE 1.02";
NETCODE_PACKET_SEND_RATE       :: 10.0;
NETCODE_NUM_DISCONNECT_PACKETS :: 10;

NETCODE_ADDRESS_MAP_BUCKETS :: NETCODE_MAX_CLIENTS;

// ----------------------------------------------------------------

EncryptionKeyBuf  :: [NETCODE_KEY_BYTES] u8;
ConnectTokenBuf   :: [NETCODE_CONNECT_TOKEN_PRIVATE_BYTES] u8;
BigNonceBuf       :: [NETCODE_CONNECT_TOKEN_NONCE_BYTES] u8;    // use big nonce for when you don't have a sequential number (random bytes; bigger to reduce collisions)
ChallengeTokenBuf :: [NETCODE_CHALLENGE_TOKEN_BYTES] u8;
NonceBuf          :: [NETCODE_CHALLENGE_TOKEN_NONCE_BYTES] u8;  // use regular nonce when you have a sequential number
VerionInfoBuf     :: [NETCODE_VERSION_INFO_BYTES] u8;
UserDataBuf       :: [NETCODE_USER_DATA_BYTES] u8;

// ----------------------------------------------------------------

netcode_t :: struct {
    initialized: bool;
};

netcode :: netcode_t;

netcode_log :: (flags: Log_Flags, format_string: string, args: .. Any, loc := #caller_location) {
    #if NETCODE_ENABLE_LOGGING {
        log(format_string, ..args, loc, flags,, temp);
    }
}

// ----------------------------------------------------------------

netcode_address_t :: struct {
    data :: union {
        ipv4: [4] u8;
        ipv6: [8] u16;
    };
    port: u16;
    type: u8;
};

netcode_parse_address :: (address_string_in: string, address: *netcode_address_t) -> int {
    // TODO(dlb): Implement this via yojimbo.address
    assert(false, "Not implemented");
}

netcode_address_to_string :: (address: *netcode_address_t) -> string {
    // TODO(dlb): Implement this via yojimbo.address
    assert(false, "Not implemented");
}

netcode_address_equal :: (a: *netcode_address_t, b: *netcode_address_t) -> int {
    // TODO(dlb): Implement this via yojimbo.address
    assert(false, "Not implemented");
}

// ----------------------------------------------------------------

netcode_socket_t :: struct {
    handle: Socket;
    address: netcode_address_t;
}

netcode_socket_holder_t :: struct {
    ipv4: netcode_socket_t;
    ipv6: netcode_socket_t;
};

NETCODE_SOCKET_ERROR_NONE                     :: 0;
NETCODE_SOCKET_ERROR_CREATE_FAILED            :: 1;
NETCODE_SOCKET_ERROR_SET_NON_BLOCKING_FAILED  :: 2;
NETCODE_SOCKET_ERROR_SOCKOPT_IPV6_ONLY_FAILED :: 3;
NETCODE_SOCKET_ERROR_SOCKOPT_RCVBUF_FAILED    :: 4;
NETCODE_SOCKET_ERROR_SOCKOPT_SNDBUF_FAILED    :: 5;
NETCODE_SOCKET_ERROR_BIND_IPV4_FAILED         :: 6;
NETCODE_SOCKET_ERROR_BIND_IPV6_FAILED         :: 7;
NETCODE_SOCKET_ERROR_GET_SOCKNAME_IPV4_FAILED :: 8;
NETCODE_SOCKET_ERROR_GET_SOCKNAME_IPV6_FAILED :: 9;

netcode_socket_destroy :: (socket: *netcode_socket_t) {
    assert(socket != null);
    assert(netcode.initialized);

    close_and_reset(*socket.handle);
}

netcode_socket_create :: (s: *netcode_socket_t, address: *netcode_address_t, send_buffer_size: s32, receive_buffer_size: s32) -> int {
    assert(s != null);
    assert(address != null);
    assert(netcode.initialized);

    assert(address.type != NETCODE_ADDRESS_NONE);
    s.address = address.*;

    // create socket
    addressFamily := ifx address.type == NETCODE_ADDRESS_IPV6 then AF_INET6 else AF_INET;
    s.handle = socket(addressFamily, SOCK.DGRAM, IPPROTO.UDP);

    if s.handle == INVALID_SOCKET {
        netcode_log(.ERROR, "error: failed to create socket\n");
        return NETCODE_SOCKET_ERROR_CREATE_FAILED;
    }

    // IMPORTANT: tell windows we don't want to receive any connection reset messages
    // for this socket, otherwise recvfrom errors out when client sockets disconnect hard
    // in response to ICMP messages.
    #if OS == .WINDOWS {
        SIO_UDP_CONNRESET :: 0x9800000C; //_WSAIOW(IOC_VENDOR, 12)
        bNewBehavior: s32 = 0;  // Win32 BOOL false
        dwBytesReturned: u32 = 0;  // Win32 DWORD
        result := WSAIoctl(s.handle, SIO_UDP_CONNRESET, *bNewBehavior, size_of(type_of(bNewBehavior)), null, 0, *dwBytesReturned, null, null);
        if result != 0 {
            error_code := get_last_socket_error();
            error_string := System.get_error_string(error_code);
            netcode_log(.WARNING, "warning: Couldn’t set keep-alive values for socket %: % %", s, error_code, error_string);
            return false;
        }
    }

    // force IPv6 only if necessary

    if address.type == NETCODE_ADDRESS_IPV6 {
        yes: s32 = 1;  // Win32 BOOL
        if setsockopt(s.handle, IPPROTO_IPV6, IPV6_V6ONLY, cast(*void) *yes, size_of(s32)) != 0 {
            netcode_log(.ERROR, "error: failed to set socket ipv6 only\n");
            netcode_socket_destroy(s);
            return NETCODE_SOCKET_ERROR_SOCKOPT_IPV6_ONLY_FAILED;
        }
    }

    // increase socket send and receive buffer sizes

    if setsockopt(s.handle, SOL_SOCKET, SO_SNDBUF, cast(*void) *send_buffer_size, size_of(s32)) != 0 {
        netcode_log(.ERROR, "error: failed to set socket send buffer size\n");
        netcode_socket_destroy(s);
        return NETCODE_SOCKET_ERROR_SOCKOPT_SNDBUF_FAILED;
    }

    if setsockopt(s.handle, SOL_SOCKET, SO_RCVBUF, cast(*void) *receive_buffer_size, size_of(s32)) != 0 {
        netcode_log(.ERROR, "error: failed to set socket receive buffer size\n");
        netcode_socket_destroy(s);
        return NETCODE_SOCKET_ERROR_SOCKOPT_RCVBUF_FAILED;
    }

    // bind to port
    if address.type == NETCODE_ADDRESS_IPV6 {
        // TODO(dlb): Is this correct?
        addr: [16] u8 = (cast(*[16] u8) address.data.ipv6.data).*;
        if bind(s.handle, .{ 16, address.data.ipv6.data }, address.port) < 0 {
            netcode_log(.ERROR, "error: failed to bind socket (ipv6)\n");
            netcode_socket_destroy(s);
            return NETCODE_SOCKET_ERROR_BIND_IPV6_FAILED;
        }
    } else {
        // TODO(dlb): Is this correct?
        addr: u32 = (cast(*u32) address.data.ipv4.data).*;
        if bind(s.handle, addr, address.port) < 0 {
            netcode_log(.ERROR, "error: failed to bind socket (ipv4)\n");
            netcode_socket_destroy(s);
            return NETCODE_SOCKET_ERROR_BIND_IPV4_FAILED;
        }
    }

    // if bound to port 0 find the actual port we got
    if address.port == 0 {
        if address.type == NETCODE_ADDRESS_IPV6 {
            sin: sockaddr_in6;
            len: socklen_t = size_of(sin);
            if getsockname(s.handle, cast(*sockaddr) *sin, *len) == -1 {
                netcode_log(.ERROR, "error: failed to get socket port (ipv6)\n");
                netcode_socket_destroy(s);
                return NETCODE_SOCKET_ERROR_GET_SOCKNAME_IPV6_FAILED;
            }
            s.address.port = ntohs(sin.sin6_port);
        } else {
            sin: sockaddr_in;
            len: socklen_t = sizeof(sin);
            if getsockname(s.handle, cast(*sockaddr) *sin, *len) == -1 {
                netcode_log(.ERROR, "error: failed to get socket port (ipv4)\n");
                netcode_socket_destroy(s);
                return NETCODE_SOCKET_ERROR_GET_SOCKNAME_IPV4_FAILED;
            }
            s.address.port = ntohs(sin.sin_port);
        }
    }

    // set non-blocking io
    set_blocking(socket.handle, false);

    return NETCODE_SOCKET_ERROR_NONE;
}

netcode_socket_send_packet :: (socket: *netcode_socket_t, to: *netcode_address_t, packet_data: [] u8) -> bool {
    assert(socket != null);
    assert(socket.handle != 0);
    assert(to != null);
    assert(to.type == NETCODE_ADDRESS_IPV6 || to.type == NETCODE_ADDRESS_IPV4);
    assert(packet_data.count > 0);

    if to.type == NETCODE_ADDRESS_IPV6 {
        socket_address: sockaddr_in6;
        socket_address.sin6_family = AF_INET6;
        for 0..7 {
            (cast(*u16) *socket_address.sin6_addr)[it] = htons(to.data.ipv6[i]);
        }
        socket_address.sin6_port = htons(to.port);
        result := sendto(socket.handle, packet_data.data, cast(s32) packet_data.count, 0, cast(*sockaddr) *socket_address, size_of(sockaddr_in6));
        if result == SOCKET_ERROR {
            netcode_log(.ERROR, "error: failed send packet (ipv6)\n");
            return false;
        }
    } else if to.type == NETCODE_ADDRESS_IPV4 {
        socket_address: sockaddr_in;
        socket_address.sin_family = AF_INET;
        socket_address.sin_addr.s_addr = ((cast(u32) to.data.ipv4[0])      ) |
                                         ((cast(u32) to.data.ipv4[1]) << 8 ) |
                                         ((cast(u32) to.data.ipv4[2]) << 16) |
                                         ((cast(u32) to.data.ipv4[3]) << 24);
        socket_address.sin_port = htons(to.port);
        result := sendto(socket.handle, packet_data.data, packet_data.count, 0, cast(*sockaddr) *socket_address, size_of(sockaddr_in));
        if result == SOCKET_ERROR {
            netcode_log(.ERROR, "error: failed send packet (ipv4)\n");
            return false;
        }
    }

    return true;
}

netcode_socket_receive_packet :: (socket: *netcode_socket_t, from: *netcode_address_t, packet_data: [] u8) -> [] u8 {
    assert(socket != null);
    assert(socket.handle != 0);
    assert(from != null);
    assert(packet_data.count > 0);

    #if NETCODE_PLATFORM == NETCODE_PLATFORM_WINDOWS {
        socklen_t :: int;
    }

    sockaddr_from: sockaddr_storage;
    from_length: socklen_t = cast(socklen_t) size_of(sockaddr_from);

    result := recvfrom(socket.handle, packet_data.data, packet_data.count, 0, cast(*sockaddr) *sockaddr_from, *from_length);
    if result == SOCKET_ERROR {
        error := get_last_socket_error();
        if error == SOCKET_WOULDBLOCK {
            return 0;
        }

        netcode_log(.ERROR, "error: recvfrom failed with error %\n", error);
        return 0;
    }

    if sockaddr_from.ss_family == AF_INET6 {
        addr_ipv6 := cast(*sockaddr_in6) *sockaddr_from;
        from.type = NETCODE_ADDRESS_IPV6;
        for 0..7 {
            from.data.ipv6[it] = ntohs((cast(*u16) *addr_ipv6.sin6_addr)[it]);
        }
        from.port = ntohs(addr_ipv6.sin6_port);
    } else if sockaddr_from.ss_family == AF_INET {
        addr_ipv4 := cast(*sockaddr_in) *sockaddr_from;
        from.type = NETCODE_ADDRESS_IPV4;
        from.data.ipv4[0] = cast(uint8_t) ((addr_ipv4.sin_addr.s_addr & 0x000000FF)      );
        from.data.ipv4[1] = cast(uint8_t) ((addr_ipv4.sin_addr.s_addr & 0x0000FF00) >> 8 );
        from.data.ipv4[2] = cast(uint8_t) ((addr_ipv4.sin_addr.s_addr & 0x00FF0000) >> 16);
        from.data.ipv4[3] = cast(uint8_t) ((addr_ipv4.sin_addr.s_addr & 0xFF000000) >> 24);
        from.port = ntohs(addr_ipv4.sin_port);
    } else {
        assert(false, "Invalid address family");
        return 0;
    }

    assert(result >= 0);
    return .{ bytes_read, packet_data.data };
}

// ----------------------------------------------------------------

netcode_write_uint8 :: (p: **u8, value: u8) {
    p.*.* = value;
    p.* += 1;
}

netcode_write_uint16 :: (p: **u8, value: u16) {
    (p.*)[0] = value & 0xFF;
    (p.*)[1] = value >> 8;
    p.* += 2;
}

netcode_write_uint32 :: (p: **u8, value: u32) {
    (p.*)[0] = value & 0xFF;
    (p.*)[1] = (value >> 8 ) & 0xFF;
    (p.*)[2] = (value >> 16) & 0xFF;
    (p.*)[3] = value >> 24;
    p.* += 4;
}

netcode_write_uint64 :: (p: **u8, value: u64) {
    (p.*)[0] = value & 0xFF;
    (p.*)[1] = (value >> 8 ) & 0xFF;
    (p.*)[2] = (value >> 16) & 0xFF;
    (p.*)[3] = (value >> 24) & 0xFF;
    (p.*)[4] = (value >> 32) & 0xFF;
    (p.*)[5] = (value >> 40) & 0xFF;
    (p.*)[6] = (value >> 48) & 0xFF;
    (p.*)[7] = value >> 56;
    p.* += 8;
}

netcode_write_bytes :: (p: **u8, byte_array: [] u8) {
    for byte_array {
        netcode_write_uint8(p, it);
    }
}

netcode_read_uint8 :: (p: **u8) -> u8 {
    value: u8 = p.*.*;
    p.* += 1;
    return value;
}

netcode_read_uint16 :: (p: **u8) -> u16 {
    value: u16 = (p.*)[0];
    value |= (cast(u16) ((p.*)[1])) << 8;
    p.* += 2;
    return value;
}

netcode_read_uint32 :: (p: **u8) -> u32 {
    value: u32 = (p.*)[0];
    value |= (cast(u32) ((p.*)[1])) << 8;
    value |= (cast(u32) ((p.*)[2])) << 16;
    value |= (cast(u32) ((p.*)[3])) << 24;
    p.* += 4;
    return value;
}

netcode_read_uint64 :: (p: **u8) -> u64 {
    value: u64 = (p.*)[0];
    value |= (cast(u64) ((p.*)[1])) << 8;
    value |= (cast(u64) ((p.*)[2])) << 16;
    value |= (cast(u64) ((p.*)[3])) << 24;
    value |= (cast(u64) ((p.*)[4])) << 32;
    value |= (cast(u64) ((p.*)[5])) << 40;
    value |= (cast(u64) ((p.*)[6])) << 48;
    value |= (cast(u64) ((p.*)[7])) << 56;
    p.* += 8;
    return value;
}

netcode_read_bytes :: (p: **u8, byte_array: [] u8) {
    for * byte_array {
        it.* = netcode_read_uint8(p);
    }
}

// ----------------------------------------------------------------
// TODO(dlb): Don't pretend to encrypt important data?
// HACK(dlb): !!! INSECURE / FAKE / BAD / DANGEROUS !!!
// Sodium placeholders to avoid the dependency while porting
// ----------------------------------------------------------------

// TODO(dlb): This should be crypto random
randombytes_buf :: (buf: [] u8) {
    for 0..buf.count-1 {
        buf[it] = it % buf.count;
    }
}

crypto_aead_xchacha20poly1305_ietf_encrypt :: (
    c      : *u8,   // [out] encrypted
    clen_p : *u64,  // [out] encrypted length
    m      : *u8,   // [in] plaintext
    mlen   : u64,   // [in] plaintext length
    ad     : *u8,   // [in] additional data
    adlen  : u64,   // [in] additional data length
    nsec   : *u8,   // [in] secret nonce
    npub   : *u8,   // [in] public nonce
    k      : *u8    // [in] key
) -> int {
    return 0;
}

crypto_aead_xchacha20poly1305_ietf_decrypt :: (
    m      : *u8,   // [out] plaintext
    mlen_p : *u64,  // [out] plaintext length
    nsec   : *u8,   // [in] secret nonce
    c      : *u8,   // [in] encrypted
    clen   : u64,   // [in] encrypted length
    ad     : *u8,   // [in] additional data
    adlen  : u64,   // [in] additional data length
    npub   : *u8,   // [in] public nonce
    k      : *u8    // [in] key
) -> int {
    return 0;
}

// NOTE: These are different in the real implementation, but their arguments are the same so we can re-use the placeholders
crypto_aead_chacha20poly1305_ietf_encrypt :: crypto_aead_xchacha20poly1305_ietf_encrypt;
crypto_aead_chacha20poly1305_ietf_decrypt :: crypto_aead_xchacha20poly1305_ietf_decrypt;

// ----------------------------------------------------------------

netcode_generate_key :: (key: EncryptionKeyBuf) {
    randombytes_buf(key);
}

netcode_generate_nonce :: (nonce: BigNonceBuf) {
    randombytes_buf(nonce);
}

// the nonce here is expected to be random bytes which differ for each message
netcode_encrypt_aead_bignonce :: (message: [] u8, header: [] u8, nonce: BigNonceBuf, key: EncryptionKeyBuf) -> int {
    encrypted_length: u64;

    result := crypto_aead_xchacha20poly1305_ietf_encrypt(
        message.data, *encrypted_length,
        message.data, message.count,
        header.data, header.count,
        null,
        nonce, key
    );

    if result != 0 {
        return NETCODE_ERROR;
    }

    assert(encrypted_length == message.count + NETCODE_MAC_BYTES);
    return NETCODE_OK;
}

// the nonce here is expected to be random bytes which differ for each message
netcode_decrypt_aead_bignonce :: (message: [] u8, header: [] u8, nonce: BigNonceBuf, key: EncryptionKeyBuf) -> int {
    decrypted_length: u64;

    result := crypto_aead_xchacha20poly1305_ietf_decrypt(
        message.data, *decrypted_length,
        null,
        message.data, message.count,
        header.data, header.count,
        nonce, key
    );

    if result != 0 {
        return NETCODE_ERROR;
    }

    assert(decrypted_length == message.count - NETCODE_MAC_BYTES);
    return NETCODE_OK;
}

// the nonce here is expected to sequential for each message
netcode_encrypt_aead :: (message: [] u8, header: [] u8, nonce: NonceBuf, key: EncryptionKeyBuf) -> int {
    encrypted_length: u64;

    result := crypto_aead_chacha20poly1305_ietf_encrypt(
        message.data, *encrypted_length,
        message.data, message.count,
        header.data, header.count,
        null,
        nonce, key
    );

    if result != 0 {
        return NETCODE_ERROR;
    }

    assert(encrypted_length == message.count + NETCODE_MAC_BYTES);
    return NETCODE_OK;
}

// the nonce here is expected to sequential for each message
netcode_decrypt_aead :: (message: [] u8, header: [] u8, nonce: NonceBuf, key: EncryptionKeyBuf) -> int {
    decrypted_length: u64;

    result := crypto_aead_chacha20poly1305_ietf_decrypt(
        message.data, *decrypted_length,
        null,
        message.data, message.count,
        header.data, header.count,
        nonce, key
    );

    if result != 0 {
        return NETCODE_ERROR;
    }

    assert(decrypted_length == message.count - NETCODE_MAC_BYTES);
    return NETCODE_OK;
}

// ----------------------------------------------------------------

netcode_connect_token_private_t :: struct {
    client_id            : u64;
    timeout_seconds      : int;
    num_server_addresses : int;
    server_addresses     : [NETCODE_MAX_SERVERS_PER_CONNECT] netcode_address_t;
    client_to_server_key : EncryptionKeyBuf;
    server_to_client_key : EncryptionKeyBuf;
    user_data            : UserDataBuf;
};

netcode_generate_connect_token_private :: (connect_token: *netcode_connect_token_private_t, client_id: u64, timeout_seconds: int, server_addresses: [] netcode_address_t, user_data: *UserDataBuf) {
    assert(connect_token != null);
    assert(server_addresses.count > 0);
    assert(server_addresses.count <= NETCODE_MAX_SERVERS_PER_CONNECT);
    assert(user_data != null);

    connect_token.client_id = client_id;
    connect_token.timeout_seconds = timeout_seconds;
    connect_token.num_server_addresses = server_addresses.count;

    for server_addresses {
        connect_token.server_addresses[it_index] = it;
    }

    netcode_generate_key(connect_token.client_to_server_key);
    netcode_generate_key(connect_token.server_to_client_key);

    if user_data != null {
        connect_token.user_data = user_data.*;
    }
}

netcode_write_connect_token_private :: (connect_token: *netcode_connect_token_private_t, token_buffer: ConnectTokenBuf) {
    assert(connect_token != null);
    assert(connect_token.num_server_addresses > 0);
    assert(connect_token.num_server_addresses <= NETCODE_MAX_SERVERS_PER_CONNECT);

    start := token_buffer.data;
    ptr := token_buffer.data;

    netcode_write_uint64(*ptr, connect_token.client_id);
    netcode_write_uint32(*ptr, connect_token.timeout_seconds);
    netcode_write_uint32(*ptr, connect_token.num_server_addresses);

    for address: connect_token.server_addresses {
        if address.type == NETCODE_ADDRESS_IPV4 {
            netcode_write_uint8(*ptr, NETCODE_ADDRESS_IPV4);
            for 0..3 {
                netcode_write_uint8(*ptr, address.data.ipv4[it]);
            }
            netcode_write_uint16(*ptr, address.port);
        } else if address.type == NETCODE_ADDRESS_IPV6 {
            netcode_write_uint8(*ptr, NETCODE_ADDRESS_IPV6);
            for 0..7 {
                netcode_write_uint16(*ptr, address.data.ipv6[it]);
            }
            netcode_write_uint16(*ptr, address.port);
        } else {
            assert(false, "Invalid address type");
        }
    }

    netcode_write_bytes(*ptr, connect_token.client_to_server_key);
    netcode_write_bytes(*ptr, connect_token.server_to_client_key);
    netcode_write_bytes(*ptr, connect_token.user_data);

    assert(pointer_diff(ptr, start) <= NETCODE_CONNECT_TOKEN_PRIVATE_BYTES - NETCODE_MAC_BYTES);
}

netcode_encrypt_connect_token_private :: (token_buffer: ConnectTokenBuf, version_info: VerionInfoBuf, protocol_id: u64, expire_timestamp: u64, none: BigNonceBuf, key: EncryptionKeyBuf) -> int {
    additional_data: [version_info.count + 8 + 8] u8;
    {
        ptr := additional_data.data;
        netcode_write_bytes(*ptr, version_info);
        netcode_write_uint64(*ptr, protocol_id);
        netcode_write_uint64(*ptr, expire_timestamp);
    }

    return netcode_encrypt_aead_bignonce(.{ NETCODE_CONNECT_TOKEN_PRIVATE_BYTES - NETCODE_MAC_BYTES, token_buffer.data }, additional_data, nonce, key);
}

netcode_decrypt_connect_token_private :: (token_buffer: ConnectTokenBuf, version_info: VerionInfoBuf, protocol_id: u64, expire_timestamp: u64, nonce: BigNonceBuf, key: EncryptionKeyBuf) -> int {
    additional_data: [NETCODE_VERSION_INFO_BYTES + 8 + 8] u8;
    {
        ptr := additional_data.data;
        netcode_write_bytes(*ptr, version_info);
        netcode_write_uint64(*ptr, protocol_id);
        netcode_write_uint64(*ptr, expire_timestamp);
    }
    return netcode_decrypt_aead_bignonce(token_buffer, additional_data, nonce, key);
}

netcode_read_connect_token_private :: (token_buffer: ConnectTokenBuf, connect_token: *netcode_connect_token_private_t) -> int {
    assert(connect_token != null);

    ptr := token_buffer.data;

    connect_token.client_id = netcode_read_uint64(*ptr);
    connect_token.timeout_seconds = cast(int) netcode_read_uint32(*ptr);
    connect_token.num_server_addresses = netcode_read_uint32(*ptr);

    if connect_token.num_server_addresses <= 0 {
        return NETCODE_ERROR;
    }
    if connect_token.num_server_addresses > NETCODE_MAX_SERVERS_PER_CONNECT {
        return NETCODE_ERROR;
    }

    for address: connect_token.server_addresses {
        address.type = netcode_read_uint8(*ptr);

        if address.type == NETCODE_ADDRESS_IPV4 {
            for 0..3 {
                address.data.ipv4[it] = netcode_read_uint8(*ptr);
            }
            address.port = netcode_read_uint16(*ptr);
        } else if address.type == NETCODE_ADDRESS_IPV6 {
            for 0..7 {
                address.data.ipv6[it] = netcode_read_uint16(*ptr);
            }
            address.port = netcode_read_uint16(*ptr);
        } else {
            return NETCODE_ERROR;
        }
    }

    netcode_read_bytes(*ptr, connect_token.client_to_server_key);
    netcode_read_bytes(*ptr, connect_token.server_to_client_key);
    netcode_read_bytes(*ptr, connect_token.user_data);

    return NETCODE_OK;
}

// -----------------------------------------------

netcode_challenge_token_t :: struct {
    client_id: u64;
    user_data: UserDataBuf;
};

netcode_write_challenge_token :: (challenge_token: *netcode_challenge_token_t, token_buffer: ChallengeTokenBuf) {
    assert(challenge_token != null);

    start := token_buffer.data;

    netcode_write_uint64(*ptr, challenge_token.client_id);
    netcode_write_bytes(*ptr, challenge_token.user_data);

    assert(pointer_diff(ptr, start) <= NETCODE_CHALLENGE_TOKEN_BYTES - NETCODE_MAC_BYTES);
}

netcode_encrypt_challenge_token :: (token_buffer: ChallengeTokenBuf, sequence: u64, key: EncryptionKeyBuf) -> int {
    nonce: [12] u8;
    {
        ptr := nonce.data;
        netcode_write_uint32(*ptr, 0);
        netcode_write_uint64(*ptr, sequence);
    }

    return netcode_encrypt_aead(.{ NETCODE_CHALLENGE_TOKEN_BYTES - NETCODE_MAC_BYTES, token_buffer.data }, .{}, nonce, key );
}

netcode_decrypt_challenge_token :: (token_buffer: ChallengeTokenBuf, sequence: u64, key: EncryptionKeyBuf) -> int {
    nonce: [12] u8;
    {
        ptr := nonce.data;
        netcode_write_uint32(*ptr, 0);
        netcode_write_uint64(*ptr, sequence);
    }

    return netcode_decrypt_aead(token_buffer, .{}, nonce, key);
}

netcode_read_challenge_token :: (token_buffer: ChallengeTokenBuf, challenge_token: *netcode_challenge_token_t) -> int {
    assert(challenge_token != null);

    start := buffer.data;
    ptr := token_buffer.data;

    challenge_token.client_id = netcode_read_uint64(*ptr);
    netcode_read_bytes(*ptr, challenge_token.user_data);

    assert(pointer_diff(ptr, start) == 8 + NETCODE_USER_DATA_BYTES);
    return NETCODE_OK;
}
