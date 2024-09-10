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

EncryptionKeyBuf :: [NETCODE_KEY_BYTES] u8;

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
    private_key                   : EncryptionKeyBuf;
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

NETCODE_SOCKET_ERROR_NONE                              :: 0;
NETCODE_SOCKET_ERROR_CREATE_FAILED                     :: 1;
NETCODE_SOCKET_ERROR_SET_NON_BLOCKING_FAILED           :: 2;
NETCODE_SOCKET_ERROR_SOCKOPT_IPV6_ONLY_FAILED          :: 3;
NETCODE_SOCKET_ERROR_SOCKOPT_RCVBUF_FAILED             :: 4;
NETCODE_SOCKET_ERROR_SOCKOPT_SNDBUF_FAILED             :: 5;
NETCODE_SOCKET_ERROR_BIND_IPV4_FAILED                  :: 6;
NETCODE_SOCKET_ERROR_BIND_IPV6_FAILED                  :: 7;
NETCODE_SOCKET_ERROR_GET_SOCKNAME_IPV4_FAILED          :: 8;
NETCODE_SOCKET_ERROR_GET_SOCKNAME_IPV6_FAILED          :: 9;
NETCODE_SOCKET_ERROR_DISABLE_UDP_PORT_CONNRESET_FAILED :: 10;

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
        SIO_UDP_CONNRESET :: 0x9800000C;  //_WSAIOW(IOC_VENDOR, 12)
        bNewBehavior :: cast(s32) 0;      // Win32 BOOL false
        dwBytesReturned: u32 = 0;         // Win32 DWORD
        result := WSAIoctl(s.handle, SIO_UDP_CONNRESET, *bNewBehavior, size_of(type_of(bNewBehavior)), null, 0, *dwBytesReturned, null, null);
        if result != 0 {
            error_code := get_last_socket_error();
            error_string := System.get_error_string(error_code);
            netcode_log(.ERROR, "error: failed to disable UDP CONNRESET (port unreachable) message reporting on socket. %: \n", error_code, error_string);
            return NETCODE_SOCKET_ERROR_DISABLE_UDP_PORT_CONNRESET_FAILED;
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
        from.data.ipv4[0] = cast(u8) ((addr_ipv4.sin_addr.s_addr & 0x000000FF)      );
        from.data.ipv4[1] = cast(u8) ((addr_ipv4.sin_addr.s_addr & 0x0000FF00) >> 8 );
        from.data.ipv4[2] = cast(u8) ((addr_ipv4.sin_addr.s_addr & 0x00FF0000) >> 16);
        from.data.ipv4[3] = cast(u8) ((addr_ipv4.sin_addr.s_addr & 0xFF000000) >> 24);
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

netcode_generate_connect_token_private :: (connect_token: *netcode_connect_token_private_t, client_id: u64, timeout_seconds: int, num_server_addresses: int, server_addresses: [] netcode_address_t, user_data: *UserDataBuf) {
    assert(connect_token != null);
    assert(num_server_addresses > 0);
    assert(num_server_addresses <= NETCODE_MAX_SERVERS_PER_CONNECT);
    assert(user_data != null);

    connect_token.client_id = client_id;
    connect_token.timeout_seconds = timeout_seconds;
    connect_token.num_server_addresses = num_server_addresses;

    for 0..num_server_addresses-1 {
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
    cursor := token_buffer.data;

    netcode_write_uint64(*cursor, connect_token.client_id);
    netcode_write_uint32(*cursor, connect_token.timeout_seconds);
    netcode_write_uint32(*cursor, connect_token.num_server_addresses);

    for it_address: 0..connect_token.num_server_addresses-1 {
        address := *connect_token.server_addresses[it_address];
        if address.type == NETCODE_ADDRESS_IPV4 {
            netcode_write_uint8(*cursor, NETCODE_ADDRESS_IPV4);
            for it_byte: 0..3 {
                netcode_write_uint8(*cursor, address.data.ipv4[it_byte]);
            }
            netcode_write_uint16(*cursor, address.port);
        } else if address.type == NETCODE_ADDRESS_IPV6 {
            netcode_write_uint8(*cursor, NETCODE_ADDRESS_IPV6);
            for it_byte: 0..7 {
                netcode_write_uint16(*cursor, address.data.ipv6[it_byte]);
            }
            netcode_write_uint16(*cursor, address.port);
        } else {
            assert(false, "Invalid address type");
        }
    }

    netcode_write_bytes(*cursor, connect_token.client_to_server_key);
    netcode_write_bytes(*cursor, connect_token.server_to_client_key);
    netcode_write_bytes(*cursor, connect_token.user_data);

    assert(pointer_diff(cursor, start) <= NETCODE_CONNECT_TOKEN_PRIVATE_BYTES - NETCODE_MAC_BYTES);
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

    cursor := token_buffer.data;

    connect_token.client_id = netcode_read_uint64(*cursor);
    connect_token.timeout_seconds = cast(int) netcode_read_uint32(*cursor);
    connect_token.num_server_addresses = netcode_read_uint32(*cursor);

    if connect_token.num_server_addresses <= 0 {
        return NETCODE_ERROR;
    }
    if connect_token.num_server_addresses > NETCODE_MAX_SERVERS_PER_CONNECT {
        return NETCODE_ERROR;
    }

    for it_address: 0..connect_token.num_server_addresses-1 {
        address := *connect_token.server_addresses[it_address];

        address.type = netcode_read_uint8(*cursor);
        if address.type == NETCODE_ADDRESS_IPV4 {
            for it_byte: 0..3 {
                address.data.ipv4[it_byte] = netcode_read_uint8(*cursor);
            }
            address.port = netcode_read_uint16(*cursor);
        } else if address.type == NETCODE_ADDRESS_IPV6 {
            for it_byte: 0..7 {
                address.data.ipv6[it_byte] = netcode_read_uint16(*cursor);
            }
            address.port = netcode_read_uint16(*cursor);
        } else {
            return NETCODE_ERROR;
        }
    }

    netcode_read_bytes(*cursor, connect_token.client_to_server_key);
    netcode_read_bytes(*cursor, connect_token.server_to_client_key);
    netcode_read_bytes(*cursor, connect_token.user_data);

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

    netcode_write_uint64(*cursor, challenge_token.client_id);
    netcode_write_bytes(*cursor, challenge_token.user_data);

    assert(pointer_diff(cursor, start) <= NETCODE_CHALLENGE_TOKEN_BYTES - NETCODE_MAC_BYTES);
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
    cursor := token_buffer.data;

    challenge_token.client_id = netcode_read_uint64(*cursor);
    netcode_read_bytes(*cursor, challenge_token.user_data);

    assert(pointer_diff(cursor, start) == 8 + NETCODE_USER_DATA_BYTES);
    return NETCODE_OK;
}

// ----------------------------------------------------------------

// TODO(dlb): Make this an enum
NETCODE_CONNECTION_REQUEST_PACKET    :: 0;
NETCODE_CONNECTION_DENIED_PACKET     :: 1;
NETCODE_CONNECTION_CHALLENGE_PACKET  :: 2;
NETCODE_CONNECTION_RESPONSE_PACKET   :: 3;
NETCODE_CONNECTION_KEEP_ALIVE_PACKET :: 4;
NETCODE_CONNECTION_PAYLOAD_PACKET    :: 5;
NETCODE_CONNECTION_DISCONNECT_PACKET :: 6;
NETCODE_CONNECTION_NUM_PACKETS       :: 7;

netcode_connection_packet_t :: struct {
    type: u8;
};

netcode_connection_request_packet_t :: struct {
    using #as base: netcode_connection_packet_t;
    base.type = NETCODE_CONNECTION_REQUEST_PACKET;

    version_info                   : VerionInfoBuf;
    protocol_id                    : u64;
    connect_token_expire_timestamp : u64;
    connect_token_nonce            : BigNonceBuf;
    connect_token_data             : ConnectTokenBuf;
};

netcode_connection_denied_packet_t :: struct {
    using #as base: netcode_connection_packet_t;
    base.type = NETCODE_CONNECTION_DENIED_PACKET;
};

netcode_connection_challenge_packet_t :: struct {
    using #as base: netcode_connection_packet_t;
    base.type = NETCODE_CONNECTION_CHALLENGE_PACKET;

    challenge_token_sequence : u64;
    challenge_token_data     : ChallengeTokenBuf;
};

netcode_connection_response_packet_t :: struct {
    using #as base: netcode_connection_packet_t;
    base.type = NETCODE_CONNECTION_RESPONSE_PACKET;

    challenge_token_sequence : u64;
    challenge_token_data     : ChallengeTokenBuf;
};

netcode_connection_keep_alive_packet_t :: struct {
    using #as base: netcode_connection_packet_t;
    base.type = NETCODE_CONNECTION_KEEP_ALIVE_PACKET;

    client_index : int;
    max_clients  : int;
};

netcode_connection_payload_packet_t :: struct {
    using #as base: netcode_connection_packet_t;
    base.type = NETCODE_CONNECTION_PAYLOAD_PACKET;

    payload_data : [] u8;
};

netcode_connection_disconnect_packet_t :: struct {
    using #as base: netcode_connection_packet_t;
    base.type = NETCODE_CONNECTION_DISCONNECT_PACKET;
};

netcode_create_payload_packet :: (payload_bytes: int) -> *netcode_connection_payload_packet_t {
    assert(payload_bytes >= 0);
    assert(payload_bytes <= NETCODE_MAX_PAYLOAD_BYTES);

    buffer := NewArray(size_of(netcode_connection_payload_packet_t) + payload_bytes, u8);
    if buffer == null {
        return null;
    }

    packet := cast(*netcode_connection_payload_packet_t) buffer.data;
    Initialize(packet);
    packet.payload_data = .{ payload_bytes, buffer.data + size_of(netcode_connection_payload_packet_t) };

    return packet;
}

netcode_context_t :: struct {
    write_packet_key: EncryptionKeyBuf;
    read_packet_key: EncryptionKeyBuf;
};

netcode_sequence_number_bytes_required :: (sequence: u64) -> int {
    mask: u64 = 0xFF00000000000000;
    for 0..6 {
        if sequence & mask {
            return 8 - it; // n bytes
        }
        mask >>= 8;
    }
    return 1;  // 1 byte
}

netcode_write_packet :: (packet: *netcode_connection_packet_t, buffer: [] u8, sequence: u64, write_packet_key: EncryptionKeyBuf, protocol_id: u64) -> int {
    assert(packet != null);
    assert(buffer.count > 0);
    assert(write_packet_key.count > 0);

    if packet.type == NETCODE_CONNECTION_REQUEST_PACKET {
        // connection request packet: first byte is zero

        assert(buffer.count >= 1 + 13 + 8 + 8 + NETCODE_CONNECT_TOKEN_NONCE_BYTES + NETCODE_CONNECT_TOKEN_PRIVATE_BYTES);

        p := cast(*netcode_connection_request_packet_t) packet;

        start := buffer.data;
        cursor := start;

        netcode_write_uint8(*cursor, NETCODE_CONNECTION_REQUEST_PACKET);
        netcode_write_bytes(*cursor, p.version_info);
        netcode_write_uint64(*cursor, p.protocol_id);
        netcode_write_uint64(*cursor, p.connect_token_expire_timestamp);
        netcode_write_bytes(*cursor, p.connect_token_nonce);
        netcode_write_bytes(*cursor, p.connect_token_data);

        assert(pointer_diff(cursor, start) == 1 + 13 + 8 + 8 + NETCODE_CONNECT_TOKEN_NONCE_BYTES + NETCODE_CONNECT_TOKEN_PRIVATE_BYTES);

        return cast(int) pointer_diff(cursor, start);
    } else {
        // *** encrypted packets ***

        // write the prefix byte (this is a combination of the packet type and number of sequence bytes)

        start := buffer.data;
        cursor := start;

        sequence_bytes := cast(u8) netcode_sequence_number_bytes_required(sequence);

        assert(sequence_bytes >= 1);
        assert(sequence_bytes <= 8);

        assert(packet.type <= 0xF);  // huh? that's not even the max packet type bruh

        prefix_byte := packet.type | (sequence_bytes << 4);

        netcode_write_uint8(*cursor, prefix_byte);

        // write the variable length sequence number [1,8] bytes.

        sequence_temp := sequence;

        for 0..sequence_bytes-1 {
            netcode_write_uint8(*cursor, cast(u8) (sequence_temp & 0xFF));
            sequence_temp >>= 8;
        }

        // write packet data according to type. this data will be encrypted.

        encrypted_start := cursor;

        if packet.type == {
            case NETCODE_CONNECTION_DENIED_PACKET;
                // ...
            case NETCODE_CONNECTION_CHALLENGE_PACKET;
                p := cast(*netcode_connection_challenge_packet_t) packet;
                netcode_write_uint64(*cursor, p.challenge_token_sequence );
                netcode_write_bytes(*cursor, p.challenge_token_data);
            case NETCODE_CONNECTION_RESPONSE_PACKET;
                p := cast(*netcode_connection_response_packet_t) packet;
                netcode_write_uint64(*cursor, p.challenge_token_sequence);
                netcode_write_bytes(*cursor, p.challenge_token_data);
            case NETCODE_CONNECTION_KEEP_ALIVE_PACKET;
                p := cast(*netcode_connection_keep_alive_packet_t) packet;
                netcode_write_uint32(*cursor, p.client_index);
                netcode_write_uint32(*cursor, p.max_clients);
            case NETCODE_CONNECTION_PAYLOAD_PACKET;
                p := cast(*netcode_connection_payload_packet_t) packet;

                assert(p.payload_bytes <= NETCODE_MAX_PAYLOAD_BYTES);

                netcode_write_bytes(*cursor, p.payload_data, p.payload_bytes);
            case NETCODE_CONNECTION_DISCONNECT_PACKET;
                // ...
            case;
                assert(false, "invalid connection packet type");
        }

        netcode_assert(pointer_diff(cursor, start) <= buffer.count - NETCODE_MAC_BYTES);

        encrypted_finish := cursor;

        // encrypt the per-packet packet written with the prefix byte, protocol id and version as the associated data. this must match to decrypt.

        additional_data: [NETCODE_VERSION_INFO_BYTES + 8 + 1] u8;
        {
            ptr := additional_data.data;
            netcode_write_bytes(*ptr, NETCODE_VERSION_INFO, NETCODE_VERSION_INFO_BYTES);
            netcode_write_uint64(*ptr, protocol_id);
            netcode_write_uint8(*ptr, prefix_byte);
        }

        nonce: [12] u8;
        {
            ptr := nonce.data;
            netcode_write_uint32(*ptr, 0);
            netcode_write_uint64(*ptr, sequence);
        }

        if netcode_encrypt_aead(.{ pointer_diff(encrypted_finish, encrypted_start), encrypted_start }, additional_data, nonce, write_packet_key) != NETCODE_OK {
            return NETCODE_ERROR;
        }

        cursor += NETCODE_MAC_BYTES;
        netcode_assert(pointer_diff(cursor - start) <= buffer.count);

        return pointer_diff(cursor - start);
    }
}

netcode_replay_protection_t :: struct {
    most_recent_sequence : u64;
    received_packet      : [NETCODE_REPLAY_PROTECTION_BUFFER_SIZE] u64;
};

netcode_replay_protection_reset :: (replay_protection: *netcode_replay_protection_t) {
    assert(replay_protection != null);

    replay_protection.most_recent_sequence = 0;
    array_fill_byte(replay_protection.received_packet, 0xFF);
}

netcode_replay_protection_already_received :: (replay_protection: *netcode_replay_protection_t, sequence: u64) -> bool {
    assert(replay_protection != null);

    // NOTE(dlb): If we sent a packet every millisecond it would take roughly 584 million years for
    // this to wrap, assuming we always start a zero. As such, we elide wraparound protection.
    if sequence + NETCODE_REPLAY_PROTECTION_BUFFER_SIZE <= replay_protection.most_recent_sequence {
        return true;
    }

    index := cast(int) (sequence % NETCODE_REPLAY_PROTECTION_BUFFER_SIZE);

    if replay_protection.received_packet[index] == 0x_FFFF_FFFF_FFFF_FFFF {
        return false;
    }

    if replay_protection.received_packet[index] >= sequence {
        return true;
    }

    return false;
}

netcode_replay_protection_advance_sequence :: (replay_protection: *netcode_replay_protection_t, sequence: u64) {
    assert(replay_protection != null);

    // NOTE(dlb): No wraparound protection, it's big enough (see above).
    if sequence > replay_protection.most_recent_sequence {
        replay_protection.most_recent_sequence = sequence;
    }

    index := cast(int) (sequence % NETCODE_REPLAY_PROTECTION_BUFFER_SIZE);

    replay_protection.received_packet[index] = sequence;
}

netcode_read_packet :: (
    buffer            : [] u8,
    read_packet_key   : EncryptionKeyBuf,
    protocol_id       : u64,
    current_timestamp : u64,
    private_key       : *EncryptionKeyBuf,
    allowed_packets   : [NETCODE_CONNECTION_NUM_PACKETS] bool,  // NOTE(dlb): Could be a Bit_Array, but it's on the stack, so I probably don't care?
    replay_protection : *netcode_replay_protection_t
) -> packet: *netcode_connection_packet_t, sequence: u64 {
    netcode_assert(sequence != null);

    if buffer.count < 1 {
        netcode_log(.VERBOSE_ONLY, "ignored packet. buffer length is less than 1\n");
        return null, 0;
    }

    start := buffer.data;
    cursor := start;

    prefix_byte := netcode_read_uint8(*cursor);

    if prefix_byte == NETCODE_CONNECTION_REQUEST_PACKET {
        // connection request packet: first byte is zero

        if !allowed_packets[NETCODE_CONNECTION_REQUEST_PACKET] {
            netcode_log(.VERBOSE_ONLY, "ignored connection request packet. packet type is not allowed\n");
            return null, 0;
        }

        if buffer.count != 1 + NETCODE_VERSION_INFO_BYTES + 8 + 8 + NETCODE_CONNECT_TOKEN_NONCE_BYTES + NETCODE_CONNECT_TOKEN_PRIVATE_BYTES {
            netcode_log(.VERBOSE_ONLY, "ignored connection request packet. bad packet length (expected %, got %)\n", 1 + NETCODE_VERSION_INFO_BYTES + 8 + 8 + NETCODE_CONNECT_TOKEN_NONCE_BYTES + NETCODE_CONNECT_TOKEN_PRIVATE_BYTES, buffer.count);
            return null, 0;
        }

        if private_key == null {
            netcode_log(.VERBOSE_ONLY, "ignored connection request packet. no private key\n");
            return null, 0;
        }

        version_info: VerionInfoBuf;
        netcode_read_bytes(*cursor, version_info);
        if version_info[0]  != #char "N" ||
           version_info[1]  != #char "E" ||
           version_info[2]  != #char "T" ||
           version_info[3]  != #char "C" ||
           version_info[4]  != #char "O" ||
           version_info[5]  != #char "D" ||
           version_info[6]  != #char "E" ||
           version_info[7]  != #char " " ||
           version_info[8]  != #char "1" ||
           version_info[9]  != #char "." ||
           version_info[10] != #char "0" ||
           version_info[11] != #char "2" ||
           version_info[12] != #char "\0"
        {
            netcode_log(.VERBOSE_ONLY, "ignored connection request packet. bad version info\n");
            return null, 0;
        }

        packet_protocol_id := netcode_read_uint64(*cursor);
        if packet_protocol_id != protocol_id {
            netcode_log(.VERBOSE_ONLY, "ignored connection request packet. wrong protocol id. expected %, got %\n", protocol_id, packet_protocol_id);
            return null, 0;
        }

        packet_connect_token_expire_timestamp := netcode_read_uint64(*cursor);
        if packet_connect_token_expire_timestamp <= current_timestamp {
            netcode_log(.VERBOSE_ONLY, "ignored connection request packet. connect token expired\n");
            return null, 0;
        }

        packet_connect_token_nonce: BigNonceBuf;
        netcode_read_bytes(*cursor, packet_connect_token_nonce);

        assert(pointer_diff(cursor, start) == 1 + NETCODE_VERSION_INFO_BYTES + 8 + 8 + NETCODE_CONNECT_TOKEN_NONCE_BYTES);

        decrypt_token_result := netcode_decrypt_connect_token_private(
            .{ NETCODE_CONNECT_TOKEN_PRIVATE_BYTES, cursor },
            version_info,
            protocol_id,
            packet_connect_token_expire_timestamp,
            packet_connect_token_nonce,
            private_key
        );
        if decrypt_token_result != NETCODE_OK {
            netcode_log(.VERBOSE_ONLY, "ignored connection request packet. connect token failed to decrypt\n");
            return null, 0;
        }

        packet := New(netcode_connection_request_packet_t);
        if packet == null {
            netcode_log(.VERBOSE_ONLY, "ignored connection request packet. failed to allocate packet\n");
            return null, 0;
        }

        packet.packet_type = NETCODE_CONNECTION_REQUEST_PACKET;
        packet.version_info = version_info;
        packet.protocol_id = packet_protocol_id;
        packet.connect_token_expire_timestamp = packet_connect_token_expire_timestamp;
        packet.connect_token_nonce = packet_connect_token_nonce;

        netcode_read_bytes(*cursor, packet.connect_token_data);

        assert(pointer_diff(cursor, start) == 1 + NETCODE_VERSION_INFO_BYTES + 8 + 8 + NETCODE_CONNECT_TOKEN_NONCE_BYTES + NETCODE_CONNECT_TOKEN_PRIVATE_BYTES);

        return packet, 0;  // first packet is sequence number 0 of course, not an error case!
    }
    else
    {
        // *** encrypted packets ***

        if read_packet_key.count == 0 {
            netcode_log(.VERBOSE_ONLY, "ignored encrypted packet. no read packet key for this address\n");
            return null, 0;
        }

        if buffer.count < 1 + 1 + NETCODE_MAC_BYTES {
            netcode_log(.VERBOSE_ONLY, "ignored encrypted packet. packet is too small to be valid (% bytes)\n", buffer.count);
            return null, 0;
        }

        // extract the packet type and number of sequence bytes from the prefix byte

        packet_type := prefix_byte & 0xF;

        if packet_type >= NETCODE_CONNECTION_NUM_PACKETS {
            netcode_log(.VERBOSE_ONLY, "ignored encrypted packet. packet type % is invalid\n", packet_type);
            return null, 0;
        }

        if !allowed_packets[packet_type] {
            netcode_log(.VERBOSE_ONLY, "ignored encrypted packet. packet type % is not allowed\n", packet_type);
            return null, 0;
        }

        sequence_bytes := prefix_byte >> 4;

        if sequence_bytes < 1 || sequence_bytes > 8 {
            netcode_log(.VERBOSE_ONLY, "ignored encrypted packet. sequence bytes % is out of range [1,8]\n", sequence_bytes);
            return null, 0;
        }

        if buffer.count < 1 + sequence_bytes + NETCODE_MAC_BYTES {
            netcode_log(.VERBOSE_ONLY, "ignored encrypted packet. buffer is too small for sequence bytes + encryption mac\n");
            return null, 0;
        }

        // read variable length sequence number [1,8]

        sequence: u64;
        for 0..sequence_bytes-1 {
            value := netcode_read_uint8(*cursor);
            sequence |= (cast(u64) value) << (8 * it);
        }

        // ignore the packet if it has already been received

        if replay_protection != null && packet_type >= NETCODE_CONNECTION_KEEP_ALIVE_PACKET {
            if netcode_replay_protection_already_received(replay_protection, sequence) {
                netcode_log(.VERBOSE_ONLY, "ignored packet. sequence % already received (replay protection)\n", sequence);
                return null, 0;
            }
        }

        // decrypt the per-packet type data

        additional_data: [NETCODE_VERSION_INFO_BYTES + 8 + 1] u8;
        {
            ptr := additional_data.data;
            netcode_write_bytes(*ptr, NETCODE_VERSION_INFO, NETCODE_VERSION_INFO_BYTES);
            netcode_write_uint64(*ptr, protocol_id);
            netcode_write_uint8(*ptr, prefix_byte);
        }

        nonce: [12] u8;
        {
            ptr := nonce.data;
            netcode_write_uint32(*ptr, 0);
            netcode_write_uint64(*ptr, sequence);
        }

        encrypted_bytes := (buffer.count - pointer_diff(cursor, start));

        if encrypted_bytes < NETCODE_MAC_BYTES {
            netcode_log(.VERBOSE_ONLY, "ignored encrypted packet. encrypted payload is too small\n");
            return null, 0;
        }

        if netcode_decrypt_aead(.{ encrypted_bytes, cursor }, additional_data, nonce, read_packet_key) != NETCODE_OK {
            netcode_log(.VERBOSE_ONLY, "ignored encrypted packet. failed to decrypt\n");
            return null, 0;
        }

        decrypted_bytes := encrypted_bytes - NETCODE_MAC_BYTES;

        // update the latest replay protection sequence #

        if replay_protection != null && packet_type >= NETCODE_CONNECTION_KEEP_ALIVE_PACKET {
            netcode_replay_protection_advance_sequence(replay_protection, sequence);
        }

        // process the per-packet type data that was just decrypted

        if packet_type == {
            case NETCODE_CONNECTION_DENIED_PACKET;
                if decrypted_bytes != 0 {
                    netcode_log(.VERBOSE_ONLY, "ignored connection denied packet. decrypted packet data is wrong size\n");
                    return null, 0;
                }

                packet := New(netcode_connection_denied_packet_t);
                if packet == null {
                    netcode_log(.VERBOSE_ONLY, "ignored connection denied packet. could not allocate packet struct\n");
                    return null, 0;
                }
                assert(packet.type == NETCODE_CONNECTION_DENIED_PACKET);

                return packet, sequence;
            case NETCODE_CONNECTION_CHALLENGE_PACKET;
                if decrypted_bytes != 8 + NETCODE_CHALLENGE_TOKEN_BYTES {
                    netcode_log(.VERBOSE_ONLY, "ignored connection challenge packet. decrypted packet data is wrong size\n");
                    return null, 0;
                }

                packet := New(netcode_connection_challenge_packet_t);
                if packet == null {
                    netcode_log(.VERBOSE_ONLY, "ignored connection challenge packet. could not allocate packet struct\n");
                    return null, 0;
                }
                assert(packet.type == NETCODE_CONNECTION_CHALLENGE_PACKET);

                packet.challenge_token_sequence = netcode_read_uint64(*cursor);
                netcode_read_bytes(*cursor, packet.challenge_token_data);

                return packet, sequence;
            case NETCODE_CONNECTION_RESPONSE_PACKET;
                if decrypted_bytes != 8 + NETCODE_CHALLENGE_TOKEN_BYTES {
                    netcode_log(.VERBOSE_ONLY, "ignored connection response packet. decrypted packet data is wrong size\n");
                    return null, 0;
                }

                packet := New(netcode_connection_response_packet_t);
                if packet == null {
                    netcode_log(.VERBOSE_ONLY, "ignored connection response packet. could not allocate packet struct\n");
                    return null, 0;
                }
                assert(packet.type == NETCODE_CONNECTION_RESPONSE_PACKET);

                packet.challenge_token_sequence = netcode_read_uint64(*cursor);
                netcode_read_bytes(*cursor, packet.challenge_token_data);

                return packet, sequence;
            case NETCODE_CONNECTION_KEEP_ALIVE_PACKET;
                if decrypted_bytes != 8 {
                    netcode_log(.VERBOSE_ONLY, "ignored connection keep alive packet. decrypted packet data is wrong size\n");
                    return null, 0;
                }

                packet := New(netcode_connection_keep_alive_packet_t);
                if packet == null {
                    netcode_log(.VERBOSE_ONLY, "ignored connection keep alive packet. could not allocate packet struct\n");
                    return null, 0;
                }
                assert(packet.packet_type == NETCODE_CONNECTION_KEEP_ALIVE_PACKET);

                packet.client_index = netcode_read_uint32(*cursor);
                packet.max_clients = netcode_read_uint32(*cursor);

                return packet, sequence;
            case NETCODE_CONNECTION_PAYLOAD_PACKET;
                if decrypted_bytes < 1 {
                    netcode_log(.VERBOSE_ONLY, "ignored connection payload packet. payload is too small\n");
                    return null, 0;
                }

                if decrypted_bytes > NETCODE_MAX_PAYLOAD_BYTES {
                    netcode_log(.VERBOSE_ONLY, "ignored connection payload packet. payload is too large\n");
                    return null, 0;
                }

                packet := netcode_create_payload_packet(decrypted_bytes);
                if packet == null {
                    netcode_log(.VERBOSE_ONLY, "ignored connection payload packet. could not allocate packet struct\n");
                    return null, 0;
                }
                assert(packet.type == NETCODE_CONNECTION_PAYLOAD_PACKET);

                memcpy(packet.payload_data.data, cursor, decrypted_bytes);

                return packet, sequence;
            case NETCODE_CONNECTION_DISCONNECT_PACKET;
                if decrypted_bytes != 0 {
                    netcode_log(.VERBOSE_ONLY, "ignored connection disconnect packet. decrypted packet data is wrong size\n");
                    return null, 0;
                }

                packet := New(netcode_connection_disconnect_packet_t);
                if packet == null {
                    netcode_log(.VERBOSE_ONLY, "ignored connection disconnect packet. could not allocate packet struct\n");
                    return null, 0;
                }
                assert(packet.type == NETCODE_CONNECTION_DISCONNECT_PACKET);

                return packet, sequence;
            case;
                return null, 0;
        }
    }
}

// ----------------------------------------------------------------

netcode_connect_token_t :: struct  {
    version_info         : VerionInfoBuf;
    protocol_id          : u64;
    create_timestamp     : u64;
    expire_timestamp     : u64;
    nonce                : BigNonceBuf;
    private_data         : ConnectTokenBuf;
    timeout_seconds      : int;
    num_server_addresses : int;
    server_addresses     : [NETCODE_MAX_SERVERS_PER_CONNECT] netcode_address_t;
    client_to_server_key : EncryptionKeyBuf;
    server_to_client_key : EncryptionKeyBuf;
};

// buffer expected to be zero'd
netcode_write_connect_token :: (connect_token: *netcode_connect_token_t, buffer: [] u8) {
    assert(connect_token != null);
    assert(buffer_length >= NETCODE_CONNECT_TOKEN_BYTES);

    start := buffer.data;
    cursor := start;

    netcode_write_bytes(cursor, connect_token.version_info);
    netcode_write_uint64(cursor, connect_token.protocol_id);
    netcode_write_uint64(cursor, connect_token.create_timestamp);
    netcode_write_uint64(cursor, connect_token.expire_timestamp);
    netcode_write_bytes(cursor, connect_token.nonce);
    netcode_write_bytes(cursor, connect_token.private_data);
    netcode_write_uint32(cursor, connect_token.timeout_seconds);
    netcode_write_uint32(cursor, connect_token.num_server_addresses);

    for it_address: 0..connect_token.num_server_addresses-1 {
        address := *connect_token.server_addresses[it_address];

        if address.type == NETCODE_ADDRESS_IPV4 {
            netcode_write_uint8(cursor, NETCODE_ADDRESS_IPV4);
            for it_byte: 0..3 {
                netcode_write_uint8(cursor, address.data.ipv4[it_byte]);
            }
            netcode_write_uint16(cursor, address.port);
        } else if address.type == NETCODE_ADDRESS_IPV6 {
            netcode_write_uint8(cursor, NETCODE_ADDRESS_IPV6);
            for it_byte: 0..7 {
                netcode_write_uint16(cursor, address.data.ipv6[it_byte]);
            }
            netcode_write_uint16(cursor, address.port);
        } else {
            assert(false, "Invalid address type");
        }
    }

    netcode_write_bytes(cursor, connect_token.client_to_server_key);
    netcode_write_bytes(cursor, connect_token.server_to_client_key);

    assert(pointer_diff(cursor, start) <= NETCODE_CONNECT_TOKEN_BYTES);
}

netcode_read_connect_token :: (buffer: [] u8, connect_token: *netcode_connect_token_t) -> int {
    assert(buffer.count > 0);
    assert(connect_token != null);

    cursor := buffer.data;

    if buffer.count != NETCODE_CONNECT_TOKEN_BYTES {
        netcode_log(.ERROR, "error: read connect data has bad buffer length (%)\n", buffer.count);
        return NETCODE_ERROR;
    }

    netcode_read_bytes(cursor, connect_token.version_info);
    if connect_token.version_info[0]  != #char "N" ||
       connect_token.version_info[1]  != #char "E" ||
       connect_token.version_info[2]  != #char "T" ||
       connect_token.version_info[3]  != #char "C" ||
       connect_token.version_info[4]  != #char "O" ||
       connect_token.version_info[5]  != #char "D" ||
       connect_token.version_info[6]  != #char "E" ||
       connect_token.version_info[7]  != #char " " ||
       connect_token.version_info[8]  != #char "1" ||
       connect_token.version_info[9]  != #char "." ||
       connect_token.version_info[10] != #char "0" ||
       connect_token.version_info[11] != #char "2" ||
       connect_token.version_info[12] != #char "\0"
    {
        connect_token.version_info[12] = #char "\0";
        netcode_log(.ERROR, "error: read connect data has bad version info (got %, expected %)\n", connect_token.version_info, NETCODE_VERSION_INFO);
        return NETCODE_ERROR;
    }

    connect_token.protocol_id = netcode_read_uint64(cursor);
    connect_token.create_timestamp = netcode_read_uint64(cursor);
    connect_token.expire_timestamp = netcode_read_uint64(cursor);

    if connect_token.create_timestamp > connect_token.expire_timestamp {
        return NETCODE_ERROR;
    }

    netcode_read_bytes(cursor, connect_token.nonce);
    netcode_read_bytes(cursor, connect_token.private_data);

    connect_token.timeout_seconds = netcode_read_uint32(cursor);
    connect_token.num_server_addresses = netcode_read_uint32(cursor);

    if connect_token.num_server_addresses <= 0 || connect_token.num_server_addresses > NETCODE_MAX_SERVERS_PER_CONNECT {
        netcode_log(.ERROR, "error: read connect data has bad number of server addresses (%)\n", connect_token.num_server_addresses);
        return NETCODE_ERROR;
    }

    for it_address: 0..connect_token.num_server_addresses-1 {
        address := *connect_token.server_addresses[it_address];

        address.type = netcode_read_uint8(cursor);
        if address.type == NETCODE_ADDRESS_IPV4 {
            for it_byte: 0..3 {
                address.data.ipv4[it_byte] = netcode_read_uint8(cursor);
            }
            address.port = netcode_read_uint16(cursor);
        } else if address.type == NETCODE_ADDRESS_IPV6 {
            for it_byte: 0..7 {
                address.data.ipv6[it_byte] = netcode_read_uint16(cursor);
            }
            address.port = netcode_read_uint16(cursor);
        } else {
            netcode_log(.ERROR, "error: read connect data has bad address type (%)\n", address.type);
            return NETCODE_ERROR;
        }
    }

    netcode_read_bytes(cursor, connect_token.client_to_server_key);
    netcode_read_bytes(cursor, connect_token.server_to_client_key);

    return NETCODE_OK;
}

// ----------------------------------------------------------------

netcode_packet_queue_t :: struct {
    num_packets     : int;
    start_index     : int;
    packet_data     : [NETCODE_PACKET_QUEUE_SIZE] *netcode_connection_packet_t;
    packet_sequence : [NETCODE_PACKET_QUEUE_SIZE] u64;
};

netcode_packet_queue_clear :: (using queue: *netcode_packet_queue_t) {
    assert(queue != null);

    for 0..num_packets-1 {
        free(packet_data[it]);
    }
    queue.* = .{};
}

netcode_packet_queue_push :: (using queue: *netcode_packet_queue_t, packet: *netcode_connection_packet_t, sequence: u64) -> bool {
    assert(queue != null);
    assert(packet != null);

    if num_packets == NETCODE_PACKET_QUEUE_SIZE {
        free(packet);
        return false;
    }

    index := (start_index + num_packets) % NETCODE_PACKET_QUEUE_SIZE;
    packet_data[index] = packet;
    sequence[index] = sequence;
    num_packets += 1;
    return true;
}

netcode_packet_queue_pop :: (using queue: *netcode_packet_queue_t) -> packet: *netcode_connection_packet_t, sequence: u64 {
    if num_packets == 0 {
        return null, 0;
    }

    packet := packet_data[start_index];
    sequence := packet_sequence[start_index];
    start_index = (start_index + 1) % NETCODE_PACKET_QUEUE_SIZE;
    num_packets -= 1;
    return packet, sequence;
}

// ----------------------------------------------------------------

NETCODE_NETWORK_SIMULATOR_NUM_PACKET_ENTRIES          :: NETCODE_MAX_CLIENTS * 256;
NETCODE_NETWORK_SIMULATOR_NUM_PENDING_RECEIVE_PACKETS :: NETCODE_MAX_CLIENTS * 64;

netcode_network_simulator_packet_entry_t :: struct {
    from          : netcode_address_t;
    to            : netcode_address_t;
    delivery_time : Apollo_Time;
    packet_data   : [] u8;
};

netcode_network_simulator_t :: struct {
    latency_milliseconds        : float;
    jitter_milliseconds         : float;
    packet_loss_percent         : float;
    duplicate_packet_percent    : float;
    time                        : Apollo_Time;
    current_index               : int;
    num_pending_receive_packets : int;
    packet_entries              : [NETCODE_NETWORK_SIMULATOR_NUM_PACKET_ENTRIES] netcode_network_simulator_packet_entry_t;
    pending_receive_packets     : [NETCODE_NETWORK_SIMULATOR_NUM_PENDING_RECEIVE_PACKETS] netcode_network_simulator_packet_entry_t;
};

netcode_network_simulator_reset :: (using network_simulator: *netcode_network_simulator_t) {
    assert(network_simulator != null);

    netcode_log(.VERBOSE_ONLY, "network simulator reset\n");

    for * packet_entries {
        array_free(it.packet_data);
    }
    array_reset(packet_entries);

    for 0..num_pending_receive_packets-1 {
        array_free(pending_receive_packets[it].packet_data);
    }
    array_reset(pending_receive_packets);

    network_simulator.* = .{};
}

netcode_network_simulator_destroy :: (network_simulator: *netcode_network_simulator_t) {
    assert(network_simulator != null);

    netcode_network_simulator_reset(network_simulator);
    free(network_simulator);
}

/*
Generate a random float between a and b.
IMPORTANT: This is not a cryptographically secure random. It's used only for test functions and in the network simulator.
@param a The minimum integer value to generate.
@param b The maximum integer value to generate.
@returns A pseudo random float value in [a,b].
*/
netcode_random_float :: inline (a: float, b: float) -> float {
    assert(a < b);
    result := a + random_get_zero_to_one_new() * (b - a);
    assert(result >= a);
    assert(result <= b);
    return a + r;
}



netcode_network_simulator_queue_packet :: (using network_simulator: *netcode_network_simulator_t, from: *netcode_address_t, to: *netcode_address_t, packet_data: [] u8, delay: Apollo_Time) {
    entry := *packet_entries[current_index];
    entry.from = from.*;
    entry.to = to.*;
    entry.packet_data = array_copy(packet_data);
    entry.delivery_time = time + delay;

    current_index = (current_index + 1) % NETCODE_NETWORK_SIMULATOR_NUM_PACKET_ENTRIES;
}

netcode_network_simulator_send_packet :: (using network_simulator: *netcode_network_simulator_t, from: *netcode_address_t, to: *netcode_address_t, packet_data: [] u8) {
    assert(network_simulator != null);
    assert(from != null);
    assert(from.type != 0);
    assert(to != null);
    assert(to.type != 0);
    assert(packet_data.count > 0);
    assert(packet_data.count <= NETCODE_MAX_PACKET_BYTES);

    if netcode_random_float(0.0, 100.0) <= packet_loss_percent {
        return;
    }

    entry := *packet_entries[current_index];
    if entry.packet_data.count > 0 {
        array_reset(*entry.packet_data);
    }

    delay := latency_milliseconds / 1000.0;

    if jitter_milliseconds > 0.0 {
        delay += netcode_random_float(-jitter_milliseconds, jitter_milliseconds) / 1000.0;
    }

    netcode_network_simulator_queue_packet(network_simulator, from, to, packet_data, delay);

    if netcode_random_float(0.0, 100.0) <= duplicate_packet_percent {
        netcode_network_simulator_queue_packet(network_simulator, from, to, packet_data, delay + netcode_random_float(0, 1.0));
    }
}

netcode_network_simulator_receive_packets :: (using network_simulator: *netcode_network_simulator_t, to: *netcode_address_t, max_packets: int, packet_data: [][] u8, from: [] netcode_address_t) -> int {
    assert(network_simulator != null);
    assert(to != null);
    assert(max_packets >= 0);
    assert(packet_data.count >= max_packets);
    assert(from.count >= max_packets);

    num_packets := 0;

    for 0..num_pending_receive_packets-1 {
        if num_packets == max_packets {
            break;
        }

        if pending_receive_packets[it].packet_data.count == 0 {
            continue;
        }

        if !netcode_address_equal(*pending_receive_packets[it].to, to) {
            continue;
        }

        packet_data[num_packets] = pending_receive_packets[it].packet_data;
        from[num_packets] = pending_receive_packets[it].from;

        pending_receive_packets[it].packet_data = null;

        num_packets += 1;
    }

    assert(num_packets <= max_packets);

    return num_packets;
}

netcode_network_simulator_update :: (using network_simulator: *netcode_network_simulator_t, _time: Apollo_Time) {
    assert(network_simulator != null);

    time = _time;

    // discard any pending receive packets that are still in the buffer

    for 0..num_pending_receive_packets-1 {
        packet := *pending_receive_packets[it];
        if packet.packet_data.count > 0 {
            array_reset(packet.packet_data);
        }
    }

    num_pending_receive_packets = 0;

    // walk across packet entries and move any that are ready to be received into the pending receive buffer

    for 0..NETCODE_NETWORK_SIMULATOR_NUM_PACKET_ENTRIES-1 {
        if num_pending_receive_packets == NETCODE_NETWORK_SIMULATOR_NUM_PENDING_RECEIVE_PACKETS {
            break;
        }

        packet := *packet_entries[it];
        if packet.packet_data.count == 0 {
            continue;
        }

        if packet.delivery_time <= time {
            pending_receive_packets[num_pending_receive_packets] = packet;
            num_pending_receive_packets += 1;
            packet.packet_data = null;
        }
    }
}