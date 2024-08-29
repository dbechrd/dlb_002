//---------------------------------------------------------------------------------------------------------------------
// Native port of Glenn Fielder's yojimbo library, as of this commit:
// https://github.com/mas-bandwidth/yojimbo/commit/c6c02dfec105b36b9cbefd82f86f11f894f6de51
//
// Original license:
//---------------------------------------------------------------------------------------------------------------------
// Yojimbo Client/Server Network Library.
//
// Copyright © 2016 - 2024, Mas Bandwidth LLC.
//
// Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
//
//     1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
//
//     2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer
//        in the documentation and/or other materials provided with the distribution.
//
//     3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived
//        from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
// INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
// WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
// USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//---------------------------------------------------------------------------------------------------------------------

#module_parameters(
    YOJIMBO_ENABLE_LOGGING       := false,
    YOJIMBO_DEFAULT_TIMEOUT      := 10,
    YOJIMBO_DEBUG_MEMORY_LEAKS   := false,
    YOJIMBO_DEBUG_MESSAGE_LEAKS  := false,
    YOJIMBO_DEBUG_MESSAGE_BUDGET := false
);

/**
    Initialize the yojimbo library.
    Call this before calling any yojimbo library functions.
    @returns True if the library was successfully initialized, false otherwise.
 */
yojimbo_init :: () -> bool {

}

/**
    Shutdown the yojimbo library.
    Call this after you finish using the library and it will run some checks for you (for example, checking for memory leaks in debug build).
 */
yojimbo_shutdown :: () {

}

yojimbo_tests :: () {
    address_tests();
}

#scope_module

// #load "adapter.jai";
#load "address.jai";
// #load "base_client.jai";
// #load "base_server.jai";
// #load "bit_array.jai";
// #load "channel.jai";
// #load "channel_packet_data.jai";;
// #load "client_interface.jai";
// #load "client.jai";
// #load "config.jai";
// #load "connection.jai";
// #load "constants.jai";
// #load "message.jai";
// #load "network_info.jai";
// #load "network_simulator.jai";
// #load "queue.jai";
// #load "reliable_ordered_channel.jai";
// #load "sequence_buffer.jai";
// #load "serialize.jai";
// #load "server_interface.jai";
// #load "server.jai";
// #load "unreliable_unordered_channel.jai";
// #load "utils.jai";

#import "Basic";

yojimbo_log :: (flags: Log_Flags, format_string: string, args: .. Any, loc := #caller_location) {
    #if YOJIMBO_ENABLE_LOGGING {
        log(format_string, ..args, loc, flags,, temp);
    }
}
