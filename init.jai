Size :: struct { x: s64; y: s64; };

init :: (state: *State) {
    path := path_strip_filename(get_path_of_running_executable());
    set_working_directory(path);

    #if OS == .WINDOWS {
        Windows :: #import "Windows";

        Windows.SetProcessDPIAware();

        // Windows is very bad at thread-switching by default unless you do this. Sad.
        Windows.timeBeginPeriod(1);
    }

    init_logger();
    init_state(state);
    init_fonts(state);
    init_audio(state);
}

deinit :: (state: *State) {
    deinit_audio(state);
    state_free(state);
}

#scope_file

init_state :: (using state: *State) {
    state.window = create_window(state.window_size.x, state.window_size.y, "dlb_002");
    Simp.set_render_target(state.window);
    state.window_size.x, state.window_size.y = Simp.get_render_dimensions(state.window);

    array_add(*nav_history, Any.{ type_info(State), state });
}

state_free :: (using state: *State) {
    array_free(nav_history);
}

#import "String";  // For path_strip_filename. @Cleanup.
#import "System";  // For get_path_of_running_executable. @Cleanup.
