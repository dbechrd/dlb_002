Simp :: #import "Simp";

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
}

init_state :: (using state: *State) {
    array_add(*nav_history, Any.{ type_info(State), state });

    state.window = create_window(state.window_size.x, state.window_size.y, "dlb_002");
    Simp.set_render_target(state.window);
    state.window_size.x, state.window_size.y = Simp.get_render_dimensions(state.window);

    init_fonts(state);
}

#scope_file

#import "String";  // For path_strip_filename. @Cleanup.
#import "System";  // For get_path_of_running_executable. @Cleanup.
