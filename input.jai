InputCommand :: struct {
    nav_forward: bool;
    nav_back: bool;
    nav_grab: bool;

    mouse_position: Vector2;
    motion: Vector2;
}

capture_input_command :: (using inputCmd: *InputCommand) {
    nav_grab = Input.input_button_states[Input.Key_Code.MOUSE_BUTTON_MIDDLE] == .DOWN;
    x, y := get_mouse_pointer_position();
    mouse_position = .{ xx x, xx y };
    motion = .{cast(float)Input.mouse_delta_x, cast(float)-Input.mouse_delta_y};
}

process_input :: (state: *State) {
    Input.update_window_events();

    inputCmd: InputCommand;
    capture_input_command(*inputCmd);

    for Input.events_this_frame {
        if it.type == {
            case .QUIT;
                state.quit = true;
            case .KEYBOARD;
                if it.key_pressed && !it.repeat {
                    if it.key_code == {
                        case .ESCAPE;
                            state.quit = true;
                        case xx #char "0";
                            state.box_offset = .{};
                        case .F5;
                            log_error("Not implemented\n");
                        case .F11;
                            #if OS == .WINDOWS {
                                state.fullscreen = !state.fullscreen;
                                toggle_fullscreen(state.window, state.fullscreen, *state.window_info);
                            }
                        case xx #char "L";
                            log_error("Not implemented\n");
                        case .MOUSE_BUTTON_LEFT;
                            inputCmd.nav_forward = true;
                            stream := make_stream(*missing_ogg);
                            // HACK: Our .ogg isn't big enough to finish loading "initial pages", so we need to disable that feature.
                            stream.internal_flags &= ~.WAITING_FOR_INITIAL_DECODER_PAGES;
                            start_playing(stream);
                        case .BACKSPACE;
                            inputCmd.nav_back = true;
                    }
                }
            case .MOUSE_WHEEL;
                if it.wheel_delta {
                    factor := it.wheel_delta / cast(float) it.typical_wheel_delta * 10;
                    if Input.input_button_states[Input.Key_Code.SHIFT] != .NONE {
                        state.scroll_vel += .{ factor, 0 };
                    } else {
                        state.scroll_vel += .{ 0, factor };
                    }
                }
        }
    }

    for Input.get_window_resizes() {
        Simp.update_window(it.window);  // Simp will do nothing if it doesn't care about this window.

        if it.window == state.window && (it.width != state.window_size.x || it.height != state.window_size.y) {
            state.window_size = .{ it.width, it.height };
            init_fonts(state);  // Resize the font for the new window size.
        }
    }

    state.inputCmd = inputCmd;
}

#scope_file

Input :: #import "Input";
