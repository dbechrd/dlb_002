Reliable :: #import "Reliable"(DEBUG=true, RUN_TESTS=true);

main :: () {
    print("--- CPU Info -------------------------------------------------------------------\n");
    cpu_info := get_cpu_info();
    print("Vendor: %\n", cpu_info.vendor);
    print("SSE  : %\n", ifx check_feature(cpu_info.feature_leaves, x86_Feature_Flag.SSE) then "Supported" else "Not Supported");
    print("SSE2 : %\n", ifx check_feature(cpu_info.feature_leaves, x86_Feature_Flag.SSE2) then "Supported" else "Not Supported");
    print("AVX2 : %\n", ifx check_feature(cpu_info.feature_leaves, x86_Feature_Flag.AVX2) then "Supported" else "Not Supported");
    print("--------------------------------------------------------------------------------\n");

    run_game();
}

#scope_file

/*
FLOOR_HEIGHT :: 20.0;

Transform :: struct {
    position: Vector3;
    orientation: Quaternion;
}

Player :: struct {
    transform: Transform;
    transform.position.y = FLOOR_HEIGHT;  // fun thing with default values in structs
}
*/

Input :: #import "Input";

#import "Window_Creation";
#import "Machine_X64";

#import "Basic";
#import "Random";
#import "Math";
#import "Thread";
#import "Atomics";

#load "common.jai";
#load "fonts.jai";

State :: struct {
    window_size := Size.{ 1280, 720 };
    max_box_width: s64;
    box_offset: Vector2;
}

state: State;

InputCommand :: struct {
    primary_action: bool;
    motion: Vector2;
}

capture_input_command :: (using inputCmd: *InputCommand) {
    primary_action = Input.input_button_states[Input.Key_Code.MOUSE_BUTTON_LEFT] == .DOWN;
    motion = Vector2.{cast(float)Input.mouse_delta_x, cast(float)-Input.mouse_delta_y};
}

run_game :: () {
    dlb_init_common();

    window := create_window(state.window_size.x, state.window_size.y, "A Window");
    state.window_size.x, state.window_size.y = Simp.get_render_dimensions(window);
    Simp.set_render_target(window);

    dlb_init_fonts(state.window_size);

    fullscreen := false;
    window_info: Saved_Window_Info;
    inputCmd: InputCommand;

    quit := false;
    while !quit {
        Input.update_window_events();

        capture_input_command(*inputCmd);

        for Input.events_this_frame {
            if it.type == {
                case .QUIT;
                    quit = true;
                case .KEYBOARD;
                    if it.key_pressed && !it.repeat {
                        if it.key_code == {
                            case .ESCAPE;
                                quit = true;
                            case .F5;
                                log_error("Not implemented\n");
                            case .F11;
                                #if OS == .WINDOWS {
                                    toggle_fullscreen(window, !fullscreen, *window_info);
                                    fullscreen = !fullscreen;
                                }
                            case xx #char "L";
                                log_error("Not implemented\n");
                        }
                    }
            }
        }

        for Input.get_window_resizes() {
            Simp.update_window(it.window);  // Simp will do nothing if it doesn't care about this window.

            if it.window == window && (it.width != state.window_size.x || it.height != state.window_size.y) {
                state.window_size.x  = it.width;
                state.window_size.y = it.height;
                dlb_init_fonts(state.window_size);  // Resize the font for the new window size.
            }
        }

        draw_one_frame(inputCmd);

        Simp.swap_buffers(window);
        sleep_milliseconds(10);
        reset_temporary_storage();
    }

    print("Thanks for playing!\n");
}

draw_one_frame :: (inputCmd: InputCommand) {
    Simp.clear_render_target(.15, .08, .08, 1);

    Simp.set_shader_for_color(true);

    labels := string.["Server Time", "Frame Time"];
    time := seconds_since_init();

    max_label_width: s64;
    max_value_width: s64;

    for labels {
        label := tprint("%", it);
        value := tprint("%", FormatFloat.{ value=time, trailing_width=2, zero_removal=.NO });

        label_width := Simp.prepare_text(font, label);
        max_label_width = max(max_label_width, label_width);

        value_width := Simp.prepare_text(font, value);
        max_value_width = max(max_value_width, value_width);
    }

    box_offset: Vector2;
    if inputCmd.primary_action {
        box_offset = inputCmd.motion;
    }

    new_box_width := max(max_label_width, max_value_width) * 2 + font.em_width * 3;
    state.max_box_width = max(state.max_box_width, new_box_width);
    box_half_width := state.max_box_width / 2;

    {
        half_w := cast(float)box_half_width;
        half_h := cast(float)state.window_size.y / 4;
        p: Vector2;
        p.x = cast(float)(state.window_size.x / 2);
        p.y = cast(float)(state.window_size.y / 2);

        w := Vector2.{half_w, 0};
        h := Vector2.{0, -half_h};

        p0 := p - w - h + state.box_offset + box_offset;
        p1 := p + w - h + state.box_offset + box_offset;
        p2 := p + w + h + state.box_offset + box_offset;
        p3 := p - w + h + state.box_offset + box_offset;

        Simp.immediate_quad(p0, p1, p2, p3, Vector4.{0, 0, 0, 0.25});
    }

    text_x := state.window_size.x / 2 + cast(s64)state.box_offset.x + cast(s64)box_offset.x - box_half_width;
    text_y := state.window_size.y / 2 + cast(s64)state.box_offset.y + cast(s64)box_offset.y + state.window_size.y / 4 - font.typical_ascender - font.em_width;  // fixme

    for labels {
        label := tprint("%", it);
        value := tprint("%", FormatFloat.{ value=time, trailing_width=2, zero_removal=.NO });

        Simp.prepare_text(font, label);
        Simp.draw_prepared_text(font, text_x + font.em_width, text_y, .{0, 1, 0, 1});

        Simp.prepare_text(font, value);
        Simp.draw_prepared_text(font, text_x + box_half_width + font.em_width / 2, text_y, .{1, 1, 1, 1});

        text_y -= font.default_line_spacing;
    }

    state.box_offset += box_offset;
    state.box_offset.x = clamp(state.box_offset.x, -100, 100);
    state.box_offset.y = clamp(state.box_offset.y, -100, 100);
}
