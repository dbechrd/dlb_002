// jai dlb_002.jai -output_path bin -exe dlb_002 -plug Performance_Report

main :: () {
    context.logger = logger;
    context.log_level = .VERY_VERBOSE;
    context.print_style.default_format_struct.use_long_form_if_more_than_this_many_members = -1;
    context.print_style.default_format_struct.use_newlines_if_long_form = true;
    context.print_style.default_format_array.stop_printing_after_this_many_elements = 1000;

    log_cpu_info();
    // address_test();
    // serialize_test();
    // reliable_test();
    // netcode_test();
    // yojimbo_init();
    // yojimbo_tests();

    //config: netcode_client_config_t;
    //client := netcode_client_create("192.168.0.143", *config, current_time_monotonic());

    run_game();
}

#scope_file

// NOTE: Set DEFAULT_EDITOR_COMMAND to `start /b code -g %2:%1` in codex_view's settings.jai file.
MEMORY_DEBUGGER :: false;

/*
Player :: struct {
    transform: Transform;
    transform.position.y = 20;  // fun thing with default values in structs
}
*/

log_cpu_info :: () {
    log("\n--- CPU Info -------------------------------------------------------------------\n");
    cpu_info := get_cpu_info();
    log("Vendor: %\n", cpu_info.vendor);
    log("SSE  : %\n", ifx check_feature(cpu_info.feature_leaves, x86_Feature_Flag.SSE) then "Supported" else "Not Supported");
    log("SSE2 : %\n", ifx check_feature(cpu_info.feature_leaves, x86_Feature_Flag.SSE2) then "Supported" else "Not Supported");
    log("AVX2 : %\n", ifx check_feature(cpu_info.feature_leaves, x86_Feature_Flag.AVX2) then "Supported" else "Not Supported");
}

#import "dlb";
#import "IPAddress";//()(ENABLE_LOGGING=true);
#import "Serialize";//()(ENABLE_LOGGING=true);
#import "Reliable";//()(ENABLE_LOGGING=true);
#import "Netcode";//()(ENABLE_LOGGING=true);
#import "Yojimbo";//()(ENABLE_LOGGING=true);
#import "Socket";

logger :: (message: string, data: *void, info: Log_Info) {
    if !message then return;

    if info.common_flags & .VERY_VERBOSE_ONLY && context.log_level < .VERY_VERBOSE {
        return;
    }
    if info.common_flags & .VERBOSE_ONLY && context.log_level < .VERBOSE {
        return;
    }

    to_standard_error := false; //(info.common_flags & .ERROR) != 0;

    if message[message.count-1] != #char "\n" {
        write_strings(message, "\n", to_standard_error = to_standard_error);
    } else {
        write_string(message, to_standard_error = to_standard_error);
    }
}

Input :: #import "Input";

#import "Window_Creation";
#import "Machine_X64";

#import "Basic"()(MEMORY_DEBUGGER=MEMORY_DEBUGGER);
#import "Random";
#import "Math";
#import "Thread";
#import "Atomics";
Windows :: #import "Windows";

#load "common.jai";
#load "fonts.jai";

State :: struct {
    window_size := Size.{ 1280, 720 };
    box_offset: Vector2;
    nav_history: [..] *Type_Info;
    scroll_vel: Vector2;
}

state: State;

InputCommand :: struct {
    nav_forward: bool;
    nav_back: bool;
    nav_motion: bool;

    mouse_position: Vector2;
    motion: Vector2;
}

capture_input_command :: (using inputCmd: *InputCommand) {
    nav_motion = Input.input_button_states[Input.Key_Code.MOUSE_BUTTON_MIDDLE] == .DOWN;
    x, y := get_mouse_pointer_position();
    mouse_position = .{ xx x, xx y };
    motion = .{cast(float)Input.mouse_delta_x, cast(float)-Input.mouse_delta_y};
}

run_game :: () {
    log("\n--- Game -----------------------------------------------------------------------\n");
    dlb_init_common();

    window := create_window(state.window_size.x, state.window_size.y, "dlb_002");
    Simp.set_render_target(window);
    dlb_init_fonts(state.window_size);

    state.window_size.x, state.window_size.y = Simp.get_render_dimensions(window);
    array_add(*state.nav_history, type_info(netcode_server_t));

    fullscreen := false;
    window_info: Saved_Window_Info;

    quit := false;
    while !quit {
        Input.update_window_events();

        inputCmd: InputCommand;
        capture_input_command(*inputCmd);
        state.scroll_vel *= 0.9;

        for Input.events_this_frame {
            if it.type == {
                case .QUIT;
                    quit = true;
                case .KEYBOARD;
                    if it.key_pressed && !it.repeat {
                        if it.key_code == {
                            case .ESCAPE;
                                quit = true;
                            case xx #char "0";
                                state.box_offset = .{};
                            case .F5;
                                log_error("Not implemented\n");
                            case .F11;
                                #if OS == .WINDOWS {
                                    toggle_fullscreen(window, !fullscreen, *window_info);
                                    fullscreen = !fullscreen;
                                }
                            case xx #char "L";
                                log_error("Not implemented\n");
                            case .MOUSE_BUTTON_LEFT;
                                inputCmd.nav_forward = true;
                            case .BACKSPACE;
                                inputCmd.nav_back = true;
                        }
                        if it.vkey == Windows.VK_NUMPAD0 {
                            state.box_offset = .{};
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

            if it.window == window && (it.width != state.window_size.x || it.height != state.window_size.y) {
                state.window_size.x  = it.width;
                state.window_size.y = it.height;
                dlb_init_fonts(state.window_size);  // Resize the font for the new window size.
            }
        }

        if inputCmd.nav_back && state.nav_history.count > 1 {
            array_ordered_remove_by_index(*state.nav_history, state.nav_history.count-1);
        }

        draw_one_frame(inputCmd);
        Simp.swap_buffers(window);

        reset_temporary_storage();
        memory_visualizer_per_frame_update();

        sleep_milliseconds(10);
    }

    log("Thanks for playing!\n");
}

Layout :: struct {
    state: *State;
    top_left: Vector2;
    cursor: Vector2;
    border_thickness: float;
    pad: float;
    column_widths: [2] float;
    font_y_offset: int;
    line_spacing: float;
    depth: int;
    inputCmd: InputCommand;
}

draw_quad :: (x: float, y: float, w: float, h: float, layout: Layout) -> clicked: bool {
    x0, y0, x1, y1 := x, y, x + w, y + h;

    m := layout.inputCmd.mouse_position;
    m.y = layout.state.window_size.y - m.y;
    hover := m.x >= x0 && m.y >= y0 && m.x <= x1 && m.y <= y1;

    factor := cos(to_milliseconds(current_time_monotonic()) / 150.0);

    Simp.set_shader_for_color(true);
    Simp.immediate_quad(x0, y0, x1, y1, .{.25 + (ifx hover then .2 else 0), .22, .23, .6 + (ifx hover then .2 + .15 * factor else 0)});

    if layout.border_thickness > 0 {
        b := layout.border_thickness;
        Simp.immediate_quad(x0    , y1    , x1    , y1 + b, .{0, 0, 0, 1});  // top border
        Simp.immediate_quad(x1    , y0 - b, x1 + b, y1 + b, .{0, 0, 0, 1});  // right border
        Simp.immediate_quad(x0    , y0 - b, x1    , y0    , .{0, 0, 0, 1});  // bottom border
        Simp.immediate_quad(x0 - b, y0 - b, x0    , y1 + b, .{0, 0, 0, 1});  // left border
    }

    return hover && layout.inputCmd.nav_forward;
}

draw_one_frame :: (inputCmd: InputCommand) {
    Simp.clear_render_target(.15, .08, .08, 1);

    Simp.set_shader_for_color(true);

    box_offset: Vector2;
    if inputCmd.nav_motion {
        box_offset = inputCmd.motion;
    }
    box_offset -= state.scroll_vel;

    box_width := state.window_size.x;
    box_half_width := box_width / 2;

    #if 0 {
        half_w := cast(float)box_half_width;
        half_h := cast(float)state.window_size.y / 2;
        p := Vector2.{
            cast(float)(state.window_size.x / 2),
            cast(float)(state.window_size.y / 2)
        };

        w := Vector2.{half_w, 0};
        h := Vector2.{0, -half_h};

        p0 := p - w - h + state.box_offset + box_offset;
        p1 := p + w - h + state.box_offset + box_offset;
        p2 := p + w + h + state.box_offset + box_offset;
        p3 := p - w + h + state.box_offset + box_offset;

        Simp.immediate_quad(p0, p1, p2, p3, Vector4.{0, 0, 0, 0.25});
    }

    text_x := state.window_size.x / 2 + cast(s64)state.box_offset.x + cast(s64)box_offset.x - box_half_width;
    text_y := state.window_size.y + cast(s64)state.box_offset.y + cast(s64)box_offset.y - font.typical_ascender - font.em_width;

    layout := Layout.{
        state            = *state,
        top_left         = .{ xx text_x, xx text_y },
        cursor           = .{ xx text_x, xx text_y },
        border_thickness = 2,
        pad              = 8,
        column_widths    = .[0, 0],
        font_y_offset    = font.y_offset_for_centering,
        line_spacing     = xx font.default_line_spacing,
        depth            = 0,
        inputCmd         = inputCmd
    };

    column_width := floor((state.window_size.x - layout.pad * (layout.column_widths.count + 1)) / layout.column_widths.count);
    for * layout.column_widths {
        it.* = column_width;
    }

    get_type_details :: (ti: *Type_Info) -> string {
        if ti.type == {
            case .STRUCT;
                using _ := cast(*Type_Info_Struct) ti;
                if textual_flags & .UNION {
                    return tprint("% (% bytes)", ifx name then name else "UNION", ti.runtime_size);
                } else {
                    return tprint("% (% bytes)", ifx name then name else "STRUCT", ti.runtime_size);
                }
            case .INTEGER;
                using _ := cast(*Type_Info_Integer) ti;
                return tprint("%0%", ifx signed then "s" else "u", ti.runtime_size * 8);
            case .POINTER;
                using _ := cast(*Type_Info_Pointer) ti;
                if pointer_to.type == .STRUCT {
                    pointee := cast(*Type_Info_Struct) pointer_to;
                    return tprint("*% (% bytes)", pointee.name, ti.runtime_size);
                } else {
                    return tprint("*% (% bytes)", pointer_to.type, ti.runtime_size);
                }
            case;
                return tprint("% (% bytes)", ti.type, ti.runtime_size);
        }
    }

    draw_row :: (label: string, value: string, layout: *Layout) -> clicked_column: int {
        clicked_column := -1;

        layout.cursor.x = layout.top_left.x + layout.pad;
        if draw_quad(layout.cursor.x, layout.cursor.y, layout.column_widths[0], layout.line_spacing, layout) {
            clicked_column = 0;
        }

        indent := layout.depth * 16;

        Simp.prepare_text(font, label);
        Simp.draw_prepared_text(font, xx (layout.cursor.x + indent), xx (layout.cursor.y + layout.font_y_offset), .{1, 1, .92, 1});

        layout.cursor.x += layout.column_widths[0] + layout.pad;

        if draw_quad(layout.cursor.x, layout.cursor.y, layout.column_widths[0], layout.line_spacing, layout) {
            clicked_column = 1;
        }

        Simp.prepare_text(font, value);
        Simp.draw_prepared_text(font, xx layout.cursor.x, xx (layout.cursor.y + layout.font_y_offset), .{0.38, 0.61, 0.84, 1});

        layout.cursor.y -= layout.line_spacing + layout.border_thickness;

        return clicked_column;
    }

    Nav :: struct {
        forward_request: *Type_Info;
        back_request := false;
    }

    draw_type_info :: (name: string, ti: *Type_Info, layout: *Layout, nav: *Nav) {
        label := tprint("%", name);
        value := get_type_details(ti);

        if layout.depth == 0 {
            if layout.state.nav_history.count > 1 {
                // nav row
                clicked_column := draw_row("< Back", .{}, layout);
                if clicked_column == 0 {
                    nav.back_request = true;
                }
            }

            // display value as root node
            draw_row(value, .{}, layout);
        } else {
            clicked_column := draw_row(label, value, layout);
            if clicked_column >= 0 && ti != layout.state.nav_history[layout.state.nav_history.count-1] {
                nav.forward_request = ti;
            }
        }

        if layout.depth == 0 && ti.type == .STRUCT {
            tis := cast(*Type_Info_Struct) ti;
            for tis.members {
                layout.depth += 1;
                draw_type_info(it.name, it.type, layout, nav);
                layout.depth -= 1;
            }
        }
    }

    nav: Nav;
    draw_type_info("[root]", state.nav_history[state.nav_history.count-1], *layout, *nav);

    if nav.forward_request {
        if nav.forward_request.type == .STRUCT {
            array_add(*layout.state.nav_history, nav.forward_request);
            state.box_offset = .{};
            state.scroll_vel = .{};
        }
    } else if nav.back_request && layout.state.nav_history.count > 1 {
        array_ordered_remove_by_index(*layout.state.nav_history, layout.state.nav_history.count-1);
        state.box_offset = .{};
    } else {
        state.box_offset += box_offset;
    }

    // labels := string.["Server Time", "Frame Time"];
    // time := seconds_since_init();
    // tprint("%", FormatFloat.{ value=time, trailing_width=2, zero_removal=.NO });

}
