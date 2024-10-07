/*
------------------------------------------------------------------------------------------------------------------------
Random dev notes:
------------------------------------------------------------------------------------------------------------------------
jai dlb_002.jai -output_path bin -exe dlb_002 -plug Performance_Report -plug Codex
------------------------------------------------------------------------------------------------------------------------
NOTE: Need to patch codex_view to make it work with VS Code.
examples/codex_view/src/draw_metrics.jai:

  open_editor_to_file_and_line :: (filename: string, line: s64) {
      command := tprint("C:/Users/User/AppData/Local/Programs/Microsoft VS Code/Code.exe -g %:%", filename, line);
      strings := Process.break_command_into_strings(command);
      log("Running: %\n", strings);
      Process.run_command(..strings);
  }
------------------------------------------------------------------------------------------------------------------------
*/

MEMORY_DEBUGGER :: true;

main :: () {
    //config: netcode_client_config_t;
    //client := netcode_client_create("192.168.0.143", *config, current_time_monotonic());

    init();
    run_game();
    free_game();

    report_memory_leaks();
}

#load "font.jai";
#load "init.jai";
#load "input.jai";
#load "log.jai";

State :: struct {
    quit: bool;
    window: Window_Type;
    window_info: Saved_Window_Info;
    window_size := Size.{ 1280, 720 };
    fullscreen: bool;

    inputCmd: InputCommand;

    box_offset: Vector2;
    nav_history: [..] *Type_Info;
    scroll_vel: Vector2;
}

#scope_file

#import "Basic"()(MEMORY_DEBUGGER=MEMORY_DEBUGGER);
#import "DLB_Basic";
#import "Math";
#import "Window_Creation";
// #import "Atomics";
// #import "Random";
// #import "Thread";

// #import "IPAddress";//()(ENABLE_LOGGING=true);
// #import "Serialize";//()(ENABLE_LOGGING=true);
// #import "Reliable";//()(ENABLE_LOGGING=true);
// #import "Netcode";//()(ENABLE_LOGGING=true);
// #import "Yojimbo";//()(ENABLE_LOGGING=true);
// #import "Socket";

state_init :: (using state: *State) {
    array_add(*nav_history, type_info(State));

    state.window = create_window(state.window_size.x, state.window_size.y, "dlb_002");
    Simp.set_render_target(state.window);
    state.window_size.x, state.window_size.y = Simp.get_render_dimensions(state.window);

    init_fonts(state);
}

update_state :: (using state: *State) {
    scroll_vel *= 0.9;

    if inputCmd.nav_back && state.nav_history.count > 1 {
        array_ordered_remove_by_index(*state.nav_history, state.nav_history.count-1);
    }
}

state_free :: (using state: *State) {
    array_free(nav_history);
}

run_game :: () {
    log_preamble();
    log("\n--- Game ---\n");
    log("Playing...\n");

    state: State;
    state_init(*state);

    while !state.quit {
        process_input(*state);
        update_state(*state);

        draw_one_frame(*state);
        Simp.swap_buffers(state.window);

        memory_visualizer_per_frame_update();
        reset_temporary_storage();

        sleep_milliseconds(10);
    }

    state_free(*state);
}

free_game :: () {
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

draw_one_frame :: (state: *State) {
    Simp.clear_render_target(.15, .08, .08, 1);

    Simp.set_shader_for_color(true);

    box_offset: Vector2;
    if state.inputCmd.nav_grab {
        box_offset = state.inputCmd.motion;
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
        state            = state,
        top_left         = .{ xx text_x, xx text_y },
        cursor           = .{ xx text_x, xx text_y },
        border_thickness = 2,
        pad              = 8,
        column_widths    = .[0, 0],
        font_y_offset    = font.y_offset_for_centering,
        line_spacing     = xx font.default_line_spacing,
        depth            = 0,
        inputCmd         = state.inputCmd
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
