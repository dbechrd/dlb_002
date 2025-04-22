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

tpj_logo: Simp.Texture;

main :: () {
    state: State;
    init(*state);

    filename := "tpj.png";
    if !Simp.texture_load_from_file(*tpj_logo, filename) {
        log_error("Failed to convert PNG to texture\n");
    }

    // array_reset_keeping_memory(*state.nav_history);
    // array_add(*state.nav_history, Any.{ type_info(type_of(missing_ogg_stream.*)), missing_ogg_stream });
    array_add(*state.nav_history, context);

    run_game(*state);
    deinit(*state);

    report_memory_leaks();
}

#load "audio.jai";
#load "font.jai";
#load "init.jai";
#load "input.jai";
#load "log.jai";
#load "missing_ogg.jai";

RingMode :: enum {
    NONE;
    DIALTONE;
    RINGING;
};

State :: struct {
    quit: bool;
    window: Window_Type;
    window_info: Saved_Window_Info;
    window_size := Size.{ 1280, 720 };
    fullscreen: bool;

    input_cmd: InputCommand;
    prev_ring_mode: RingMode;
    ring_mode: RingMode;
    ring_interval_started_at: Apollo_Time;  // if ring_mode == RINGING, when the ring or silence interval started
    ring_interval_silent: bool;  // toggles back and forth to create an intervaled ring

    box_offset: Vector2;
    nav_history: [..] Any;
    scroll_vel: Vector2;
    populated_cities := CITIES;
}

#import "Basic"()(MEMORY_DEBUGGER=MEMORY_DEBUGGER);
#import "Trivial";
#import "File";
#import "Math";
#import "Window_Creation";
Simp :: #import "Simp";
using Sound :: #import "Sound_Player";

#scope_file

// #import "Atomics";
// #import "Random";
// #import "Thread";

// #import "IPAddress";//()(ENABLE_LOGGING=true);
// #import "Serialize";//()(ENABLE_LOGGING=true);
// #import "Reliable";//()(ENABLE_LOGGING=true);
// #import "Netcode";//()(ENABLE_LOGGING=true);
// #import "Yojimbo";//()(ENABLE_LOGGING=true);
// #import "Socket";

update_state :: (using state: *State) {
    scroll_vel *= 0.9;

    if input_cmd.nav_back && nav_history.count > 1 {
        array_ordered_remove_by_index(*nav_history, nav_history.count-1);
    }

    now := current_time_monotonic();

    if ring_mode != prev_ring_mode {
        stop_all_sounds_abruptly(0);
        if ring_mode == {
            case .DIALTONE;
                log("started dialtone\n");
                play_sound(*sine_350, true);
                play_sound(*sine_440, true);
            case .RINGING;
                log("started ringing\n");
                ring_interval_started_at = now;
                ring_interval_silent = false;
                play_sound(*sine_440, true);
                play_sound(*sine_480, true);

        }
        prev_ring_mode = ring_mode;
    }

    if ring_mode == .RINGING {
        interval_duration := now - ring_interval_started_at;
        if ring_interval_silent && interval_duration > seconds_to_apollo(4) {
            log("started ring interval\n");
            ring_interval_silent = false;
            ring_interval_started_at = now;
            play_sound(*sine_440, true);
            play_sound(*sine_480, true);
        } else if !ring_interval_silent && interval_duration > seconds_to_apollo(2) {
            log("started ring silence interval\n");
            stop_all_sounds_abruptly(0);
            ring_interval_silent = true;
            ring_interval_started_at = now;
        }
    }
}

run_game :: (state: *State) {
    log_preamble();
    log("\n--- Game ---\n");
    log("Playing...\n");

    while !state.quit {
        process_input(state);
        update_state(state);

        Simp.clear_render_target(.15, .08, .08, 1);

        draw_one_frame(state);
        draw_rect(4, 4, cast(float) font.character_height * 1.2, cast(float) font.character_height * 1.2, *tpj_logo);
        Simp.draw_text(font, cast(int) (8 + font.character_height * 1.2), font.character_height / 2, "© 2024 The Programming Junkie");
        Simp.swap_buffers(state.window);
        Sound.update();

        memory_visualizer_per_frame_update();
        reset_temporary_storage();

        sleep_milliseconds(10);
    }

    log("Thanks for playing!\n");
}

draw_rect :: (x: float, y: float, w: float, h: float, texture: *Simp.Texture = null, color := Vector4.{1,1,1,1}) {
    x0, y0, x1, y1 := x, y, x + w, y + h;

    if texture {
        Simp.set_shader_for_images(texture);
    } else {
        Simp.set_shader_for_color();
    }
    Simp.immediate_quad(x0, y0, x1, y1, color);
}

Layout :: struct {
    state: *State;
    top_left: Vector2;
    cursor: Vector2;
    border_thickness: float;
    pad: float;
    column_widths: [4] float;
    font_y_offset: int;
    line_spacing: float;
    depth: int;
    input_cmd: InputCommand;
}

draw_quad :: (x: float, y: float, w: float, h: float, layout: Layout) -> clicked: bool {
    x0, y0, x1, y1 := x, y, x + w, y + h;

    m := layout.input_cmd.mouse_position;
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

    return hover && layout.input_cmd.nav_forward;
}

draw_one_frame :: (state: *State) {
    Simp.set_shader_for_color(true);

    box_offset: Vector2;
    if state.input_cmd.nav_grab {
        box_offset = state.input_cmd.motion;
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
        column_widths    = .[0, 0, 0, 0],
        font_y_offset    = font.y_offset_for_centering,
        line_spacing     = xx font.default_line_spacing,
        depth            = 0,
        input_cmd        = state.input_cmd
    };

    column_width := floor((state.window_size.x - layout.pad * (layout.column_widths.count + 1)) / layout.column_widths.count);
    for * layout.column_widths {
        it.* = column_width;
    }

    get_type_string :: (any: Any) -> string {
        if any.type.type == {
            /*
            INTEGER              :: 0;
            FLOAT                :: 1;
            BOOL                 :: 2;
            STRING               :: 3;
            POINTER              :: 4;
            PROCEDURE            :: 5;
            VOID                 :: 6;
            STRUCT               :: 7;
            ARRAY                :: 8;
            OVERLOAD_SET         :: 9;
            ANY                  :: 10;
            ENUM                 :: 11;
            POLYMORPHIC_VARIABLE :: 12;
            TYPE                 :: 13;
            CODE                 :: 14;
            */
            case .INTEGER;
                using _ := cast(*Type_Info_Integer) any.type;
                return ifx signed {
                    tprint("s%", any.type.runtime_size * 8);
                } else {
                    tprint("u%", any.type.runtime_size * 8);
                };
            case .FLOAT;
                using _ := cast(*Type_Info_Integer) any.type;
                return ifx any.type.runtime_size == 4 then "float" else "float64";
            case .BOOL;
                return "bool";
            case .POINTER;
                using _ := cast(*Type_Info_Pointer) any.type;
                if pointer_to.type == {
                    case .STRUCT;
                        pointee := cast(*Type_Info_Struct) pointer_to;
                        return tprint("*%", pointee.name);
                    case;
                        return tprint("*%", pointer_to.type);
                }
             case .STRUCT;
                using _ := cast(*Type_Info_Struct) any.type;
                if textual_flags & .UNION {
                    return tprint("%", ifx name then name else "UNION");
                } else {
                    return tprint("%", ifx name then name else "STRUCT");
                }
            case;
                return tprint("%", any.type.type);
        }
    }

    get_value_string :: (any: Any) -> string {
        if any.type.type == {
            case .INTEGER;
                using _ := cast(*Type_Info_Integer) any.type;
                if signed {
                    if runtime_size == {
                        case 1; return tprint("%", (cast(*s8) any.value_pointer).*);
                        case 2; return tprint("%", (cast(*s16) any.value_pointer).*);
                        case 4; return tprint("%", (cast(*s32) any.value_pointer).*);
                        case 8; return tprint("%", (cast(*s64) any.value_pointer).*);
                        case; assert(false, "weird integer"); return "???";
                    }
                } else {
                    if runtime_size == {
                        case 1; return tprint("%", (cast(*u8) any.value_pointer).*);
                        case 2; return tprint("%", (cast(*u16) any.value_pointer).*);
                        case 4; return tprint("%", (cast(*u32) any.value_pointer).*);
                        case 8; return tprint("%", (cast(*u64) any.value_pointer).*);
                        case; assert(false, "weird integer"); return "???";
                    }
                }
            case .FLOAT;
                using _ := cast(*Type_Info_Integer) any.type;
                return ifx any.type.runtime_size == 4 {
                    tprint("%", (cast(*float) any.value_pointer).*);
                } else {
                    tprint("%", (cast(*float64) any.value_pointer).*);
                };
            case .BOOL;
                return ifx (cast(*bool) any.value_pointer).* then "true" else "false";
            case .STRING;
                return (cast(*string) any.value_pointer).*;
            case .POINTER;
                return tprint("%", (cast(**void) any.value_pointer).*);
            case .STRUCT;
                if any.type == {
                    case type_info(type_of(Vector2));
                        v := cast(*Vector2) any.value_pointer;
                        return tprint("%, %", v.x, v.y);
                    case type_info(type_of(Size));
                        s := cast(*Size) any.value_pointer;
                        return tprint("%, %", s.x, s.y);
                }
                using _ := cast(*Type_Info_Struct) any.type;
                if textual_flags & .UNION {
                    return "...";
                } else {
                    return "...";
                }
            case .ARRAY;
                info_array := cast(*Type_Info_Array) any.type;

                count: s64;
                if info_array.array_type == .FIXED {
                    count = info_array.array_count;
                } else {
                    count = << cast(*s64)  (any.value_pointer);
                }

                return tprint("[%] %", count, info_array.element_type.type);
            case .ANY;
                any_value := cast(*Any) any.value_pointer;
                return get_value_string(any_value.*);
            case;
                return tprint("{%}", any.type.type);
        }
    }

    draw_row :: (cols: [] string, layout: *Layout) -> clicked_column: int {
        clicked_column := -1;
        layout.cursor.x = layout.top_left.x + layout.pad;

        colors := Vector4.[.{1, 1, .92, 1}, .{0.38, 0.61, 0.84, 1}, .{.6, .6, .6, 1}, .{1, 1, 1, 1}];

        for cols {
            if draw_quad(layout.cursor.x, layout.cursor.y, layout.column_widths[it_index], layout.line_spacing, layout) {
                clicked_column = it_index;
            }

            indent := 4 + ifx it_index == 0 then layout.depth * 8 else 0;

            Simp.prepare_text(font, it);
            Simp.draw_prepared_text(font, xx (layout.cursor.x + indent), xx (layout.cursor.y + layout.font_y_offset), colors[it_index]);
            layout.cursor.x += layout.column_widths[it_index] + layout.pad;
        }

        layout.cursor.y -= layout.line_spacing + layout.border_thickness;
        return clicked_column;
    }

    Nav :: struct {
        forward_request: Any;
        back_request := false;
    }

    draw_type_info :: (name: string, any: Any, layout: *Layout, nav: *Nav) {
        type_str := get_type_string(any);
        size_str := tprint("%", any.type.runtime_size);
        value_str := get_value_string(any);

        if layout.depth == 0 {
            if layout.state.nav_history.count > 1 {
                // nav row
                clicked_column := draw_row(.["< Back"], layout);
                if clicked_column == 0 {
                    nav.back_request = true;
                }
            }

            // display value as root node
            draw_row(.[type_str, tprint("%", any.value_pointer), "", size_str], layout);
        } else {
            clicked_column := draw_row(.[name, value_str, type_str, size_str], layout);
            nav_current := layout.state.nav_history[layout.state.nav_history.count-1];
            if clicked_column >= 0 && (any.type != nav_current.type || any.value_pointer != nav_current.value_pointer) {
                nav.forward_request = any;
            }
        }

        if layout.depth == 0 {
            if any.type.type == {
                case .STRUCT;
                    info_struct := cast(*Type_Info_Struct) any.type;
                    for info_struct.members {
                        if it.flags & .IMPORTED {
                            log("imported\n");
                        }
                        layout.depth += 1;
                        member_any := Any.{ it.type, any.value_pointer + it.offset_in_bytes };
                        draw_type_info(it.name, member_any, layout, nav);
                        layout.depth -= 1;
                    }
                case .ARRAY;
                    info_array := cast(*Type_Info_Array) any.type;

                    count: s64;
                    data: *void;
                    if info_array.array_type == .FIXED {
                        count = info_array.array_count;
                        data  = any.value_pointer;
                    } else {
                        count = << cast(*s64)  (any.value_pointer);
                        data  = << cast(**void)(any.value_pointer + 8);
                    }

                    to_print := count;
                    limit := 64;
                    if limit >= 0 then to_print = min(to_print, limit);

                    elem_type := info_array.element_type;
                    for 0..to_print-1 {
                        pointer := data + info_array.element_type.runtime_size * it;
                        item: Any = ---;
                        item.type = elem_type;
                        item.value_pointer = pointer;

                        layout.depth += 1;
                        draw_type_info(tprint("[%]", it), item, layout, nav);
                        layout.depth -= 1;
                    }
            }
        }
    }

    nav: Nav;
    draw_type_info("[root]", state.nav_history[state.nav_history.count-1], *layout, *nav);

    if nav.forward_request.value_pointer {
        if nav.forward_request.type.type == {
            case .STRUCT; #through;
            case .ARRAY;
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

CITIES :: string.[
    "Tokyo, Japan",
    "Delhi, India",
    "Shanghai, China",
    "São Paulo, Brazil",
    "Mexico City, Mexico",
    "Cairo, Egypt",
    "Mumbai, India",
    "Beijing, China",
    "Dhaka, Bangladesh",
    "Osaka, Japan",
    "New York City, United States",
    "Tehran, Iran",
    "Karachi, Pakistan",
    "Buenos Aires, Argentina",
    "Chongqing, China",
    "Istanbul, Turkey",
    "Kolkata, India",
    "Manila, Philippines",
    "Lagos, Nigeria",
    "Rio de Janeiro, Brazil",
    "Tianjin, China",
    "Kinshasa, DR Congo",
    "Guangzhou, China",
    "Los Angeles, United States",
    "Moscow, Russia",
    "Shenzhen, China",
    "Lahore, Pakistan",
    "Bangalore, India",
    "Paris, France",
    "Bogotá, Colombia",
    "Jakarta, Indonesia",
    "Chennai, India",
    "Lima, Peru",
    "Bangkok, Thailand",
    "Seoul, South Korea",
    "Nagoya, Japan",
    "Hyderabad, India",
    "London, United Kingdom",
    "Chicago, United States",
    "Chengdu, China",
    "Nanjing, China",
    "Wuhan, China",
    "Ho Chi Minh City, Vietnam",
    "Luanda, Angola",
    "Ahmedabad, India",
    "Kuala Lumpur, Malaysia",
    "Xi'an, China",
    "Hong Kong, Hong Kong",
    "Dongguan, China",
    "Hangzhou, China",
    "Foshan, China",
    "Shenyang, China",
    "Riyadh, Saudi Arabia",
    "Baghdad, Iraq",
    "Santiago, Chile",
    "Surat, India",
    "Madrid, Spain",
    "Suzhou, China",
    "Pune, India",
    "Harbin, China",
    "Houston, United States",
    "Dallas, United States",
    "Toronto, Canada",
    "Dar es Salaam, Tanzania",
    "Miami, United States",
    "Belo Horizonte, Brazil",
    "Singapore, Singapore",
    "Philadelphia, United States",
    "Atlanta, United States",
    "Fukuoka, Japan",
    "Khartoum, Sudan",
    "Barcelona, Spain",
    "Johannesburg, South Africa",
    "Yangon, Myanmar",
    "Guadalajara, Mexico",
];