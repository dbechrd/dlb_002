font: *Simp.Dynamic_Font;

dlb_init_fonts :: (window_size: Size) {
    if font != null {
        Simp.release_font(font);
    }

    pixel_height := window_size.y / 36;

    // @Cleanup: Don't have path + name be separate.
    font = Simp.get_font_at_size(".", "KarminaBold.otf", pixel_height);
    assert(font != null);
}