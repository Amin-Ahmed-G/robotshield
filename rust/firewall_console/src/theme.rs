//! Visual design for the console: a dark monitoring-tool theme plus a few
//! reusable building blocks (cards, KPI tiles, status chips).

use eframe::egui::{self, Color32, CornerRadius, FontId, Margin, RichText, Stroke, TextStyle};

// Surfaces
pub const BG: Color32 = Color32::from_rgb(0x0f, 0x11, 0x15);
pub const PANEL: Color32 = Color32::from_rgb(0x14, 0x17, 0x1c);
pub const CARD: Color32 = Color32::from_rgb(0x1a, 0x1e, 0x25);
pub const CARD_HI: Color32 = Color32::from_rgb(0x22, 0x27, 0x30);
pub const BORDER: Color32 = Color32::from_rgb(0x2a, 0x30, 0x3a);

// Text
pub const TEXT: Color32 = Color32::from_rgb(0xe8, 0xea, 0xee);
pub const TEXT2: Color32 = Color32::from_rgb(0xa9, 0xb0, 0xbc);
pub const MUTED: Color32 = Color32::from_rgb(0x6f, 0x78, 0x86);

// Accent + status (status colors are never reused for data series)
pub const ACCENT: Color32 = Color32::from_rgb(0x39, 0x87, 0xe5);
pub const GOOD: Color32 = Color32::from_rgb(0x3f, 0xb9, 0x50);
pub const WARN: Color32 = Color32::from_rgb(0xd9, 0x9a, 0x1e);
pub const CRIT: Color32 = Color32::from_rgb(0xe5, 0x53, 0x4b);

/// Data series: joints (fixed order) and the traffic chart.
pub const SERIES: [Color32; 4] = [
    Color32::from_rgb(0x39, 0x87, 0xe5), // blue
    Color32::from_rgb(0x19, 0x9e, 0x70), // aqua
    Color32::from_rgb(0x90, 0x85, 0xe9), // violet
    Color32::from_rgb(0xd5, 0x51, 0x81), // magenta
];
pub const FORWARDED: Color32 = Color32::from_rgb(0x39, 0x87, 0xe5);
pub const BLOCKED: Color32 = Color32::from_rgb(0xd9, 0x59, 0x26);

pub fn apply(ctx: &egui::Context) {
    ctx.set_theme(egui::Theme::Dark);
    ctx.all_styles_mut(|style| {
        style.text_styles = [
            (TextStyle::Heading, FontId::proportional(17.0)),
            (TextStyle::Body, FontId::proportional(13.5)),
            (TextStyle::Button, FontId::proportional(13.5)),
            (TextStyle::Small, FontId::proportional(11.0)),
            (TextStyle::Monospace, FontId::monospace(12.5)),
        ]
        .into();
        style.spacing.item_spacing = egui::vec2(8.0, 7.0);
        style.spacing.button_padding = egui::vec2(12.0, 5.0);
        style.spacing.interact_size.y = 26.0;

        let v = &mut style.visuals;
        v.panel_fill = PANEL;
        v.window_fill = CARD;
        v.extreme_bg_color = BG;
        v.faint_bg_color = CARD_HI;
        v.window_stroke = Stroke::new(1.0, BORDER);
        v.window_corner_radius = CornerRadius::same(10);
        v.override_text_color = Some(TEXT);
        v.hyperlink_color = ACCENT;
        v.selection.bg_fill = ACCENT.gamma_multiply(0.45);
        v.selection.stroke = Stroke::new(1.0, ACCENT);
        v.striped = true;
        let r = CornerRadius::same(6);
        for w in [&mut v.widgets.inactive, &mut v.widgets.hovered, &mut v.widgets.active,
                  &mut v.widgets.open, &mut v.widgets.noninteractive] {
            w.corner_radius = r;
        }
        v.widgets.noninteractive.bg_stroke = Stroke::new(1.0, BORDER);
        v.widgets.inactive.bg_fill = CARD_HI;
        v.widgets.inactive.weak_bg_fill = CARD_HI;
        v.widgets.inactive.bg_stroke = Stroke::new(1.0, BORDER);
        v.widgets.hovered.bg_fill = Color32::from_rgb(0x2b, 0x31, 0x3c);
        v.widgets.hovered.weak_bg_fill = Color32::from_rgb(0x2b, 0x31, 0x3c);
        v.widgets.hovered.bg_stroke = Stroke::new(1.0, ACCENT.gamma_multiply(0.7));
        v.widgets.active.bg_fill = ACCENT.gamma_multiply(0.6);
        v.widgets.active.weak_bg_fill = ACCENT.gamma_multiply(0.6);
    });
}

/// A titled card section.
pub fn card<R>(ui: &mut egui::Ui, title: &str, add: impl FnOnce(&mut egui::Ui) -> R) -> R {
    egui::Frame::new()
        .fill(CARD)
        .stroke(Stroke::new(1.0, BORDER))
        .corner_radius(CornerRadius::same(10))
        .inner_margin(Margin::same(14))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.vertical(|ui| {
                if !title.is_empty() {
                    ui.label(RichText::new(title.to_uppercase()).size(11.5).strong().color(MUTED));
                    ui.add_space(4.0);
                }
                add(ui)
            })
            .inner
        })
        .inner
}

/// Small rounded label, e.g. a severity or state badge.
pub fn chip(ui: &mut egui::Ui, text: &str, color: Color32) -> egui::Response {
    egui::Frame::new()
        .fill(color.gamma_multiply(0.18))
        .stroke(Stroke::new(1.0, color.gamma_multiply(0.55)))
        .corner_radius(CornerRadius::same(5))
        .inner_margin(Margin::symmetric(7, 2))
        .show(ui, |ui| ui.label(RichText::new(text).size(11.5).strong().color(color)))
        .response
}

/// KPI tile: caption, big value, optional sub line.
pub fn kpi(ui: &mut egui::Ui, width: f32, caption: &str, value: &str, color: Color32, sub: &str) {
    egui::Frame::new()
        .fill(CARD)
        .stroke(Stroke::new(1.0, BORDER))
        .corner_radius(CornerRadius::same(10))
        .inner_margin(Margin::symmetric(14, 10))
        .show(ui, |ui| {
            // Frame adds 2 x 14 px margin + 2 x 1 px stroke around the content.
            ui.set_width(width - 30.0);
            ui.vertical(|ui| {
                ui.spacing_mut().item_spacing.y = 2.0;
                ui.label(RichText::new(caption.to_uppercase()).size(11.0).strong().color(MUTED));
                ui.label(RichText::new(value).size(24.0).strong().color(color));
                ui.label(RichText::new(if sub.is_empty() { " " } else { sub }).size(11.5).color(TEXT2));
            });
        });
}

/// Colored dot followed by text (connection / state indicators).
pub fn dot_label(ui: &mut egui::Ui, color: Color32, text: impl Into<String>) {
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 6.0;
        let (rect, _) = ui.allocate_exact_size(egui::vec2(9.0, 9.0), egui::Sense::hover());
        ui.painter().circle_filled(rect.center(), 4.5, color);
        ui.label(RichText::new(text.into()).color(TEXT2));
    });
}

pub fn severity(level: u8) -> (&'static str, Color32) {
    match level {
        2 => ("CRITICAL", CRIT),
        1 => ("WARNING", WARN),
        _ => ("INFO", GOOD),
    }
}
