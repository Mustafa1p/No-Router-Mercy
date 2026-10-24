use crate::config::{load_config, save_config};
use crate::export::save_to_file;
use crate::models::{AppState, Config, FilterRule, ScanResult};
use crate::scanner::{start_scan, ScanMsg, ScanStats as ScannerStats};
use crossbeam_channel::Receiver;
use egui::{Button, Color32, ScrollArea, TextEdit, Ui};

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

// ─── Tabs ─────────────────────────────────────────────────────────────────────

#[derive(PartialEq, Clone, Copy)]
enum Tab {
    Realtime,
    Good,
    Search,
}

// ─── Settings dialog state ────────────────────────────────────────────────────

#[derive(Default)]
struct SettingsWindow {
    open: bool,
    tab: u8,
}

// ─── Main application struct ─────────────────────────────────────────────────

pub struct RouterScanApp {
    config: Config,
    logo: egui::TextureHandle,

    // Results
    all_results: Vec<ScanResult>,
    result_rows: HashMap<(String, u16), usize>,
    search_results: Vec<ScanResult>,
    current_tab: Tab,

    // Scanning
    state: AppState,
    stop_flag: Arc<AtomicBool>,
    pause_flag: Arc<AtomicBool>,
    scan_rx: Option<Receiver<ScanMsg>>,
    scan_stats: ScannerStats,
    elapsed_secs: u64,

    // Search
    search_text: String,
    search_case: bool,
    search_all: bool,

    // UI state
    settings_win: SettingsWindow,
    status_msg: String,
    scan_error: Option<String>,
    ports_text: String,
    ranges_text: String,
    range_editor_open: bool,
    filter_rules: Vec<FilterRule>,
    filter_win_open: bool,
    exclusions_text: String,
    excl_win_open: bool,
    selected_row: Option<(String, u16)>,
    details_open: bool,

    // Export dialog
    export_format: String,
    show_only_good: bool,
    device_filter: usize,
    ports_editor_open: bool,
    ports_draft: String,
    ports_error: Option<String>,
    selected_port: Option<usize>,
    selected_range: Option<usize>,
}

impl RouterScanApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        Self::with_config(&cc.egui_ctx, load_config())
    }

    fn with_config(ctx: &egui::Context, config: Config) -> Self {
        configure_theme(ctx);
        let icon = crate::app_icon();
        let logo = ctx.load_texture(
            "application-logo",
            egui::ColorImage::from_rgba_unmultiplied(
                [icon.width as usize, icon.height as usize],
                &icon.rgba,
            ),
            egui::TextureOptions::LINEAR,
        );
        let ports_text = config
            .ports
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join("\n");
        let ranges_text = config.ranges.join("\n");

        let filter_content = std::fs::read_to_string("filter.txt").unwrap_or_default();
        let filter_rules = crate::filter::parse_filter_rules(&filter_content);
        let exclusions_text = std::fs::read_to_string("exclusions.txt").unwrap_or_default();

        Self {
            config,
            logo,
            all_results: Vec::new(),
            result_rows: HashMap::new(),
            search_results: Vec::new(),
            current_tab: Tab::Realtime,
            state: AppState::Idle,
            stop_flag: Arc::new(AtomicBool::new(false)),
            pause_flag: Arc::new(AtomicBool::new(false)),
            scan_rx: None,
            scan_stats: Default::default(),
            elapsed_secs: 0,
            search_text: "Router".into(),
            search_case: false,
            search_all: true,
            settings_win: Default::default(),
            status_msg: "Ready.".into(),
            scan_error: None,
            ports_text,
            ranges_text,
            range_editor_open: false,
            filter_rules,
            filter_win_open: false,
            exclusions_text,
            excl_win_open: false,
            selected_row: None,
            details_open: false,
            export_format: "txt".into(),
            show_only_good: false,
            device_filter: 0,
            ports_editor_open: false,
            ports_draft: String::new(),
            ports_error: None,
            selected_port: None,
            selected_range: None,
        }
    }

    // ─── Drain incoming scan results ──────────────────────────────────────────

    fn poll_scan(&mut self) {
        let rx = match &self.scan_rx {
            Some(r) => r.clone(),
            None => return,
        };
        let mut count = 0;
        loop {
            match rx.try_recv() {
                Ok(ScanMsg::Result(r)) => {
                    upsert_result(&mut self.all_results, &mut self.result_rows, *r);
                    count += 1;
                    if count > 500 {
                        break;
                    } // cap batch size
                }
                Ok(ScanMsg::Stats(s)) => {
                    self.scan_stats = s.clone();
                    self.elapsed_secs = s.elapsed_secs;
                    if self.state == AppState::Scanning {
                        self.status_msg = format!("Scanning: {} / {}", s.completed, s.total);
                    }
                }
                Ok(ScanMsg::Error(error)) => {
                    self.scan_error = Some(error);
                    self.status_msg = "Scan could not start".into();
                    self.state = AppState::Idle;
                    self.scan_rx = None;
                    self.scan_stats = Default::default();
                    break;
                }
                Ok(ScanMsg::Done) => {
                    let stopped = self.stop_flag.load(Ordering::Relaxed);
                    self.state = AppState::Idle;
                    self.scan_stats.active_connect = 0;
                    self.scan_stats.active_process = 0;
                    self.stop_flag.store(false, Ordering::Relaxed);
                    self.pause_flag.store(false, Ordering::Relaxed);
                    self.scan_rx = None;
                    self.status_msg = format!(
                        "{}: {} / {}",
                        if stopped { "Stopped" } else { "Complete" },
                        self.scan_stats.completed,
                        self.scan_stats.total
                    );
                    save_config(&self.config);
                    break;
                }
                Err(crossbeam_channel::TryRecvError::Disconnected) => {
                    self.state = AppState::Idle;
                    self.scan_rx = None;
                    self.scan_stats.active_connect = 0;
                    self.scan_stats.active_process = 0;
                    self.status_msg = "Scan worker disconnected".into();
                    for row in &mut self.all_results {
                        if row.is_loading() {
                            row.status = "Interrupted".into();
                            row.info = "Worker disconnected before completion".into();
                        }
                    }
                    break;
                }
                Err(crossbeam_channel::TryRecvError::Empty) => break,
            }
        }
    }

    fn good_results(&self) -> Vec<&ScanResult> {
        self.all_results
            .iter()
            .filter(|r| r.is_found() && r.is_good())
            .collect()
    }

    fn do_start_scan(&mut self) {
        self.scan_error = None;
        self.config.ports = match parse_ports(&self.ports_text) {
            Ok(ports) => ports,
            Err(error) => {
                self.status_msg = "Scan could not start".into();
                self.scan_error = Some(error);
                return;
            }
        };
        self.config.ranges = self
            .ranges_text
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect();
        if self.config.ports.is_empty() {
            self.status_msg = "Scan could not start".into();
            self.scan_error = Some("Add at least one valid scan port.".into());
            return;
        }
        if self.config.ranges.is_empty() {
            self.status_msg = "Scan could not start".into();
            self.scan_error = Some("Add at least one IP address or range.".into());
            return;
        }

        self.all_results.clear();
        self.result_rows.clear();
        self.search_results.clear();
        self.selected_row = None;
        self.current_tab = Tab::Realtime;
        self.scan_stats = Default::default();
        self.elapsed_secs = 0;
        self.stop_flag.store(false, Ordering::Relaxed);
        self.pause_flag.store(false, Ordering::Relaxed);

        let cfg = Arc::new(self.config.clone());
        let rx = start_scan(cfg, self.stop_flag.clone(), self.pause_flag.clone());
        self.scan_rx = Some(rx);
        self.state = AppState::Scanning;
        self.status_msg = "Scanning…".into();
    }

    fn do_stop_scan(&mut self) {
        self.stop_flag.store(true, Ordering::Relaxed);
        self.state = AppState::Stopping;
        self.status_msg = "Stopping…".into();
    }

    fn do_pause_toggle(&mut self) {
        if self.state == AppState::Paused {
            self.pause_flag.store(false, Ordering::Relaxed);
            self.state = AppState::Scanning;
            self.status_msg = "Resumed.".into();
        } else {
            self.pause_flag.store(true, Ordering::Relaxed);
            self.state = AppState::Paused;
            self.status_msg = "Paused.".into();
        }
    }

    fn do_search(&mut self) {
        let text = &self.search_text.clone();
        if text.is_empty() {
            self.search_results.clear();
            return;
        }
        let source: Vec<ScanResult> = if self.search_all {
            self.all_results.clone()
        } else {
            match self.current_tab {
                Tab::Good => self
                    .all_results
                    .iter()
                    .filter(|r| r.is_good())
                    .cloned()
                    .collect(),
                Tab::Search => self.search_results.clone(),
                Tab::Realtime => self.all_results.clone(),
            }
        };
        let results = if self.search_case {
            source
                .iter()
                .filter(|r| r.is_found() && row_contains(r, text))
                .cloned()
                .collect()
        } else {
            let lower = text.to_ascii_lowercase();
            source
                .iter()
                .filter(|r| r.is_found() && row_contains_ci(r, &lower))
                .cloned()
                .collect()
        };
        self.search_results = results;
        self.current_tab = Tab::Search;
    }

    fn result_visible(&self, r: &ScanResult) -> bool {
        r.is_found()
            && (!(self.show_only_good || self.current_tab == Tab::Good) || r.is_good())
            && match self.device_filter {
                1 => {
                    !r.ssid.is_empty()
                        || !r.bssid.is_empty()
                        || r.device_type.to_ascii_lowercase().contains("router")
                }
                2 => !r.auth.is_empty(),
                3 => r.ssid.is_empty() && r.bssid.is_empty(),
                _ => true,
            }
    }

    fn do_export(&mut self) {
        let source = if self.current_tab == Tab::Search {
            &self.search_results
        } else {
            &self.all_results
        };
        let results: Vec<ScanResult> = source
            .iter()
            .filter(|r| self.result_visible(r))
            .cloned()
            .collect();
        let name = crate::export::timestamped_filename(&self.export_format);
        match save_to_file(&results, &name, &self.export_format) {
            Ok(()) => self.status_msg = format!("Exported to {}", name),
            Err(e) => self.status_msg = format!("Export error: {}", e),
        }
    }

    // ─── Top panel ────────────────────────────────────────────────────────────

    fn ui_navigation(&mut self, ui: &mut Ui) {
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 4.0;
            ui.add(egui::Image::new(&self.logo).fit_to_exact_size(egui::vec2(38.0, 38.0)))
                .on_hover_text(crate::APP_TITLE);
            ui.add_space(4.0);
            for (label, icon, tab, width) in [
                ("Scanner", "wifi", None, 135.0),
                ("Realtime Stats", "stats", Some(Tab::Realtime), 160.0),
                ("Good Results", "good", Some(Tab::Good), 154.0),
                ("Search Results", "search", Some(Tab::Search), 168.0),
            ] {
                if icon_button(
                    ui,
                    label,
                    icon,
                    egui::vec2(width, 42.0),
                    tab.is_none(),
                    false,
                )
                .clicked()
                {
                    if let Some(tab) = tab {
                        self.current_tab = tab;
                    }
                }
            }
            if icon_button(
                ui,
                "Settings",
                "settings",
                egui::vec2(132.0, 42.0),
                false,
                false,
            )
            .clicked()
            {
                self.settings_win.open = true;
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.menu_button("Menu  ▾", |ui| {
                    if ui.button("Settings…").clicked() {
                        self.settings_win.open = true;
                        ui.close_menu();
                    }
                    if ui.button("Filter Rules…").clicked() {
                        self.filter_win_open = true;
                        ui.close_menu();
                    }
                    if ui.button("IP Exclusions…").clicked() {
                        self.excl_win_open = true;
                        ui.close_menu();
                    }
                    if ui.button("Edit Ports…").clicked() {
                        self.open_ports_editor();
                        ui.close_menu();
                    }
                });
                ui.label(
                    egui::RichText::new(env!("CARGO_PKG_VERSION"))
                        .size(11.0)
                        .weak(),
                )
                .on_hover_text(crate::APP_TITLE);
            });
        });
        let r = ui.max_rect();
        ui.painter()
            .hline(r.x_range(), r.bottom(), egui::Stroke::new(1.5, BLUE));
    }

    fn open_ports_editor(&mut self) {
        self.ports_draft = self.ports_text.clone();
        self.ports_error = None;
        self.ports_editor_open = true;
    }

    fn ui_top_panel(&mut self, ui: &mut Ui) {
        let origin = ui.cursor().min;
        let gap = 7.0;
        let width = ui.available_width();
        let scale = (width - gap * 5.0) / 1497.0;
        let mut x = origin.x;
        for (index, base) in [257.0, 222.0, 346.0, 206.0, 233.0, 233.0]
            .iter()
            .enumerate()
        {
            let w = base * scale;
            let rect = egui::Rect::from_min_size(egui::pos2(x, origin.y), egui::vec2(w, 207.0));
            ui.painter()
                .rect(rect, 5.0, PANEL, egui::Stroke::new(1.0, BORDER));
            ui.allocate_new_ui(
                egui::UiBuilder::new()
                    .max_rect(rect.shrink2(egui::vec2(13.0, 10.0)))
                    .layout(egui::Layout::top_down(egui::Align::Min)),
                |ui| {
                    ui.set_clip_rect(rect.shrink(2.0));
                    ui.set_width(w - 26.0);
                    ui.spacing_mut().item_spacing.y = 4.0;
                    ui.strong(
                        [
                            "Scan Control",
                            "Scan Ports",
                            "IP Ranges to Scan",
                            "Search",
                            "Credentials",
                            "Scanning Modules",
                        ][index],
                    );
                    ui.add_space(9.0);
                    match index {
                        0 => {
                            let idle = self.state == AppState::Idle;
                            let label = if idle {
                                "Start Scan"
                            } else if self.state == AppState::Stopping {
                                "Stopping…"
                            } else {
                                "Stop Scan"
                            };
                            if icon_button(
                                ui,
                                label,
                                if idle { "play" } else { "stop" },
                                egui::vec2(w - 26.0, 51.0),
                                false,
                                idle,
                            )
                            .clicked()
                            {
                                if idle {
                                    self.do_start_scan();
                                } else {
                                    self.do_stop_scan();
                                }
                            }
                            ui.add_space(15.0);
                            egui::Grid::new("scan_values")
                                .spacing([10.0, 6.0])
                                .show(ui, |ui| {
                                    ui.label("Threads:");
                                    ui.add_sized(
                                        [100.0 * scale, 32.0],
                                        egui::DragValue::new(&mut self.config.threads)
                                            .range(1..=2000),
                                    );
                                    ui.end_row();
                                    ui.label("Timeout (ms):");
                                    ui.add_sized(
                                        [100.0 * scale, 32.0],
                                        egui::DragValue::new(&mut self.config.connect_timeout_ms)
                                            .range(100..=30000),
                                    );
                                    ui.end_row();
                                });
                            if matches!(self.state, AppState::Scanning | AppState::Paused)
                                && ui
                                    .small_button(if self.state == AppState::Paused {
                                        "Resume"
                                    } else {
                                        "Pause"
                                    })
                                    .clicked()
                            {
                                self.do_pause_toggle();
                            }
                        }
                        1 => match ports_panel(ui, &self.ports_text, &mut self.selected_port) {
                            PortAction::Edit => self.open_ports_editor(),
                            PortAction::Remove => {
                                let mut ports: Vec<_> =
                                    self.ports_text.lines().map(str::to_owned).collect();
                                if let Some(i) = self.selected_port.filter(|&i| i < ports.len()) {
                                    ports.remove(i);
                                    self.selected_port = if ports.is_empty() {
                                        None
                                    } else {
                                        Some(i.min(ports.len() - 1))
                                    };
                                    self.ports_text = ports.join("\n");
                                    self.config.ports = self
                                        .ports_text
                                        .lines()
                                        .filter_map(|p| p.trim().parse().ok())
                                        .collect();
                                }
                            }
                            PortAction::None => {}
                        },
                        2 => match ranges_panel(ui, &self.ranges_text, &mut self.selected_range) {
                            RangeAction::Edit => self.range_editor_open = true,
                            RangeAction::Remove => {
                                let mut ranges: Vec<_> =
                                    self.ranges_text.lines().map(str::to_owned).collect();
                                if let Some(i) = self.selected_range.filter(|&i| i < ranges.len()) {
                                    ranges.remove(i);
                                }
                                self.ranges_text = ranges.join("\n");
                                self.selected_range = None;
                                self.config.ranges = ranges;
                            }
                            RangeAction::Clear => {
                                self.ranges_text.clear();
                                self.config.ranges.clear();
                                self.selected_range = None;
                            }
                            RangeAction::None => {}
                        },
                        3 => {
                            ui.add_sized(
                                [w - 26.0, 39.0],
                                TextEdit::singleline(&mut self.search_text),
                            );
                            ui.add_space(13.0);
                            themed_checkbox(ui, &mut self.search_case, "Case sensitive");
                            themed_checkbox(ui, &mut self.search_all, "Search All");
                            ui.add_space(8.0);
                            if icon_button(
                                ui,
                                "Search",
                                "search",
                                egui::vec2(w - 26.0, 40.0),
                                true,
                                false,
                            )
                            .clicked()
                            {
                                self.do_search();
                            }
                        }
                        4 => {
                            themed_checkbox(
                                ui,
                                &mut self.config.use_credentials,
                                "Use Credentials",
                            );
                            ui.add_space(7.0);
                            ui.label("Username:");
                            ui.add_sized(
                                [w - 26.0, 33.0],
                                TextEdit::singleline(&mut self.config.cred_user),
                            );
                            ui.add_space(3.0);
                            ui.label("Password:");
                            ui.add_sized(
                                [w - 26.0, 33.0],
                                TextEdit::singleline(&mut self.config.cred_pass),
                            );
                        }
                        _ => {
                            egui::Frame::none()
                                .fill(INPUT)
                                .stroke(egui::Stroke::new(1.0, FIELD_BORDER))
                                .rounding(4.0)
                                .inner_margin(5.0)
                                .show(ui, |ui| {
                                    ui.set_min_size(egui::vec2(w - 38.0, 146.0));
                                    ui.spacing_mut().item_spacing.y = 2.0;
                                    ui.spacing_mut().interact_size.y = 22.0;
                                    ScrollArea::vertical()
                                        .id_salt("modules")
                                        .max_height(146.0)
                                        .auto_shrink([false, false])
                                        .show(ui, |ui| {
                                            themed_checkbox(
                                                ui,
                                                &mut self.config.mod_router_scan,
                                                "RouterScan",
                                            );
                                            themed_checkbox(ui, &mut self.config.mod_hnap, "HNAP");
                                            themed_checkbox(
                                                ui,
                                                &mut self.config.mod_proxy_check,
                                                "ProxyCheck",
                                            );
                                            themed_checkbox(
                                                ui,
                                                &mut self.config.mod_sqlite,
                                                "SQLite Manager",
                                            );
                                            themed_checkbox(
                                                ui,
                                                &mut self.config.mod_hudson,
                                                "Hudson Java Servlet",
                                            );
                                            themed_checkbox(
                                                ui,
                                                &mut self.config.mod_pma,
                                                "PMA (phpMyAdmin)",
                                            );
                                            themed_checkbox(
                                                ui,
                                                &mut self.config.mod_pedrib,
                                                "🔓 pedrib/PoC exploits",
                                            );
                                            themed_checkbox(
                                                ui,
                                                &mut self.config.mod_rs_exploits,
                                                "🛡 RS classic exploits",
                                            );
                                        });
                                });
                        }
                    }
                },
            );
            x += w + gap;
        }
        ui.advance_cursor_after_rect(egui::Rect::from_min_size(origin, egui::vec2(width, 207.0)));
        ui.add_space(7.0);
        egui::Frame::none()
            .fill(PANEL)
            .stroke(egui::Stroke::new(1.0, BORDER))
            .rounding(5.0)
            .inner_margin(10.0)
            .show(ui, |ui| {
                ui.set_width(width - 20.0);
                ui.horizontal_wrapped(|ui| {
                    ui.strong("Controls:");
                    ui.separator();
                    ui.label("Ports:");
                    let ports = parse_ports(&self.ports_text).unwrap_or_default();
                    egui::ComboBox::from_id_salt("ports_presets")
                        .width(205.0)
                        .truncate()
                        .selected_text(crate::port_presets::summary(&ports))
                        .show_ui(ui, |ui| {
                            ui.label("TCP port profiles");
                            for preset in crate::port_presets::presets() {
                                let label = format!("{} ({})", preset.name, preset.ports.len());
                                if ui
                                    .selectable_label(
                                        crate::port_presets::summary(&ports) == label,
                                        label,
                                    )
                                    .on_hover_text(preset.description)
                                    .clicked()
                                {
                                    self.config.ports = preset.ports.to_vec();
                                    self.ports_text = preset
                                        .ports
                                        .iter()
                                        .map(u16::to_string)
                                        .collect::<Vec<_>>()
                                        .join("\n");
                                    self.selected_port = None;
                                    ui.close_menu();
                                }
                            }
                            ui.separator();
                            if ui.button("Custom / Edit ports…").clicked() {
                                self.open_ports_editor();
                                ui.close_menu();
                            }
                            ui.small("Top lists: Nmap TCP frequency. Categories: curated.");
                            ui.small("Port labels are hints; services can use other ports.");
                        }).response.on_hover_text("Choose a TCP profile for the next scan. Existing scan targets are unchanged.");
                    ui.label("IP Ranges:");
                    let count = self
                        .ranges_text
                        .lines()
                        .filter(|r| !r.trim().is_empty())
                        .count();
                    if ui
                        .add_sized([100.0, 34.0], Button::new(format!("{count} ranges · Edit")))
                        .on_hover_text("Add, edit or paste IP ranges")
                        .clicked()
                    {
                        self.range_editor_open = true;
                    }
                    ui.label("Device Filter:");
                    egui::ComboBox::from_id_salt("device_filter")
                        .width(168.0 * scale)
                        .selected_text(
                            [
                                "All Devices",
                                "Routers / Wireless",
                                "Authorized",
                                "Other Devices",
                            ][self.device_filter],
                        )
                        .show_ui(ui, |ui| {
                            for (i, label) in [
                                "All Devices",
                                "Routers / Wireless",
                                "Authorized",
                                "Other Devices",
                            ]
                            .iter()
                            .enumerate()
                            {
                                ui.selectable_value(&mut self.device_filter, i, *label);
                            }
                        });
                    themed_checkbox(ui, &mut self.show_only_good, "Show Only Good Results");
                    ui.horizontal(|ui| {
                        ui.menu_button("Export  ▾", |ui| {
                            for fmt in ["txt", "csv", "json", "ipport"] {
                                if ui.button(fmt.to_uppercase()).clicked() {
                                    self.export_format = fmt.into();
                                    self.do_export();
                                    ui.close_menu();
                                }
                            }
                        });
                        if icon_button(ui, "Clear", "trash", egui::vec2(100.0, 35.0), false, false)
                            .clicked()
                        {
                            self.all_results.clear();
                            self.result_rows.clear();
                            self.search_results.clear();
                            self.selected_row = None;
                        }
                    });
                });
            });
    }

    fn ui_tables(&mut self, ui: &mut Ui) {
        use crate::result_table::{clipboard, values, widths, COLUMNS};
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 3.0;
            for (tab, label, icon, width) in [
                (
                    Tab::Realtime,
                    format!("Found Results ({})", found_result_count(&self.all_results)),
                    "wifi",
                    198.0,
                ),
                (
                    Tab::Good,
                    format!("Good Results ({})", self.good_results().len()),
                    "good",
                    172.0,
                ),
                (
                    Tab::Search,
                    format!(
                        "Search Results ({})",
                        found_result_count(&self.search_results)
                    ),
                    "search",
                    180.0,
                ),
            ] {
                if icon_button(
                    ui,
                    &label,
                    icon,
                    egui::vec2(width, 40.0),
                    self.current_tab == tab,
                    false,
                )
                .clicked()
                {
                    self.current_tab = tab;
                }
            }
        });
        let source = if self.current_tab == Tab::Search {
            &self.search_results
        } else {
            &self.all_results
        };
        let results: Vec<&ScanResult> = source.iter().filter(|r| self.result_visible(r)).collect();
        let selected_key = self.selected_row.clone();
        let selected = results.iter().copied().find(|r| {
            selected_key
                .as_ref()
                .is_some_and(|(ip, port)| r.ip == *ip && r.port == *port)
        });
        ui.horizontal(|ui| {
            if ui
                .add_enabled(selected.is_some(), Button::new("Copy row"))
                .clicked()
            {
                ui.ctx().copy_text(clipboard(&[selected.unwrap()], false));
            }
            if ui
                .add_enabled(selected.is_some(), Button::new("Copy IP:port"))
                .clicked()
            {
                let r = selected.unwrap();
                ui.ctx().copy_text(format!("{}:{}", r.ip, r.port));
            }
            if ui
                .add_enabled(!results.is_empty(), Button::new("Copy all"))
                .clicked()
            {
                ui.ctx().copy_text(clipboard(&results, true));
            }
            if ui
                .add_enabled(selected.is_some(), Button::new("Full details"))
                .clicked()
            {
                self.details_open = true;
            }
            ui.label(
                egui::RichText::new("Double-click a cell to copy; Ctrl+C copies the selected row.")
                    .weak()
                    .size(12.0),
            );
        });
        if !ui.ctx().wants_keyboard_input()
            && ui.input(|i| i.modifiers.command && i.key_pressed(egui::Key::C))
        {
            if let Some(row) = selected {
                ui.ctx().copy_text(clipboard(&[row], false));
            }
        }
        let available_height = ui.available_height().max(100.0);
        egui::Frame::none().fill(PANEL).stroke(egui::Stroke::new(1.0,FIELD_BORDER)).rounding(4.0).show(ui,|ui| {
            ui.spacing_mut().item_spacing.y=0.0;
            ui.set_min_height(available_height-2.0);
            let content_width=(ui.available_width()-ui.spacing().scroll.allocated_width()-2.0).max(100.0);
            let widths=widths(content_width);
            let (header,_)=ui.allocate_exact_size(egui::vec2(content_width,54.0),egui::Sense::hover());
            ui.painter().rect_filled(header,0.0,INPUT);
            let mut x=header.left();
            for ((name,_),width) in COLUMNS.iter().zip(&widths) {
                let cell=egui::Rect::from_min_size(egui::pos2(x,header.top()),egui::vec2(*width,header.height()));
                paint_table_text(ui.painter(),name,cell.shrink2(egui::vec2(4.0,3.0)),12.0,TEXT);
                ui.painter().vline(cell.right(),cell.y_range(),egui::Stroke::new(1.0,BORDER));
                x+=width;
            }
            ScrollArea::vertical().id_salt("fit_results_vertical")
                .scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::AlwaysVisible)
                .auto_shrink([false,false]).max_height((available_height-58.0).max(40.0))
                .stick_to_bottom(match self.current_tab { Tab::Good=>self.config.follow_good,_=>self.config.follow_realtime })
                .show_rows(ui,50.0,results.len(),|ui,range| {
                    for index in range {
                        let r=results[index]; let key=(r.ip.clone(),r.port);
                        let (rect,hover)=ui.allocate_exact_size(egui::vec2(content_width,50.0),egui::Sense::hover());
                        let is_selected=self.selected_row.as_ref()==Some(&key);
                        if is_selected || hover.hovered() { ui.painter().rect_filled(rect,0.0,Color32::from_rgb(27,52,75)); }
                        else if index%2==1 { ui.painter().rect_filled(rect,0.0,Color32::from_rgb(20,30,38)); }
                        let data=values(r); let mut x=rect.left();
                        for (column,(value,width)) in data.iter().zip(&widths).enumerate() {
                            let cell=egui::Rect::from_min_size(egui::pos2(x,rect.top()),egui::vec2(*width,50.0));
                            let response=ui.interact(cell,ui.id().with((&r.ip,r.port,column)),egui::Sense::click());
                            if response.clicked() { self.selected_row=Some(key.clone()); }
                            if response.double_clicked() { self.selected_row=Some(key.clone()); ui.ctx().copy_text(value.clone()); }
                            response.clone().on_hover_text(if column==3 && r.inspection_failed() {
                                format!("TCP port is confirmed open.\nInspection: {}\n{}",r.status,r.info)
                            } else if value.is_empty() { "No value reported".into() } else { value.clone() });
                            response.context_menu(|ui| {
                                if ui.button("Copy value").clicked() { ui.ctx().copy_text(value.clone()); ui.close_menu(); }
                                if ui.button("Copy row").clicked() { ui.ctx().copy_text(clipboard(&[r],false)); ui.close_menu(); }
                                if ui.button("Copy IP:port").clicked() { ui.ctx().copy_text(format!("{}:{}",r.ip,r.port)); ui.close_menu(); }
                                if ui.button("Full details").clicked() { self.selected_row=Some(key.clone()); self.details_open=true; ui.close_menu(); }
                            });
                            let color=if column==3 { status_color(r) } else { TEXT };
                            paint_table_text(ui.painter(),if value.is_empty(){"—"}else{value},cell.shrink2(egui::vec2(4.0,3.0)),11.5,color);
                            ui.painter().vline(cell.right(),cell.y_range(),egui::Stroke::new(1.0,BORDER));
                            x+=width;
                        }
                        ui.painter().hline(rect.x_range(),rect.bottom(),egui::Stroke::new(1.0,BORDER));
                    }
                });
            if results.is_empty() {
                let message=if self.state!=AppState::Idle { "Scanning… confirmed open ports will appear here." }
                    else if self.all_results.iter().any(ScanResult::is_found) { "No discoveries match the current filters." }
                    else { "No open ports confirmed. Check the scan status and configured target range." };
                ui.painter().text(header.left_bottom()+egui::vec2(12.0,22.0),egui::Align2::LEFT_CENTER,message,egui::FontId::proportional(13.0),Color32::from_rgb(158,179,195));
            }
        });
    }

    fn ui_result_details(&mut self, ctx: &egui::Context) {
        if !self.details_open {
            return;
        }
        let Some((ip, port)) = &self.selected_row else {
            self.details_open = false;
            return;
        };
        let Some(row) = self
            .all_results
            .iter()
            .find(|r| &r.ip == ip && r.port == *port)
            .cloned()
        else {
            self.details_open = false;
            return;
        };
        let mut open = true;
        egui::Window::new(format!("Device details — {}:{}", row.ip, row.port))
            .open(&mut open)
            .default_size([760.0, 620.0])
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    if ui.button("Copy complete row").clicked() {
                        ui.ctx()
                            .copy_text(crate::result_table::clipboard(&[&row], true));
                    }
                    ui.label(format!("Inspection status: {}", row.status));
                });
                ScrollArea::vertical().show(ui, |ui| {
                    egui::Grid::new("complete_device_values")
                        .striped(true)
                        .num_columns(3)
                        .spacing([12.0, 8.0])
                        .show(ui, |ui| {
                            for ((name, _), value) in crate::result_table::COLUMNS
                                .iter()
                                .zip(crate::result_table::values(&row))
                            {
                                ui.strong(*name);
                                ui.add(
                                    egui::Label::new(if value.is_empty() { "—" } else { &value })
                                        .selectable(true)
                                        .wrap(),
                                );
                                if ui.small_button("Copy").clicked() {
                                    ui.ctx().copy_text(value);
                                }
                                ui.end_row();
                            }
                        });
                });
            });
        self.details_open = open;
    }

    fn ui_status_bar(&self, ui: &mut Ui) {
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 14.0;
            let color = if self.state == AppState::Idle {
                Color32::from_rgb(14, 181, 58)
            } else {
                BLUE
            };
            let (r, _) = ui.allocate_exact_size(egui::vec2(16.0, 18.0), egui::Sense::hover());
            ui.painter().circle_filled(r.center(), 7.0, color);
            ui.add_sized(
                [182.0, 20.0],
                egui::Label::new(self.status_msg.trim_end_matches('.')).truncate(),
            )
            .on_hover_text(format!(
                "{} checked / {} targets; {} open; {} failed; {} queued",
                self.scan_stats.completed,
                self.scan_stats.total,
                self.scan_stats.found,
                self.scan_stats.failed,
                self.scan_stats.queued
            ));
            ui.separator();
            status_item(
                ui,
                "people",
                BLUE,
                &format!(
                    "Active Threads: {} / {}",
                    self.scan_stats.active_connect + self.scan_stats.active_process,
                    self.config.threads
                ),
            );
            ui.separator();
            status_item(
                ui,
                "file",
                Color32::from_rgb(102, 139, 251),
                &format!("Total Found: {}", found_result_count(&self.all_results)),
            );
            status_item(
                ui,
                "check",
                Color32::from_rgb(14, 181, 58),
                &format!("Good: {}", self.good_results().len()),
            );
            ui.separator();
            status_item(
                ui,
                "clock",
                Color32::from_rgb(63, 136, 251),
                &format!("Work Time: {}", format_duration(self.elapsed_secs)),
            );
            status_item(
                ui,
                "clock",
                Color32::from_rgb(255, 158, 0),
                &format!("Total Time: {}", format_duration(self.elapsed_secs)),
            );
        });
    }

    // ─── Sub-windows ──────────────────────────────────────────────────────────

    fn ui_range_editor(&mut self, ctx: &egui::Context) {
        if !self.range_editor_open {
            return;
        }
        let mut open = self.range_editor_open;
        egui::Window::new("IP Range Editor")
            .open(&mut open)
            .min_size([420.0, 380.0])
            .show(ctx, |ui| {
                ui.label("Enter one range per line. Supported: single IP, A.B.C.D-E.F.G.H, CIDR /N, Nmap-octet.");
                ui.separator();
                ScrollArea::vertical().max_height(280.0).show(ui, |ui| {
                    ui.add(TextEdit::multiline(&mut self.ranges_text)
                        .desired_rows(15)
                        .desired_width(f32::INFINITY));
                });
                ui.separator();
                ui.horizontal(|ui| {
                    if ui.button("OK").clicked() {
                        // Validate + update config
                        self.config.ranges = self.ranges_text
                            .lines()
                            .map(|l| l.trim().to_string())
                            .filter(|l| !l.is_empty())
                            .collect();
                        self.range_editor_open = false;
                    }
                    if ui.button("Cancel").clicked() {
                        self.range_editor_open = false;
                    }
                    if ui.button("Import from file…").clicked() {
                        if let Some(path) = rfd::FileDialog::new()
                            .add_filter("Text", &["txt"])
                            .pick_file()
                        {
                            if let Ok(content) = std::fs::read_to_string(&path) {
                                self.ranges_text.push('\n');
                                self.ranges_text.push_str(content.trim());
                            }
                        }
                    }
                });
            });
        self.range_editor_open = open;
    }

    fn ui_filter_editor(&mut self, ctx: &egui::Context) {
        if !self.filter_win_open {
            return;
        }
        let mut open = self.filter_win_open;
        egui::Window::new("Filter Rules")
            .open(&mut open)
            .min_size([420.0, 340.0])
            .show(ctx, |ui| {
                ui.label("Rules: place TAB mode TAB pattern. Place: body/serv/relm. Mode: eq/neq/cnt/ncnt.");
                let mut text = crate::filter::serialize_filter_rules(&self.filter_rules);
                ui.add(TextEdit::multiline(&mut text)
                    .desired_rows(12)
                    .desired_width(f32::INFINITY));
                if text != crate::filter::serialize_filter_rules(&self.filter_rules) {
                    self.filter_rules = crate::filter::parse_filter_rules(&text);
                }
                ui.separator();
                ui.horizontal(|ui| {
                    if ui.button("Save & Close").clicked() {
                        let content = crate::filter::serialize_filter_rules(&self.filter_rules);
                        let _ = std::fs::write("filter.txt", content);
                        self.filter_win_open = false;
                    }
                    if ui.button("Cancel").clicked() {
                        self.filter_win_open = false;
                    }
                });
            });
        self.filter_win_open = open;
    }

    fn ui_exclusions_editor(&mut self, ctx: &egui::Context) {
        if !self.excl_win_open {
            return;
        }
        let mut open = self.excl_win_open;
        egui::Window::new("IP Exclusions")
            .open(&mut open)
            .min_size([320.0, 300.0])
            .show(ctx, |ui| {
                ui.label("One IP or IP:port per line. These addresses are skipped during scan.");
                ui.add(
                    TextEdit::multiline(&mut self.exclusions_text)
                        .desired_rows(12)
                        .desired_width(f32::INFINITY),
                );
                ui.separator();
                ui.horizontal(|ui| {
                    if ui.button("Save & Close").clicked() {
                        let _ = std::fs::write("exclusions.txt", &self.exclusions_text);
                        self.excl_win_open = false;
                    }
                    if ui.button("Cancel").clicked() {
                        self.excl_win_open = false;
                    }
                });
            });
        self.excl_win_open = open;
    }

    fn ui_settings(&mut self, ctx: &egui::Context) {
        if !self.settings_win.open {
            return;
        }
        let mut open = self.settings_win.open;
        egui::Window::new("Settings & Tweaks")
            .open(&mut open)
            .min_size([420.0, 400.0])
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    for (i, name) in ["General", "Port Scanner", "Output", "HTTP", "Tweaks"]
                        .iter()
                        .enumerate()
                    {
                        if ui
                            .selectable_label(self.settings_win.tab == i as u8, *name)
                            .clicked()
                        {
                            self.settings_win.tab = i as u8;
                        }
                    }
                });
                ui.separator();

                match self.settings_win.tab {
                    0 => self.ui_settings_general(ui),
                    1 => self.ui_settings_portscan(ui),
                    2 => self.ui_settings_output(ui),
                    3 => self.ui_settings_http(ui),
                    4 => self.ui_settings_tweaks(ui),
                    _ => {}
                }

                ui.separator();
                ui.horizontal(|ui| {
                    if ui.button("OK").clicked() {
                        save_config(&self.config);
                        self.settings_win.open = false;
                    }
                    if ui.button("Cancel").clicked() {
                        self.settings_win.open = false;
                    }
                });
            });
        self.settings_win.open = open;
    }

    fn ui_settings_general(&mut self, ui: &mut Ui) {
        ui.checkbox(
            &mut self.config.follow_realtime,
            "Follow last line (Realtime)",
        );
        ui.checkbox(&mut self.config.follow_good, "Follow last line (Good)");
        ui.separator();
        ui.label("Good Results filter flags (bitmask):");
        let mut flags = self.config.good_filter_flags as i32;
        ui.add(egui::DragValue::new(&mut flags).range(0..=255));
        self.config.good_filter_flags = flags.max(0) as u8;
        ui.separator();
        ui.label("Geolocation provider (0=off, 2=Yandex, 3=Google, 4=Mylnikov):");
        let mut geo = self.config.geolocation_provider as i32;
        ui.add(egui::DragValue::new(&mut geo).range(0..=6));
        self.config.geolocation_provider = geo.max(0) as u8;
    }

    fn ui_settings_portscan(&mut self, ui: &mut Ui) {
        ui.label("Scan mode:");
        ui.horizontal(|ui| {
            for (v, name) in [(0u8, "Normal"), (1, "Fast"), (2, "Ultra Fast")] {
                ui.radio_value(&mut self.config.scan_mode, v, name);
            }
        });
        ui.separator();
        ui.label("Thread timeout (minutes):");
        let mut tm = self.config.thread_timeout_min as i32;
        ui.add(egui::DragValue::new(&mut tm).range(1..=30));
        self.config.thread_timeout_min = tm.max(1) as u32;
        ui.separator();
        ui.label("Post-scan action:");
        let actions = [
            "Do nothing",
            "Close program",
            "Logoff",
            "Shutdown",
            "Suspend",
            "Hibernate",
        ];
        // stored as enum index — just show info
        for a in &actions {
            ui.label(format!("  • {}", a));
        }
        ui.label("(Post-scan action: configure in config.ini StopAction key)");
    }

    fn ui_settings_output(&mut self, ui: &mut Ui) {
        ui.checkbox(&mut self.config.autosave_enabled, "Auto-save results");
        ui.horizontal(|ui| {
            ui.label("Interval (sec):");
            let mut v = self.config.autosave_interval as i32;
            ui.add(egui::DragValue::new(&mut v).range(10..=3600));
            self.config.autosave_interval = v.max(10) as u32;
        });
        ui.horizontal(|ui| {
            ui.label("Format:");
            for fmt in &["txt", "csv", "json", "ipport"] {
                ui.radio_value(&mut self.config.autosave_format, fmt.to_string(), *fmt);
            }
        });
        ui.separator();
        ui.label("3WiFi upload server:");
        ui.text_edit_singleline(&mut self.config.upload_server);
        ui.label("Username:");
        ui.text_edit_singleline(&mut self.config.upload_username);
        ui.label("Password:");
        ui.add(TextEdit::singleline(&mut self.config.upload_password).password(true));
    }

    fn ui_settings_http(&mut self, ui: &mut Ui) {
        ui.label("Proxy type:");
        let types = [
            (0u8, "None"),
            (1, "HTTP"),
            (2, "HTTPS"),
            (3, "HTTP CONNECT"),
            (4, "SOCKS4"),
            (5, "SOCKS4a"),
            (6, "SOCKS5"),
        ];
        for (v, name) in &types {
            ui.radio_value(&mut self.config.proxy_type, *v, *name);
        }
        if self.config.proxy_type > 0 {
            ui.horizontal(|ui| {
                ui.label("IP:");
                ui.text_edit_singleline(&mut self.config.proxy_ip);
                ui.label("Port:");
                let mut p = self.config.proxy_port as i32;
                ui.add(egui::DragValue::new(&mut p).range(1..=65535));
                self.config.proxy_port = p.max(1) as u16;
            });
            ui.checkbox(
                &mut self.config.proxy_use_auth,
                "Proxy requires authentication",
            );
            if self.config.proxy_use_auth {
                ui.horizontal(|ui| {
                    ui.label("User:");
                    ui.text_edit_singleline(&mut self.config.proxy_user);
                    ui.label("Pass:");
                    ui.add(TextEdit::singleline(&mut self.config.proxy_pass).password(true));
                });
            }
        }
        ui.separator();
        ui.label("User-Agent:");
        ui.text_edit_singleline(&mut self.config.user_agent);
    }

    fn ui_settings_tweaks(&mut self, ui: &mut Ui) {
        ui.label("Auth Basic pairs file:");
        ui.text_edit_singleline(&mut self.config.auth_basic_file);
        ui.label("Auth Digest pairs file:");
        ui.text_edit_singleline(&mut self.config.auth_digest_file);
        ui.label("Auth Form pairs file:");
        ui.text_edit_singleline(&mut self.config.auth_form_file);
        ui.separator();
        ui.label("Custom detection page:");
        ui.horizontal(|ui| {
            ui.label("(set in config.ini Detection.CustomPage)");
        });
    }
}

impl RouterScanApp {
    fn render(&mut self, ctx: &egui::Context) {
        // Poll scanner results every frame
        self.poll_scan();

        // Keep refreshing while scanning
        if self.state != AppState::Idle {
            ctx.request_repaint_after(std::time::Duration::from_millis(100));
        }

        egui::TopBottomPanel::top("navigation")
            .frame(egui::Frame::none().fill(PANEL).inner_margin(egui::Margin {
                left: 14.0,
                right: 16.0,
                top: 6.0,
                bottom: 0.0,
            }))
            .show(ctx, |ui| {
                self.ui_navigation(ui);
            });
        egui::TopBottomPanel::top("controls")
            .frame(
                egui::Frame::none()
                    .fill(BACKGROUND)
                    .inner_margin(egui::Margin::symmetric(12.0, 7.0)),
            )
            .show(ctx, |ui| {
                self.ui_top_panel(ui);
                if let Some(error) = &self.scan_error {
                    ui.add_space(6.0);
                    ui.colored_label(
                        Color32::from_rgb(255, 116, 116),
                        format!("Scan could not start: {error}"),
                    );
                }
            });
        egui::TopBottomPanel::bottom("status_bar")
            .frame(
                egui::Frame::none()
                    .fill(PANEL)
                    .stroke(egui::Stroke::new(1.0, BORDER))
                    .inner_margin(egui::Margin::symmetric(18.0, 12.0)),
            )
            .show(ctx, |ui| {
                self.ui_status_bar(ui);
            });
        egui::CentralPanel::default()
            .frame(
                egui::Frame::none()
                    .fill(BACKGROUND)
                    .inner_margin(egui::Margin {
                        left: 12.0,
                        right: 12.0,
                        top: 0.0,
                        bottom: 7.0,
                    }),
            )
            .show(ctx, |ui| {
                self.ui_tables(ui);
            });
        if self.ports_editor_open {
            let mut open = true;
            egui::Window::new("Scan Ports")
                .open(&mut open)
                .default_width(280.0)
                .show(ctx, |ui| {
                    ui.label("Enter ports (1–65535), separated by lines or commas.");
                    ui.add(
                        TextEdit::multiline(&mut self.ports_draft)
                            .desired_rows(12)
                            .desired_width(f32::INFINITY),
                    );
                    if let Some(error) = &self.ports_error {
                        ui.colored_label(Color32::from_rgb(255, 116, 116), error);
                    }
                    ui.horizontal(|ui| {
                        if ui.button("Done").clicked() {
                            match parse_ports(&self.ports_draft) {
                                Ok(ports) => {
                                    self.ports_text = ports
                                        .iter()
                                        .map(u16::to_string)
                                        .collect::<Vec<_>>()
                                        .join("\n");
                                    self.config.ports = ports;
                                    self.selected_port = None;
                                    self.ports_editor_open = false;
                                    save_config(&self.config);
                                }
                                Err(error) => self.ports_error = Some(error),
                            }
                        }
                        if ui.button("Cancel").clicked() {
                            self.ports_editor_open = false;
                        }
                    });
                });
            self.ports_editor_open &= open;
        }

        // ── Sub-windows ────────────────────────────────────────────────────
        self.ui_range_editor(ctx);
        self.ui_filter_editor(ctx);
        self.ui_exclusions_editor(ctx);
        self.ui_settings(ctx);
        self.ui_result_details(ctx);
    }
}

// ─── eframe::App ─────────────────────────────────────────────────────────────

impl eframe::App for RouterScanApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.render(ctx);
    }

    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        self.config.ports = self
            .ports_text
            .lines()
            .filter_map(|p| p.trim().parse::<u16>().ok())
            .filter(|&p| p != 0)
            .collect();
        self.config.ranges = self
            .ranges_text
            .lines()
            .filter(|r| !r.trim().is_empty())
            .map(str::to_owned)
            .collect();
        save_config(&self.config);
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn format_duration(secs: u64) -> String {
    let h = secs / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    format!("{:02}:{:02}:{:02}", h, m, s)
}

fn row_contains(r: &ScanResult, text: &str) -> bool {
    r.ip.contains(text)
        || r.status.contains(text)
        || r.auth.contains(text)
        || r.server_name.contains(text)
        || r.realm.contains(text)
        || r.info.contains(text)
        || r.device_type.contains(text)
        || r.ssid.contains(text)
        || r.wifi_key.contains(text)
        || r.bssid.contains(text)
        || r.wan_ip.contains(text)
        || r.dns.contains(text)
        || r.comment.contains(text)
}

fn row_contains_ci(r: &ScanResult, lower: &str) -> bool {
    r.ip.to_ascii_lowercase().contains(lower)
        || r.status.to_ascii_lowercase().contains(lower)
        || r.auth.to_ascii_lowercase().contains(lower)
        || r.server_name.to_ascii_lowercase().contains(lower)
        || r.realm.to_ascii_lowercase().contains(lower)
        || r.info.to_ascii_lowercase().contains(lower)
        || r.device_type.to_ascii_lowercase().contains(lower)
        || r.ssid.to_ascii_lowercase().contains(lower)
        || r.wifi_key.to_ascii_lowercase().contains(lower)
        || r.bssid.to_ascii_lowercase().contains(lower)
        || r.wan_ip.to_ascii_lowercase().contains(lower)
        || r.dns.to_ascii_lowercase().contains(lower)
        || r.comment.to_ascii_lowercase().contains(lower)
}
const BACKGROUND: Color32 = Color32::from_rgb(15, 23, 29);
const PANEL: Color32 = Color32::from_rgb(18, 27, 34);
const INPUT: Color32 = Color32::from_rgb(29, 40, 51);
const BORDER: Color32 = Color32::from_rgb(40, 56, 69);
const FIELD_BORDER: Color32 = Color32::from_rgb(81, 105, 127);
const BLUE: Color32 = Color32::from_rgb(0, 145, 255);
const TEXT: Color32 = Color32::from_rgb(239, 243, 250);

fn configure_theme(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();
    if let Ok(bytes) = std::fs::read("C:/Windows/Fonts/segoeui.ttf") {
        fonts
            .font_data
            .insert("segoe".into(), egui::FontData::from_owned(bytes));
        fonts
            .families
            .get_mut(&egui::FontFamily::Proportional)
            .unwrap()
            .insert(0, "segoe".into());
    }
    ctx.set_fonts(fonts);
    let mut style = (*ctx.style()).clone();
    style.visuals = egui::Visuals::dark();
    style.visuals.override_text_color = Some(TEXT);
    style.visuals.panel_fill = BACKGROUND;
    style.visuals.window_fill = PANEL;
    style.visuals.extreme_bg_color = INPUT;
    style.visuals.faint_bg_color = PANEL;
    style.visuals.selection.bg_fill = Color32::from_rgb(0, 110, 235);
    style.visuals.selection.stroke = egui::Stroke::new(1.0, Color32::WHITE);
    for widget in [
        &mut style.visuals.widgets.inactive,
        &mut style.visuals.widgets.active,
        &mut style.visuals.widgets.hovered,
    ] {
        widget.bg_fill = INPUT;
        widget.weak_bg_fill = INPUT;
        widget.bg_stroke = egui::Stroke::new(1.0, FIELD_BORDER);
        widget.fg_stroke = egui::Stroke::new(1.5, TEXT);
        widget.rounding = egui::Rounding::same(4.0);
    }
    style.visuals.widgets.hovered.bg_fill = Color32::from_rgb(43, 61, 78);
    style.visuals.widgets.hovered.weak_bg_fill = Color32::from_rgb(43, 61, 78);
    style.visuals.widgets.active.bg_fill = Color32::from_rgb(0, 105, 222);
    style.visuals.widgets.noninteractive.bg_stroke = egui::Stroke::new(1.0, BORDER);
    style.spacing.item_spacing = egui::vec2(8.0, 6.0);
    style.spacing.button_padding = egui::vec2(12.0, 7.0);
    style.spacing.interact_size = egui::vec2(32.0, 24.0);
    style.spacing.icon_width = 18.0;
    style.spacing.icon_spacing = 7.0;
    style.spacing.scroll = egui::style::ScrollStyle::solid();
    style.spacing.scroll.bar_width = 10.0;
    style
        .text_styles
        .insert(egui::TextStyle::Body, egui::FontId::proportional(14.0));
    style
        .text_styles
        .insert(egui::TextStyle::Button, egui::FontId::proportional(14.0));
    ctx.set_style(style);
}

fn icon_button(
    ui: &mut Ui,
    text: &str,
    icon: &str,
    size: egui::Vec2,
    active: bool,
    green: bool,
) -> egui::Response {
    let (rect, response) = ui.allocate_exact_size(size, egui::Sense::click());
    let fill = if green {
        Color32::from_rgb(4, 165, 24)
    } else if active {
        Color32::from_rgb(0, 101, 224)
    } else {
        INPUT
    };
    let fill = if response.hovered() {
        fill.gamma_multiply(1.2)
    } else {
        fill
    };
    let border = if green {
        Color32::from_rgb(74, 222, 84)
    } else if active {
        BLUE
    } else {
        BORDER
    };
    ui.painter().rect(
        rect,
        egui::Rounding {
            nw: 8.0,
            ne: 8.0,
            sw: 3.0,
            se: 3.0,
        },
        fill,
        egui::Stroke::new(1.0, border),
    );
    let font = egui::FontId::proportional(if green { 16.0 } else { 14.0 });
    let galley = ui.painter().layout_no_wrap(text.to_owned(), font, TEXT);
    let start = rect.center().x - (galley.size().x + 34.0) / 2.0;
    paint_icon(
        ui.painter(),
        egui::pos2(start + 10.0, rect.center().y),
        icon,
        TEXT,
    );
    ui.painter().galley(
        egui::pos2(start + 32.0, rect.center().y - galley.size().y / 2.0),
        galley,
        TEXT,
    );
    response.on_hover_cursor(egui::CursorIcon::PointingHand)
}

fn status_item(ui: &mut Ui, icon: &str, color: Color32, label: &str) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(20.0, 20.0), egui::Sense::hover());
    paint_icon(ui.painter(), rect.center(), icon, color);
    ui.label(label);
}

fn paint_icon(p: &egui::Painter, c: egui::Pos2, kind: &str, color: Color32) {
    let stroke = egui::Stroke::new(1.7, color);
    let line = |a: [f32; 2], b: [f32; 2]| {
        p.line_segment(
            [c + egui::vec2(a[0], a[1]), c + egui::vec2(b[0], b[1])],
            stroke,
        );
    };
    match kind {
        "wifi" => {
            for radius in [6.0_f32, 11.0, 16.0] {
                let points = (0..=24)
                    .map(|i| {
                        let a = -2.36 + i as f32 / 24.0 * 1.58;
                        c + egui::vec2(a.cos() * radius, a.sin() * radius + 5.0)
                    })
                    .collect();
                p.add(egui::Shape::line(points, stroke));
            }
            p.circle_filled(c + egui::vec2(0.0, 5.0), 2.0, color);
        }
        "search" => {
            p.circle_stroke(c - egui::vec2(2.0, 2.0), 7.0, stroke);
            line([3.5, 3.5], [10.0, 10.0]);
        }
        "play" => {
            p.add(egui::Shape::convex_polygon(
                vec![
                    c + egui::vec2(-5.0, -9.0),
                    c + egui::vec2(9.0, 0.0),
                    c + egui::vec2(-5.0, 9.0),
                ],
                color,
                egui::Stroke::NONE,
            ));
        }
        "stop" => {
            p.rect_filled(
                egui::Rect::from_center_size(c, egui::vec2(14.0, 14.0)),
                1.0,
                color,
            );
        }
        "clock" => {
            p.circle_stroke(c, 8.0, stroke);
            line([0.0, -5.0], [0.0, 0.0]);
            line([0.0, 0.0], [4.0, 2.0]);
        }
        "check" => {
            p.circle_filled(c, 8.0, color);
            p.line_segment(
                [c + egui::vec2(-4.0, 0.0), c + egui::vec2(-1.0, 3.0)],
                egui::Stroke::new(2.0, PANEL),
            );
            p.line_segment(
                [c + egui::vec2(-1.0, 3.0), c + egui::vec2(5.0, -3.0)],
                egui::Stroke::new(2.0, PANEL),
            );
        }
        "trash" => {
            line([-7.0, -5.0], [7.0, -5.0]);
            line([-3.0, -8.0], [3.0, -8.0]);
            line([-6.0, -5.0], [-5.0, 8.0]);
            line([-5.0, 8.0], [5.0, 8.0]);
            line([5.0, 8.0], [6.0, -5.0]);
            line([-2.0, -2.0], [-2.0, 5.0]);
            line([2.0, -2.0], [2.0, 5.0]);
        }
        "stats" => {
            p.rect_stroke(
                egui::Rect::from_center_size(c, egui::vec2(18.0, 18.0)),
                2.0,
                stroke,
            );
            line([-5.0, 5.0], [-5.0, 0.0]);
            line([0.0, 5.0], [0.0, -3.0]);
            line([5.0, 5.0], [5.0, -6.0]);
        }
        "people" => {
            p.circle_filled(c + egui::vec2(-4.0, -4.0), 3.5, color);
            p.circle_filled(c + egui::vec2(5.0, -5.0), 3.0, color);
            p.rect_filled(
                egui::Rect::from_center_size(c + egui::vec2(-4.0, 5.0), egui::vec2(10.0, 7.0)),
                3.0,
                color,
            );
            p.rect_filled(
                egui::Rect::from_center_size(c + egui::vec2(6.0, 4.0), egui::vec2(7.0, 6.0)),
                2.0,
                color,
            );
        }
        "file" => {
            p.rect_filled(
                egui::Rect::from_center_size(c, egui::vec2(13.0, 17.0)),
                2.0,
                color,
            );
            p.line_segment(
                [c + egui::vec2(-3.0, 0.0), c + egui::vec2(3.0, 0.0)],
                egui::Stroke::new(1.0, PANEL),
            );
            p.line_segment(
                [c + egui::vec2(-3.0, 4.0), c + egui::vec2(1.0, 4.0)],
                egui::Stroke::new(1.0, PANEL),
            );
        }
        "settings" => {
            p.circle_stroke(c, 7.0, stroke);
            p.circle_stroke(c, 3.0, stroke);
            for i in 0..8 {
                let a = i as f32 * std::f32::consts::TAU / 8.0;
                p.line_segment(
                    [
                        c + egui::vec2(a.cos(), a.sin()) * 7.0,
                        c + egui::vec2(a.cos(), a.sin()) * 11.0,
                    ],
                    stroke,
                );
            }
        }
        "good" => {
            for r in [4.0, 7.0, 10.0] {
                let points = (0..=28)
                    .map(|i| {
                        let a = -2.0 + i as f32 / 28.0 * 5.4;
                        c + egui::vec2(a.cos() * r, a.sin() * r)
                    })
                    .collect();
                p.add(egui::Shape::line(points, stroke));
            }
        }
        _ => {}
    }
}

fn themed_checkbox(ui: &mut Ui, value: &mut bool, label: &str) -> egui::Response {
    let galley =
        ui.painter()
            .layout_no_wrap(label.to_owned(), egui::FontId::proportional(14.0), TEXT);
    let (rect, mut response) = ui.allocate_exact_size(
        egui::vec2(25.0 + galley.size().x, 22.0),
        egui::Sense::click(),
    );
    if response.clicked() {
        *value = !*value;
        response.mark_changed();
    }
    let box_rect = egui::Rect::from_min_size(
        egui::pos2(rect.left(), rect.center().y - 9.0),
        egui::vec2(18.0, 18.0),
    );
    ui.painter().rect(
        box_rect,
        2.0,
        if *value {
            Color32::from_rgb(0, 117, 242)
        } else {
            INPUT
        },
        egui::Stroke::new(1.0, if *value { BLUE } else { FIELD_BORDER }),
    );
    if *value {
        ui.painter().add(egui::Shape::line(
            vec![
                box_rect.min + egui::vec2(4.0, 9.0),
                box_rect.min + egui::vec2(7.5, 12.5),
                box_rect.min + egui::vec2(14.0, 5.0),
            ],
            egui::Stroke::new(1.8, TEXT),
        ));
    }
    ui.painter().galley(
        egui::pos2(rect.left() + 25.0, rect.center().y - galley.size().y / 2.0),
        galley,
        TEXT,
    );
    response.widget_info(|| {
        egui::WidgetInfo::selected(egui::WidgetType::Checkbox, ui.is_enabled(), *value, label)
    });
    response
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum PortAction {
    None,
    Edit,
    Remove,
}

/// Reserve the list and action rail independently so neither can consume the other's width.
fn ports_panel(ui: &mut Ui, ports: &str, selected: &mut Option<usize>) -> PortAction {
    let (bounds, _) = ui.allocate_exact_size(
        egui::vec2(ui.available_width(), 158.0),
        egui::Sense::hover(),
    );
    let rail_width = 42.0;
    let list = egui::Rect::from_min_max(
        bounds.min,
        egui::pos2(bounds.right() - rail_width - 10.0, bounds.bottom()),
    );
    ui.painter()
        .rect(list, 4.0, INPUT, egui::Stroke::new(1.0, FIELD_BORDER));
    ui.allocate_new_ui(
        egui::UiBuilder::new()
            .max_rect(list.shrink(3.0))
            .layout(egui::Layout::top_down(egui::Align::Min)),
        |ui| {
            ui.set_clip_rect(list.shrink(1.0).intersect(ui.clip_rect()));
            ui.spacing_mut().item_spacing.y = 1.0;
            ui.spacing_mut().button_padding = egui::vec2(5.0, 1.0);
            ui.spacing_mut().interact_size.y = 22.0;
            ScrollArea::vertical()
                .id_salt("ports_list")
                .max_height(list.height() - 6.0)
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    // Keep a dedicated vertical flow with compact, left-aligned list rows.
                    for (i, port) in ports.lines().enumerate() {
                        let response = ui.add(egui::SelectableLabel::new(
                            *selected == Some(i),
                            port.parse::<u16>()
                                .map(crate::port_presets::port_label)
                                .unwrap_or_else(|_| port.to_owned()),
                        ));
                        if response.clicked() {
                            *selected = Some(i);
                        }
                    }
                });
        },
    );
    let mut action = PortAction::None;
    let rail = egui::Rect::from_min_size(
        egui::pos2(bounds.right() - rail_width, bounds.top()),
        egui::vec2(rail_width, 122.0),
    );
    ui.allocate_new_ui(
        egui::UiBuilder::new()
            .max_rect(rail)
            .layout(egui::Layout::top_down(egui::Align::Min)),
        |ui| {
            ui.spacing_mut().item_spacing.y = 7.0;
            if ui
                .add_sized([rail_width, 34.0], Button::new("+"))
                .on_hover_text("Add or edit scan ports")
                .clicked()
            {
                action = PortAction::Edit;
            }
            ui.add_enabled_ui(selected.is_some(), |ui| {
                if ui
                    .add_sized([rail_width, 34.0], Button::new("−"))
                    .on_hover_text("Remove selected port")
                    .clicked()
                {
                    action = PortAction::Remove;
                }
            });
            if ui
                .add_sized([rail_width, 34.0], Button::new("…"))
                .on_hover_text("Edit scan ports")
                .clicked()
            {
                action = PortAction::Edit;
            }
        },
    );
    action
}

fn parse_ports(text: &str) -> Result<Vec<u16>, String> {
    let mut ports = Vec::new();
    for token in text
        .split(|c: char| c.is_whitespace() || c == ',' || c == ';')
        .filter(|s| !s.is_empty())
    {
        let port = token
            .parse::<u16>()
            .ok()
            .filter(|&p| p > 0)
            .ok_or_else(|| format!("Invalid port: {token}. Use a number from 1 to 65535."))?;
        if !ports.contains(&port) {
            ports.push(port);
        }
    }
    if ports.is_empty() {
        return Err("Add at least one port.".into());
    }
    Ok(ports)
}

#[cfg(test)]
mod ui_regression_tests {
    use super::*;

    #[test]
    fn port_list_keeps_rows_vertical_and_actions_visible() {
        for width in [155.0, 196.0, 260.0] {
            let ctx = egui::Context::default();
            let mut selected = Some(0);
            let output = ctx.run(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(width + 16.0, 300.0),
                    )),
                    ..Default::default()
                },
                |ctx| {
                    egui::CentralPanel::default().show(ctx, |ui| {
                        ui.set_width(width);
                        ports_panel(ui, "80\n443", &mut selected);
                    });
                },
            );
            let texts: Vec<_> = output
                .shapes
                .iter()
                .filter_map(|shape| {
                    if let egui::Shape::Text(text) = &shape.shape {
                        Some((
                            text.galley.job.text.as_str(),
                            text.pos + text.galley.size() * 0.5,
                            shape.clip_rect,
                            text.pos,
                        ))
                    } else {
                        None
                    }
                })
                .collect();
            let locate = |label: &str| {
                texts
                    .iter()
                    .find(|(text, _, _, _)| *text == label)
                    .unwrap_or_else(|| panic!("Missing {label} at width {width}"))
            };
            let first = locate("80  HTTP");
            let second = locate("443  HTTPS");
            assert!(
                (first.3.x - second.3.x).abs() < 1.0,
                "ports must share a column"
            );
            assert!(
                second.1.y > first.1.y + 20.0,
                "ports must occupy separate rows"
            );
            for label in ["+", "−", "…"] {
                let action = locate(label);
                assert!(
                    action.1.x > first.1.x + 30.0,
                    "action rail must be right of the list"
                );
                assert!(action.2.contains(action.1), "action must not be clipped");
                assert!(
                    action.1.x < width + 8.0,
                    "action must remain inside the card"
                );
            }
        }
    }

    #[test]
    fn port_editor_accepts_separators_and_rejects_invalid_ports() {
        assert_eq!(
            parse_ports("80,443\n8080; 80").unwrap(),
            vec![80, 443, 8080]
        );
        for text in ["", "0", "65536", "80,https", "-1"] {
            assert!(parse_ports(text).is_err(), "must reject {text:?}");
        }
    }

    #[test]
    fn embedded_brand_icon_decodes() {
        let icon = crate::app_icon();
        assert_eq!((icon.width, icon.height), (256, 256));
        assert_eq!(icon.rgba.len(), 256 * 256 * 4);
    }
}

fn upsert_result(
    rows: &mut Vec<ScanResult>,
    indices: &mut HashMap<(String, u16), usize>,
    row: ScanResult,
) {
    let key = (row.ip.clone(), row.port);
    if let Some(&index) = indices.get(&key) {
        rows[index] = row;
    } else {
        indices.insert(key, rows.len());
        rows.push(row);
    }
}

fn status_color(row: &ScanResult) -> Color32 {
    if row.is_loading() {
        BLUE
    } else if row.tcp_open && row.inspection_failed() {
        Color32::from_rgb(255, 188, 75)
    } else if row.status == "Done" {
        Color32::from_rgb(78, 211, 133)
    } else if matches!(
        row.status.as_str(),
        "Auth required" | "Filtered" | "Redirect" | "Stopped"
    ) {
        Color32::from_rgb(255, 188, 75)
    } else {
        Color32::from_rgb(255, 116, 116)
    }
}

#[cfg(test)]
mod live_result_tests {
    use super::*;
    #[test]
    fn progress_updates_replace_the_existing_row_and_keep_other_ports_separate() {
        let mut rows = Vec::new();
        let mut indices = HashMap::new();
        for status in ["Connecting", "Processing", "Done"] {
            upsert_result(
                &mut rows,
                &mut indices,
                ScanResult {
                    ip: "127.0.0.1".into(),
                    port: 80,
                    status: status.into(),
                    server_name: "Office Server".into(),
                    realm: "Office Realm".into(),
                    ..Default::default()
                },
            );
        }
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].status, "Done");
        assert!(row_contains_ci(&rows[0], "office realm"));
        assert!(row_contains_ci(&rows[0], "office server"));
        upsert_result(
            &mut rows,
            &mut indices,
            ScanResult {
                ip: "127.0.0.1".into(),
                port: 443,
                status: "Processing".into(),
                ..Default::default()
            },
        );
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].status, "Done");
    }
}

fn found_result_count(rows: &[ScanResult]) -> usize {
    rows.iter().filter(|row| row.is_found()).count()
}

#[cfg(test)]
mod found_count_tests {
    use super::*;

    #[test]
    fn total_counts_only_found_rows_and_does_not_inflate_attempts() {
        let mut rows = Vec::new();
        let mut indices = HashMap::new();
        // Repeated progress updates must still leave exactly 39 responsive services.
        for i in 1..=39 {
            for (status, http_status) in [("Connecting", 0), ("Processing", 0), ("Done", 200)] {
                upsert_result(
                    &mut rows,
                    &mut indices,
                    ScanResult {
                        ip: format!("192.0.2.{i}"),
                        port: 80,
                        status: status.into(),
                        tcp_open: http_status != 0,
                        http_status,
                        ..Default::default()
                    },
                );
            }
        }
        for i in 40..=53 {
            upsert_result(
                &mut rows,
                &mut indices,
                ScanResult {
                    ip: format!("192.0.2.{i}"),
                    port: 80,
                    status: "Timed out".into(),
                    ..Default::default()
                },
            );
        }
        assert_eq!(rows.len(), 53);
        assert_eq!(found_result_count(&rows), 39);
        assert_eq!(rows.iter().filter(|r| r.is_found()).count(), 39);
        assert!(rows
            .iter()
            .filter(|r| r.is_found())
            .all(|r| r.status != "Timed out"));
    }
}

#[cfg(test)]
mod start_button_tests {
    use super::*;

    fn frame(
        ctx: &egui::Context,
        app: &mut RouterScanApp,
        events: Vec<egui::Event>,
        time: f64,
    ) -> egui::FullOutput {
        ctx.run(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(1554.0, 966.0),
                )),
                time: Some(time),
                events,
                focused: true,
                ..Default::default()
            },
            |ctx| app.render(ctx),
        )
    }

    #[test]
    fn clicking_start_scan_dispatches_and_reports_invalid_input_visibly() {
        let ctx = egui::Context::default();
        let mut app = RouterScanApp::with_config(
            &ctx,
            Config {
                ports: Vec::new(),
                ranges: vec!["192.0.2.1 /32".into()],
                ..Default::default()
            },
        );
        frame(&ctx, &mut app, vec![], 0.0);
        let output = frame(&ctx, &mut app, vec![], 0.1);
        let position = output
            .shapes
            .iter()
            .find_map(|shape| {
                if let egui::Shape::Text(text) = &shape.shape {
                    if text.galley.job.text == "Start Scan" {
                        return Some(text.pos + text.galley.size() * 0.5);
                    }
                }
                None
            })
            .expect("Start Scan must be rendered");
        frame(
            &ctx,
            &mut app,
            vec![
                egui::Event::PointerMoved(position),
                egui::Event::PointerButton {
                    pos: position,
                    button: egui::PointerButton::Primary,
                    pressed: true,
                    modifiers: egui::Modifiers::NONE,
                },
            ],
            0.2,
        );
        let output = frame(
            &ctx,
            &mut app,
            vec![egui::Event::PointerButton {
                pos: position,
                button: egui::PointerButton::Primary,
                pressed: false,
                modifiers: egui::Modifiers::NONE,
            }],
            0.3,
        );
        assert!(
            app.scan_error.is_some(),
            "Start Scan click must dispatch its action"
        );
        assert!(app.state == AppState::Idle);
        assert!(
            app.scan_rx.is_none(),
            "invalid input must never start network workers"
        );
        // Validation feedback is drawn next frame directly beneath the controls.
        let next = frame(&ctx, &mut app, vec![], 0.4);
        assert!(output.shapes.iter().chain(next.shapes.iter()).any(|shape| matches!(&shape.shape,egui::Shape::Text(text) if text.galley.job.text.contains("Scan could not start:"))));
    }
}

fn paint_table_text(
    painter: &egui::Painter,
    text: &str,
    rect: egui::Rect,
    font_size: f32,
    color: Color32,
) {
    let mut job = egui::text::LayoutJob::simple(
        text.to_owned(),
        egui::FontId::proportional(font_size),
        color,
        rect.width(),
    );
    job.wrap.break_anywhere = true;
    job.wrap.max_rows = 3;
    job.wrap.overflow_character = Some('…');
    let galley = painter.layout_job(job);
    let origin = egui::pos2(
        rect.left(),
        (rect.center().y - galley.size().y / 2.0).max(rect.top()),
    );
    painter
        .with_clip_rect(rect.intersect(painter.clip_rect()))
        .galley(origin, galley, color);
}

#[cfg(test)]
mod discovery_count_regression {
    use super::*;
    #[test]
    fn open_ports_with_failed_inspection_are_hidden_and_not_counted() {
        let rows: Vec<_> = (1..=25)
            .map(|i| ScanResult {
                ip: format!("192.0.2.{i}"),
                port: 554,
                tcp_open: true,
                status: if i % 2 == 0 {
                    "TLS error".into()
                } else {
                    "Can't load".into()
                },
                ..Default::default()
            })
            .collect();
        assert_eq!(found_result_count(&rows), 0);
        assert!(rows.iter().all(|row| row.discovery_status() == "Open"));
    }
}

#[cfg(test)]
mod fitted_table_interaction_tests {
    use super::*;
    fn sample() -> ScanResult {
        ScanResult {
            ip: "192.0.2.17".into(),
            port: 554,
            tcp_open: true,
            status: "Done".into(),
            http_status: 200,
            ssid: "Example network".into(),
            lan_mask: "255.255.255.0".into(),
            wan_mask: "255.255.255.252".into(),
            dns: "192.0.2.53".into(),
            ..Default::default()
        }
    }
    fn frame(
        ctx: &egui::Context,
        app: &mut RouterScanApp,
        width: f32,
        events: Vec<egui::Event>,
        time: f64,
        modifiers: egui::Modifiers,
    ) -> egui::FullOutput {
        ctx.run(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(width, 966.0),
                )),
                time: Some(time),
                events,
                modifiers,
                focused: true,
                ..Default::default()
            },
            |ctx| app.render(ctx),
        )
    }
    #[test]
    fn rendered_table_has_every_requested_column_inside_the_viewport() {
        for width in [1200.0, 1554.0, 1920.0] {
            let ctx = egui::Context::default();
            let mut app = RouterScanApp::with_config(&ctx, Config::default());
            app.all_results.push(sample());
            frame(&ctx, &mut app, width, vec![], 0.0, egui::Modifiers::NONE);
            let output = frame(&ctx, &mut app, width, vec![], 0.1, egui::Modifiers::NONE);
            for (header, _) in crate::result_table::COLUMNS {
                let text = output
                    .shapes
                    .iter()
                    .find_map(|s| match &s.shape {
                        egui::Shape::Text(t) if t.galley.job.text == header => Some(t),
                        _ => None,
                    })
                    .unwrap_or_else(|| panic!("Missing {header} at width {width}"));
                assert!(
                    text.pos.x >= 0.0 && text.pos.x + text.galley.size().x <= width + 0.5,
                    "{header} overflows at width {width}"
                );
            }
        }
    }
    #[test]
    fn double_click_copies_the_full_cell_and_ctrl_c_copies_the_row() {
        let ctx = egui::Context::default();
        let mut app = RouterScanApp::with_config(&ctx, Config::default());
        app.all_results.push(sample());
        frame(&ctx, &mut app, 1554.0, vec![], 0.0, egui::Modifiers::NONE);
        let output = frame(&ctx, &mut app, 1554.0, vec![], 0.1, egui::Modifiers::NONE);
        let pos = output
            .shapes
            .iter()
            .find_map(|s| match &s.shape {
                egui::Shape::Text(t) if t.galley.job.text == "192.0.2.17" => {
                    Some(t.pos + t.galley.size() * 0.5)
                }
                _ => None,
            })
            .expect("responsive row is visible");
        let mut last = None;
        for (i, pressed) in [true, false, true, false].into_iter().enumerate() {
            last = Some(frame(
                &ctx,
                &mut app,
                1554.0,
                vec![
                    egui::Event::PointerMoved(pos),
                    egui::Event::PointerButton {
                        pos,
                        button: egui::PointerButton::Primary,
                        pressed,
                        modifiers: egui::Modifiers::NONE,
                    },
                ],
                0.2 + i as f64 * 0.07,
                egui::Modifiers::NONE,
            ));
        }
        assert_eq!(last.unwrap().platform_output.copied_text, "192.0.2.17");
        assert_eq!(app.selected_row, Some(("192.0.2.17".into(), 554)));
        let modifiers = egui::Modifiers {
            ctrl: true,
            command: true,
            ..Default::default()
        };
        let output = frame(
            &ctx,
            &mut app,
            1554.0,
            vec![egui::Event::Key {
                key: egui::Key::C,
                physical_key: None,
                pressed: true,
                repeat: false,
                modifiers,
            }],
            0.6,
            modifiers,
        );
        let expected = crate::result_table::clipboard(&[&sample()], false);
        assert_eq!(output.platform_output.copied_text, expected);
    }
}

#[derive(PartialEq)]
enum RangeAction {
    None,
    Edit,
    Remove,
    Clear,
}
fn ranges_panel(ui: &mut Ui, ranges: &str, selected: &mut Option<usize>) -> RangeAction {
    let (bounds, _) = ui.allocate_exact_size(
        egui::vec2(ui.available_width(), 158.0),
        egui::Sense::hover(),
    );
    let list = egui::Rect::from_min_max(
        bounds.min,
        egui::pos2(bounds.right() - 52.0, bounds.bottom()),
    );
    ui.painter()
        .rect(list, 4.0, INPUT, egui::Stroke::new(1.0, FIELD_BORDER));
    ui.allocate_new_ui(
        egui::UiBuilder::new()
            .max_rect(list.shrink(3.0))
            .layout(egui::Layout::top_down(egui::Align::Min)),
        |ui| {
            ui.set_clip_rect(list.shrink(1.0).intersect(ui.clip_rect()));
            ScrollArea::vertical()
                .id_salt("ranges_list")
                .max_height(list.height() - 6.0)
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    ui.set_width(list.width() - 18.0);
                    for (i, range) in ranges.lines().enumerate() {
                        if ui
                            .add_sized(
                                [ui.available_width(), 28.0],
                                Button::new(range)
                                    .selected(*selected == Some(i))
                                    .wrap_mode(egui::TextWrapMode::Truncate),
                            )
                            .on_hover_text(range)
                            .clicked()
                        {
                            *selected = Some(i);
                        }
                    }
                });
        },
    );
    let rail = egui::Rect::from_min_size(
        egui::pos2(bounds.right() - 42.0, bounds.top()),
        egui::vec2(42.0, 122.0),
    );
    let mut action = RangeAction::None;
    ui.allocate_new_ui(
        egui::UiBuilder::new()
            .max_rect(rail)
            .layout(egui::Layout::top_down(egui::Align::Min)),
        |ui| {
            ui.spacing_mut().item_spacing.y = 7.0;
            if ui
                .add_sized([42.0, 34.0], Button::new("+"))
                .on_hover_text("Add or edit IP ranges")
                .clicked()
            {
                action = RangeAction::Edit;
            }
            if ui
                .add_enabled(
                    selected.is_some(),
                    Button::new("−").min_size(egui::vec2(42.0, 34.0)),
                )
                .on_hover_text("Remove selected range")
                .clicked()
            {
                action = RangeAction::Remove;
            }
            if ui
                .add_sized([42.0, 34.0], Button::new("×"))
                .on_hover_text("Clear IP ranges")
                .clicked()
            {
                action = RangeAction::Clear;
            }
        },
    );
    action
}

#[cfg(test)]
mod preset_layout_tests {
    use super::*;
    fn frame(
        ctx: &egui::Context,
        app: &mut RouterScanApp,
        width: f32,
        events: Vec<egui::Event>,
        time: f64,
    ) -> egui::FullOutput {
        ctx.run(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(width, 966.0),
                )),
                events,
                time: Some(time),
                focused: true,
                ..Default::default()
            },
            |ctx| app.render(ctx),
        )
    }
    fn text_rect(out: &egui::FullOutput, label: &str) -> egui::Rect {
        out.shapes
            .iter()
            .find_map(|s| match &s.shape {
                egui::Shape::Text(t) if t.galley.job.text == label => {
                    Some(egui::Rect::from_min_size(t.pos, t.galley.size()))
                }
                _ => None,
            })
            .unwrap_or_else(|| panic!("Missing {label}"))
    }
    #[test]
    fn hundreds_of_ranges_and_top100_cannot_push_controls_or_results_offscreen() {
        for width in [1200.0, 1554.0, 1920.0] {
            let mut baseline: Option<f32> = None;
            for count in [1, 4, 200] {
                let ctx = egui::Context::default();
                let mut app = RouterScanApp::with_config(&ctx, Config::default());
                app.ports_text = crate::port_presets::TOP_TCP
                    .iter()
                    .map(u16::to_string)
                    .collect::<Vec<_>>()
                    .join("\n");
                app.ranges_text = (1..=count)
                    .map(|i| format!("192.0.2.{i}/32"))
                    .collect::<Vec<_>>()
                    .join("\n");
                frame(&ctx, &mut app, width, vec![], 0.0);
                let out = frame(&ctx, &mut app, width, vec![], 0.1);
                for label in [
                    "Top 100 TCP (100)",
                    "Device Filter:",
                    "All Devices",
                    "Export  ▾",
                    "Clear",
                    env!("CARGO_PKG_VERSION"),
                ] {
                    let r = text_rect(&out, label);
                    assert!(
                        r.left() >= 0.0 && r.right() <= width && r.bottom() < 420.0,
                        "{label} outside controls at {width}, ranges={count}: {r:?}"
                    );
                }
                let y = text_rect(&out, "Found Results (0)").top();
                assert!(y < 420.0, "results pushed down: {y}");
                if let Some(previous) = baseline {
                    assert!(
                        (y - previous).abs() < 1.0,
                        "range count changes result position"
                    );
                } else {
                    baseline = Some(y);
                }
                assert!(text_rect(&out, "192.0.2.1/32").bottom() < 300.0);
            }
        }
    }
    fn click(
        ctx: &egui::Context,
        app: &mut RouterScanApp,
        pos: egui::Pos2,
        time: f64,
    ) -> egui::FullOutput {
        frame(
            ctx,
            app,
            1554.0,
            vec![
                egui::Event::PointerMoved(pos),
                egui::Event::PointerButton {
                    pos,
                    button: egui::PointerButton::Primary,
                    pressed: true,
                    modifiers: Default::default(),
                },
            ],
            time,
        );
        frame(
            ctx,
            app,
            1554.0,
            vec![egui::Event::PointerButton {
                pos,
                button: egui::PointerButton::Primary,
                pressed: false,
                modifiers: Default::default(),
            }],
            time + 0.05,
        )
    }
    #[test]
    fn clicking_named_preset_updates_numeric_scan_ports_and_clears_selection() {
        let ctx = egui::Context::default();
        let mut app = RouterScanApp::with_config(&ctx, Config::default());
        app.ports_text = "80\n443".into();
        app.selected_port = Some(1);
        frame(&ctx, &mut app, 1554.0, vec![], 0.0);
        let out = frame(&ctx, &mut app, 1554.0, vec![], 0.1);
        click(
            &ctx,
            &mut app,
            text_rect(&out, "Custom (2 TCP)").center(),
            0.2,
        );
        let out = frame(&ctx, &mut app, 1554.0, vec![], 0.3);
        let pos = text_rect(&out, "Top 50 TCP (50)").center();
        click(&ctx, &mut app, pos, 0.4);
        assert_eq!(app.config.ports, crate::port_presets::TOP_TCP[..50]);
        assert_eq!(parse_ports(&app.ports_text).unwrap(), app.config.ports);
        assert_eq!(app.selected_port, None);
        assert_eq!(app.state, AppState::Idle);
    }
}

#[cfg(test)]
mod hidden_timeout_rows_test {
    use super::*;
    #[test]
    fn open_dns_timeouts_are_absent_from_tables_search_copy_and_total() {
        let ctx = egui::Context::default();
        let mut app = RouterScanApp::with_config(&ctx, Config::default());
        for last in [34, 128, 163] {
            app.all_results.push(ScanResult {
                ip: format!("192.0.2.{last}"),
                port: 53,
                tcp_open: true,
                status: "Can't load".into(),
                info: "operation timed out".into(),
                ..Default::default()
            });
        }
        let good = ScanResult {
            ip: "192.0.2.80".into(),
            port: 80,
            tcp_open: true,
            http_status: 200,
            status: "Done".into(),
            ..Default::default()
        };
        app.all_results.push(good);
        assert_eq!(found_result_count(&app.all_results), 1);
        let visible: Vec<_> = app
            .all_results
            .iter()
            .filter(|r| app.result_visible(r))
            .collect();
        let copied = crate::result_table::clipboard(&visible, true);
        assert!(copied.contains("192.0.2.80"));
        assert!(!copied.contains("timed out"));
        assert!(!copied.contains("192.0.2.34"));
        app.search_text = "192.0.2".into();
        app.do_search();
        assert_eq!(app.search_results.len(), 1);
        for _ in 0..2 {
            let output = ctx.run(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(1554.0, 966.0),
                    )),
                    ..Default::default()
                },
                |ctx| app.render(ctx),
            );
            for shape in output.shapes {
                if let egui::Shape::Text(text) = shape.shape {
                    assert!(!text.galley.job.text.contains("operation timed out"));
                    assert!(!text.galley.job.text.contains("192.0.2.34"));
                }
            }
        }
    }
}
