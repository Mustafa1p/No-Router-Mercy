#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;
mod config;
mod credentials;
mod exploits;
mod export;
mod filter;
mod http_client;
mod ip_range;
mod models;
mod port_presets;
mod result_table;
mod rs_exploits;
mod scanner;
#[cfg(test)]
mod test_support;

fn app_icon() -> egui::IconData {
    eframe::icon_data::from_png_bytes(include_bytes!("../src-media/app-icon.png"))
        .expect("embedded application icon must be a valid PNG")
}

const APP_TITLE: &str = concat!("No Router-Mercy v", env!("CARGO_PKG_VERSION"));

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if let Err(error) = config::init_data_directory() {
        rfd::MessageDialog::new()
            .set_title("No Router-Mercy — startup error")
            .set_description(format!("Cannot open the application data folder: {error}"))
            .set_level(rfd::MessageLevel::Error)
            .show();
        return Err(error.into());
    }
    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title(APP_TITLE)
            .with_icon(app_icon())
            .with_min_inner_size([1200.0, 680.0])
            .with_inner_size([1554.0, 966.0]),
        ..Default::default()
    };
    eframe::run_native(
        APP_TITLE,
        native_options,
        Box::new(|cc| Ok(Box::new(app::RouterScanApp::new(cc)))),
    )
    .map_err(Into::into)
}
