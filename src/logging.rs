use crate::config::LogLevel;
use crate::Configuration;
use log::info;

pub fn setup_logging(cfg: &Configuration) {
    let log_level = cfg.log_level.unwrap_or(LogLevel::Info);

    if let Err(_err) = fern::Dispatch::new()
        .format(|out, message, record| {
            out.finish(format_args!(
                "{} [{}][{}] {}",
                chrono::Local::now().format("%+"),
                record.target(),
                record.level(),
                message
            ))
        })
        .level(log_level.into())
        .chain(std::io::stdout())
        .apply()
    {
        panic!("Failed to initialize logging.")
    }
    info!("logging initialized.");
}
