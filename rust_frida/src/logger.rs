use std::sync::atomic::{AtomicBool, Ordering};

/// Global verbose switch controlled by `--verbose`.
pub static VERBOSE: AtomicBool = AtomicBool::new(false);

pub fn is_verbose() -> bool {
    VERBOSE.load(Ordering::Relaxed)
}

/// ANSI color constants.
pub const RESET: &str = "\x1b[0m";
pub const BOLD: &str = "\x1b[1m";
pub const DIM: &str = "\x1b[2m";

pub const RED: &str = "\x1b[31m";
pub const GREEN: &str = "\x1b[32m";
pub const YELLOW: &str = "\x1b[33m";
pub const BLUE: &str = "\x1b[34m";
pub const MAGENTA: &str = "\x1b[35m";
pub const CYAN: &str = "\x1b[36m";

/// Extended colors used by the rustyline highlighter.
pub const GRAY: &str = "\x1b[38;5;245m";
pub const HIGHLIGHT_BG: &str = "\x1b[48;5;238m";
pub const HIGHLIGHT_FG: &str = "\x1b[38;5;255m";

#[macro_export]
macro_rules! log_info {
    ($($arg:tt)*) => {{
        println!("{}{} [*]{} {}", $crate::logger::BOLD, $crate::logger::BLUE, $crate::logger::RESET, format_args!($($arg)*));
    }};
}

#[macro_export]
macro_rules! log_success {
    ($($arg:tt)*) => {{
        println!("{}{} [✓]{} {}", $crate::logger::BOLD, $crate::logger::GREEN, $crate::logger::RESET, format_args!($($arg)*));
    }};
}

#[macro_export]
macro_rules! log_warn {
    ($($arg:tt)*) => {{
        eprintln!("{}{} [!]{} {}", $crate::logger::BOLD, $crate::logger::YELLOW, $crate::logger::RESET, format_args!($($arg)*));
    }};
}

#[macro_export]
macro_rules! log_error {
    ($($arg:tt)*) => {{
        eprintln!("{}{} [✗]{} {}", $crate::logger::BOLD, $crate::logger::RED, $crate::logger::RESET, format_args!($($arg)*));
    }};
}

#[macro_export]
macro_rules! log_step {
    ($($arg:tt)*) => {{
        println!("{}{} [→]{} {}", $crate::logger::BOLD, $crate::logger::CYAN, $crate::logger::RESET, format_args!($($arg)*));
    }};
}

#[macro_export]
macro_rules! log_addr {
    ($label:expr, $addr:expr) => {{
        println!(
            "     {}: {}0x{:x}{}",
            $label,
            $crate::logger::DIM,
            $addr,
            $crate::logger::RESET
        );
    }};
}

#[macro_export]
macro_rules! log_verbose {
    ($($arg:tt)*) => {{
        if $crate::logger::is_verbose() {
            println!("{}{} [→]{} {}", $crate::logger::BOLD, $crate::logger::CYAN, $crate::logger::RESET, format_args!($($arg)*));
        }
    }};
}

#[macro_export]
macro_rules! log_verbose_addr {
    ($label:expr, $addr:expr) => {{
        if $crate::logger::is_verbose() {
            println!(
                "     {}: {}0x{:x}{}",
                $label,
                $crate::logger::DIM,
                $addr,
                $crate::logger::RESET
            );
        }
    }};
}

#[macro_export]
macro_rules! log_agent {
    ($($arg:tt)*) => {{
        println!("{}{} [agent]{} {}", $crate::logger::BOLD, $crate::logger::MAGENTA, $crate::logger::RESET, format_args!($($arg)*));
    }};
}

fn banner_text(version: &str) -> String {
    format!(
        "\n {BOLD}{CYAN}╔══════════════════════════════════════╗{RESET}\n \
         {BOLD}{CYAN}║{RESET}  {BOLD}      rustFrida v{version:<17} {RESET}{BOLD}{CYAN}║{RESET}\n \
         {BOLD}{CYAN}║{RESET}  {DIM}  ARM64 Dynamic Instrumentation    {RESET}{BOLD}{CYAN}║{RESET}\n \
         {BOLD}{CYAN}╚══════════════════════════════════════╝{RESET}\n"
    )
}

pub fn print_banner() {
    let version = env!("CARGO_PKG_VERSION");
    println!("{}", banner_text(version));
}

#[cfg(test)]
mod tests {
    use super::banner_text;

    #[test]
    fn banner_uses_expected_unicode_box_drawing() {
        let banner = banner_text("0.1.0");
        assert!(banner.contains("rustFrida v0.1.0"));
        assert!(banner.contains("ARM64 Dynamic Instrumentation"));
        assert!(banner.contains("╔"));
        assert!(banner.contains("╚"));
        assert!(!banner.contains('鈺'));
    }
}
