#![cfg(all(target_os = "android", target_arch = "aarch64"))]

mod args;
mod communication;
mod injection;
#[macro_use]
mod logger;
mod proc_mem;
mod process;
mod props;
mod repl;
pub mod runner;
mod selinux;
mod server;
mod session;
mod spawn;
mod types;

use args::Args;
use clap::Parser;
use std::sync::atomic::Ordering;

fn main() {
    let args = Args::parse();
    logger::print_banner();

    // 初始化 verbose 模式
    logger::VERBOSE.store(args.verbose, Ordering::Relaxed);

    if let Some(ref profile_name) = args.dump_props {
        match props::dump_props(profile_name) {
            Ok(()) => std::process::exit(0),
            Err(e) => {
                log_error!("Dump 属性失败: {}", e);
                std::process::exit(1);
            }
        }
    }

    if let Some(ref set_args) = args.set_prop {
        match props::set_prop(&set_args[0], &set_args[1]) {
            Ok(()) => std::process::exit(0),
            Err(e) => {
                log_error!("设置属性失败: {}", e);
                std::process::exit(1);
            }
        }
    }

    if let Some(ref del_args) = args.del_prop {
        match props::del_prop(&del_args[0], &del_args[1]) {
            Ok(()) => std::process::exit(0),
            Err(e) => {
                log_error!("删除属性失败: {}", e);
                std::process::exit(1);
            }
        }
    }

    if let Some(ref profile_name) = args.repack_props {
        match props::repack_props(profile_name) {
            Ok(()) => std::process::exit(0),
            Err(e) => {
                log_error!("重排失败: {}", e);
                std::process::exit(1);
            }
        }
    }

    if args.profile.is_some() && args.spawn.is_none() && !args.server {
        log_error!("--profile 仅在 --spawn 或 --server 模式下可用");
        std::process::exit(1);
    }

    if let Some(ref profile_name) = args.profile {
        match props::prep_prop_profile(profile_name) {
            Ok(profile_dir) => {
                spawn::set_prop_profile(Some(profile_dir));
            }
            Err(e) => {
                log_error!("属性 profile 预处理失败: {}", e);
                std::process::exit(1);
            }
        }
    }

    if args.server {
        server::run_server(&args);
    } else {
        runner::start_interactive_session(&args);
    }
}
