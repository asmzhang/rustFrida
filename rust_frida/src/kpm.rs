#![cfg(all(target_os = "android", target_arch = "aarch64"))]

use anyhow::{bail, Context};
use std::process::Command;

pub(crate) const DEFAULT_LDMON_MODULE: &str = "kpm-dlopen-monitor";
const KSUD_CANDIDATES: &[&str] = &["/data/adb/ksu/bin/ksud", "/data/adb/ksud"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct KpmCtlSpec {
    pub(crate) module: String,
    pub(crate) command: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LdMonitorCommand {
    Start,
    Stop,
    Status,
    SetFilter { pattern: String },
    ClearFilter,
    SetTargetPid { pid: u32 },
    ClearTargetPid,
    Raw(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LdMonitorStatus {
    pub(crate) enabled: bool,
    pub(crate) filter: Option<String>,
    pub(crate) target_pid: Option<u32>,
    pub(crate) backend: Option<String>,
    pub(crate) subscriber: Option<u32>,
}

pub(crate) trait MonitorControlBackend {
    fn send(&self, module: &str, command: &LdMonitorCommand) -> anyhow::Result<String>;
}

#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct KernelPatchControlBackend;

#[derive(Debug, Clone)]
pub(crate) struct LdMonitorController<B: MonitorControlBackend> {
    backend: B,
    module_name: String,
}

pub(crate) fn parse_kpm_ctl_spec(parts: &[String]) -> anyhow::Result<KpmCtlSpec> {
    if parts.len() != 2 {
        bail!("kpm control requires <module> and <command>");
    }

    let module = parts[0].trim();
    let command = parts[1].trim();

    if module.is_empty() {
        bail!("kpm control module must not be empty");
    }
    if command.is_empty() {
        bail!("kpm control command must not be empty");
    }

    Ok(KpmCtlSpec {
        module: module.to_string(),
        command: command.to_string(),
    })
}

pub(crate) fn format_kpm_ctl_output(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).trim().to_string()
}

pub(crate) fn parse_ldmonitor_status(output: &str) -> anyhow::Result<LdMonitorStatus> {
    let mut enabled = None;
    let mut filter = None;
    let mut target_pid = None;
    let mut backend = None;
    let mut subscriber = None;

    for token in output.split_whitespace() {
        let Some((key, value)) = token.split_once('=') else {
            continue;
        };
        match key {
            "enabled" => {
                enabled = Some(match value {
                    "1" => true,
                    "0" => false,
                    _ => bail!("invalid enabled value: {}", value),
                });
            }
            "filter" => {
                if value != "<none>" {
                    filter = Some(value.to_string());
                }
            }
            "target_pid" => {
                if value != "0" {
                    target_pid = Some(
                        value
                            .parse::<u32>()
                            .with_context(|| format!("invalid target_pid value: {}", value))?,
                    );
                }
            }
            "backend" => backend = Some(value.to_string()),
            "subscriber" => {
                if value != "0" {
                    subscriber = Some(
                        value
                            .parse::<u32>()
                            .with_context(|| format!("invalid subscriber value: {}", value))?,
                    );
                }
            }
            _ => {}
        }
    }

    let Some(enabled) = enabled else {
        bail!("status payload missing enabled field: {}", output);
    };

    Ok(LdMonitorStatus {
        enabled,
        filter,
        target_pid,
        backend,
        subscriber,
    })
}

pub(crate) fn format_ldmonitor_status(status: &LdMonitorStatus) -> String {
    format!(
        "enabled={} filter={} target_pid={} backend={} subscriber={}",
        if status.enabled { 1 } else { 0 },
        status.filter.as_deref().unwrap_or("<none>"),
        status.target_pid.unwrap_or(0),
        status.backend.as_deref().unwrap_or("<unknown>"),
        status.subscriber.unwrap_or(0)
    )
}

pub(crate) fn parse_ldmonitor_command(command: &str) -> anyhow::Result<LdMonitorCommand> {
    let command = command.trim();
    if command.is_empty() {
        bail!("ldmonitor command must not be empty");
    }

    if command == "start" {
        return Ok(LdMonitorCommand::Start);
    }
    if command == "stop" {
        return Ok(LdMonitorCommand::Stop);
    }
    if command == "status" {
        return Ok(LdMonitorCommand::Status);
    }
    if command == "clear-filter" {
        return Ok(LdMonitorCommand::ClearFilter);
    }
    if command == "clear-target-pid" {
        return Ok(LdMonitorCommand::ClearTargetPid);
    }
    if let Some(pattern) = command.strip_prefix("filter=") {
        if pattern.is_empty() {
            bail!("filter pattern must not be empty");
        }
        return Ok(LdMonitorCommand::SetFilter {
            pattern: pattern.to_string(),
        });
    }
    if let Some(pid) = command.strip_prefix("target-pid=") {
        let pid = pid
            .parse::<u32>()
            .with_context(|| format!("invalid target pid: {}", pid))?;
        return Ok(LdMonitorCommand::SetTargetPid { pid });
    }

    Ok(LdMonitorCommand::Raw(command.to_string()))
}

fn encode_ldmonitor_command(command: &LdMonitorCommand) -> String {
    match command {
        LdMonitorCommand::Start => "start".to_string(),
        LdMonitorCommand::Stop => "stop".to_string(),
        LdMonitorCommand::Status => "status".to_string(),
        LdMonitorCommand::SetFilter { pattern } => format!("filter={pattern}"),
        LdMonitorCommand::ClearFilter => "clear-filter".to_string(),
        LdMonitorCommand::SetTargetPid { pid } => format!("target-pid={pid}"),
        LdMonitorCommand::ClearTargetPid => "clear-target-pid".to_string(),
        LdMonitorCommand::Raw(raw) => raw.clone(),
    }
}

fn find_ksud_path() -> anyhow::Result<&'static str> {
    KSUD_CANDIDATES
        .iter()
        .copied()
        .find(|path| std::path::Path::new(path).exists())
        .context("ksud not found at /data/adb/ksu/bin/ksud or /data/adb/ksud")
}

impl MonitorControlBackend for KernelPatchControlBackend {
    fn send(&self, module: &str, command: &LdMonitorCommand) -> anyhow::Result<String> {
        let ksud = find_ksud_path()?;
        let encoded = encode_ldmonitor_command(command);

        let output = Command::new(ksud)
            .args(["kpm", "control", module, encoded.as_str()])
            .output()
            .with_context(|| format!("failed to execute {}", ksud))?;

        if !output.status.success() {
            let stderr = format_kpm_ctl_output(&output.stderr);
            let stdout = format_kpm_ctl_output(&output.stdout);
            bail!(
                "ksud kpm control failed: status={} stdout={} stderr={}",
                output.status,
                stdout,
                stderr
            );
        }

        let stdout = format_kpm_ctl_output(&output.stdout);
        if stdout.is_empty() {
            match command {
                LdMonitorCommand::Status => bail!(
                    "ksud kpm control returned no status payload; this KernelPatch/SukiSU build does not expose ctl0 out_msg"
                ),
                _ => Ok("ok".to_string()),
            }
        } else {
            Ok(stdout)
        }
    }
}

impl<B: MonitorControlBackend> LdMonitorController<B> {
    pub(crate) fn new(module_name: impl Into<String>, backend: B) -> Self {
        Self {
            backend,
            module_name: module_name.into(),
        }
    }

    pub(crate) fn send(&self, command: &LdMonitorCommand) -> anyhow::Result<String> {
        self.backend.send(&self.module_name, command)
    }

    pub(crate) fn start(&self) -> anyhow::Result<String> {
        self.send(&LdMonitorCommand::Start)
    }

    pub(crate) fn stop(&self) -> anyhow::Result<String> {
        self.send(&LdMonitorCommand::Stop)
    }

    pub(crate) fn status(&self) -> anyhow::Result<LdMonitorStatus> {
        let raw = self.send(&LdMonitorCommand::Status)?;
        if raw.trim().is_empty() || raw.trim() == "ok" {
            bail!("no status payload returned by backend");
        }
        parse_ldmonitor_status(&raw)
    }

    pub(crate) fn set_filter(&self, pattern: impl Into<String>) -> anyhow::Result<String> {
        self.send(&LdMonitorCommand::SetFilter {
            pattern: pattern.into(),
        })
    }

    pub(crate) fn clear_filter(&self) -> anyhow::Result<String> {
        self.send(&LdMonitorCommand::ClearFilter)
    }

    pub(crate) fn set_target_pid(&self, pid: u32) -> anyhow::Result<String> {
        self.send(&LdMonitorCommand::SetTargetPid { pid })
    }

    pub(crate) fn clear_target_pid(&self) -> anyhow::Result<String> {
        self.send(&LdMonitorCommand::ClearTargetPid)
    }
}

pub(crate) fn run_kpm_ctl(parts: &[String]) -> anyhow::Result<String> {
    let spec = parse_kpm_ctl_spec(parts)?;
    let command = parse_ldmonitor_command(&spec.command)?;
    let controller = LdMonitorController::new(spec.module, KernelPatchControlBackend);
    match command {
        LdMonitorCommand::Start => controller.start(),
        LdMonitorCommand::Stop => controller.stop(),
        LdMonitorCommand::Status => {
            let status = controller.status()?;
            Ok(format_ldmonitor_status(&status))
        }
        LdMonitorCommand::SetFilter { pattern } => controller.set_filter(pattern),
        LdMonitorCommand::ClearFilter => controller.clear_filter(),
        LdMonitorCommand::SetTargetPid { pid } => controller.set_target_pid(pid),
        LdMonitorCommand::ClearTargetPid => controller.clear_target_pid(),
        LdMonitorCommand::Raw(raw) => controller.send(&LdMonitorCommand::Raw(raw)),
    }
}

pub(crate) fn run_ldmon_ctl(command: &str) -> anyhow::Result<String> {
    let command = parse_ldmonitor_command(command)?;
    let controller = LdMonitorController::new(DEFAULT_LDMON_MODULE, KernelPatchControlBackend);
    match command {
        LdMonitorCommand::Start => controller.start(),
        LdMonitorCommand::Stop => controller.stop(),
        LdMonitorCommand::Status => {
            let status = controller.status()?;
            Ok(format_ldmonitor_status(&status))
        }
        LdMonitorCommand::SetFilter { pattern } => controller.set_filter(pattern),
        LdMonitorCommand::ClearFilter => controller.clear_filter(),
        LdMonitorCommand::SetTargetPid { pid } => controller.set_target_pid(pid),
        LdMonitorCommand::ClearTargetPid => controller.clear_target_pid(),
        LdMonitorCommand::Raw(raw) => controller.send(&LdMonitorCommand::Raw(raw)),
    }
}

pub(crate) fn configure_ldmonitor_watch(so_pattern: &str, target_pid: Option<u32>) -> anyhow::Result<()> {
    let controller = LdMonitorController::new(DEFAULT_LDMON_MODULE, KernelPatchControlBackend);
    controller.set_filter(so_pattern)?;
    if let Some(pid) = target_pid {
        controller.set_target_pid(pid)?;
    }
    controller.start()?;
    Ok(())
}

pub(crate) fn cleanup_ldmonitor_watch() -> anyhow::Result<()> {
    let controller = LdMonitorController::new(DEFAULT_LDMON_MODULE, KernelPatchControlBackend);
    controller.clear_filter()?;
    controller.clear_target_pid()?;
    controller.stop()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_kpm_ctl_spec_splits_module_and_command() {
        let parsed = parse_kpm_ctl_spec(&["kpm-dlopen-monitor".to_string(), "status".to_string()])
            .expect("parsed");

        assert_eq!(parsed.module, "kpm-dlopen-monitor");
        assert_eq!(parsed.command, "status");
    }

    #[test]
    fn parse_kpm_ctl_spec_rejects_empty_values() {
        let err = parse_kpm_ctl_spec(&["".to_string(), "".to_string()])
            .unwrap_err()
            .to_string();

        assert!(err.contains("module"));
    }

    #[test]
    fn format_kpm_ctl_output_trims_trailing_nuls() {
        let out = format_kpm_ctl_output(b"enabled=1 filter=<none>\0\0");
        assert_eq!(out, "enabled=1 filter=<none>");
    }

    #[test]
    fn parse_ldmonitor_command_supports_structured_commands() {
        assert_eq!(parse_ldmonitor_command("start").unwrap(), LdMonitorCommand::Start);
        assert_eq!(parse_ldmonitor_command("stop").unwrap(), LdMonitorCommand::Stop);
        assert_eq!(parse_ldmonitor_command("status").unwrap(), LdMonitorCommand::Status);
        assert_eq!(
            parse_ldmonitor_command("filter=libnative-lib.so").unwrap(),
            LdMonitorCommand::SetFilter {
                pattern: "libnative-lib.so".to_string()
            }
        );
        assert_eq!(
            parse_ldmonitor_command("target-pid=1234").unwrap(),
            LdMonitorCommand::SetTargetPid { pid: 1234 }
        );
    }

    #[test]
    fn encode_ldmonitor_command_keeps_backend_strings_localized() {
        assert_eq!(encode_ldmonitor_command(&LdMonitorCommand::Start), "start");
        assert_eq!(
            encode_ldmonitor_command(&LdMonitorCommand::SetFilter {
                pattern: "libfoo.so".to_string()
            }),
            "filter=libfoo.so"
        );
        assert_eq!(
            encode_ldmonitor_command(&LdMonitorCommand::SetTargetPid { pid: 42 }),
            "target-pid=42"
        );
    }

    #[test]
    fn parse_ldmonitor_status_reads_key_value_output() {
        let status = parse_ldmonitor_status(
            "enabled=1 filter=libnative-lib.so target_pid=1234 backend=netlink netlink_proto=31 subscriber=77",
        )
        .expect("status");

        assert!(status.enabled);
        assert_eq!(status.filter.as_deref(), Some("libnative-lib.so"));
        assert_eq!(status.target_pid, Some(1234));
        assert_eq!(status.backend.as_deref(), Some("netlink"));
        assert_eq!(status.subscriber, Some(77));
    }

    #[test]
    fn parse_ldmonitor_status_treats_empty_fields_as_none() {
        let status = parse_ldmonitor_status(
            "enabled=0 filter=<none> target_pid=0 backend=netlink netlink_proto=0 subscriber=0",
        )
        .expect("status");

        assert!(!status.enabled);
        assert_eq!(status.filter, None);
        assert_eq!(status.target_pid, None);
        assert_eq!(status.subscriber, None);
    }

    #[test]
    fn parse_ldmonitor_status_rejects_non_payload_output() {
        let err = parse_ldmonitor_status("0").unwrap_err().to_string();
        assert!(err.contains("missing enabled field"));
    }

    #[test]
    fn default_module_name_is_stable() {
        assert_eq!(DEFAULT_LDMON_MODULE, "kpm-dlopen-monitor");
    }

    #[test]
    fn format_ldmonitor_status_emits_stable_key_values() {
        let rendered = format_ldmonitor_status(&LdMonitorStatus {
            enabled: true,
            filter: Some("libfoo.so".to_string()),
            target_pid: Some(123),
            backend: Some("netlink".to_string()),
            subscriber: Some(77),
        });

        assert_eq!(
            rendered,
            "enabled=1 filter=libfoo.so target_pid=123 backend=netlink subscriber=77"
        );
    }

    #[test]
    fn status_requires_payload_from_backend() {
        struct EmptyBackend;

        impl MonitorControlBackend for EmptyBackend {
            fn send(&self, _module: &str, _command: &LdMonitorCommand) -> anyhow::Result<String> {
                Ok(String::new())
            }
        }

        let controller = LdMonitorController::new(DEFAULT_LDMON_MODULE, EmptyBackend);
        let err = controller.status().unwrap_err().to_string();
        assert!(err.contains("no status payload"));
    }
}
