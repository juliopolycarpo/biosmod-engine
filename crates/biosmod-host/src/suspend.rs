//! `diag suspend pm-test`: one kernel suspend test stage, with the machine's own
//! counters as the verdict.
//!
//! `/sys/power/pm_test` makes the next suspend stop at a debug checkpoint (five
//! seconds) and unwind, so the freezer, device, platform, processor or core steps
//! run without the machine ever sleeping. `none` is the real sleep and is refused:
//! a test that cannot wake the machine is not a diagnostic.
//!
//! # Rules
//!
//! - Root, and an explicit stage: one stage per run.
//! - `pm_test` must be `none` when the run starts (another armed test is somebody
//!   else's) and the kernel must list the stage.
//! - `platform`, `processors` and `core` need `mem_sleep` set to `deep`: with
//!   `s2idle` the kernel never reaches those checkpoints and the write would be a
//!   real sleep. `freezer` and `devices` stop before the mode matters.
//! - `mem` is written only after reading `pm_test` back as the armed stage.
//! - `pm_test` is set back to `none` on every path after it was armed, and a failure
//!   to do so is the loudest error the command has.
//! - `SIGINT`, `SIGTERM` and `SIGHUP` are held from arming until that restore; they
//!   are delivered afterwards. `SIGKILL` and a power cut cannot be held, which is why
//!   a leftover armed test is recognised at the next start.

use crate::acpi::{MEM_SLEEP_PATH, STATE_PATH};
use crate::bundle::{Bundle, BundleBuilder};
use crate::files::{HostFiles, HostWrite, read_trimmed};
use crate::identity::HostIdentity;
use crate::privilege::require_root;
use crate::receipt::Receipt;
use crate::{EntryKind, HostSurfaces, Timestamp};
use biosmod_core::{Code, Error, Result};
use serde::Serialize;
use std::collections::BTreeMap;

pub const PM_TEST_PATH: &str = "/sys/power/pm_test";
pub const SUSPEND_STATS_PATH: &str = "/sys/power/suspend_stats";

/// A suspend checkpoint that returns without sleeping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Stage {
    Freezer,
    Devices,
    Platform,
    Processors,
    Core,
}

impl Stage {
    pub const ALL: [Stage; 5] = [
        Stage::Freezer,
        Stage::Devices,
        Stage::Platform,
        Stage::Processors,
        Stage::Core,
    ];

    /// The word written to `/sys/power/pm_test`.
    pub fn name(self) -> &'static str {
        match self {
            Stage::Freezer => "freezer",
            Stage::Devices => "devices",
            Stage::Platform => "platform",
            Stage::Processors => "processors",
            Stage::Core => "core",
        }
    }

    /// Whether the checkpoint comes after the point where `s2idle` diverges.
    fn needs_deep_sleep(self) -> bool {
        !matches!(self, Stage::Freezer | Stage::Devices)
    }

    /// Parse a stage name. `none` is refused as the real sleep it is.
    ///
    /// Example: `Stage::parse("core")` is `Ok(Stage::Core)`; `Stage::parse("none")` is
    /// a `HOST_REFUSED` error.
    pub fn parse(text: &str) -> Result<Stage> {
        if let Some(stage) = Stage::ALL.iter().find(|stage| stage.name() == text) {
            return Ok(*stage);
        }
        if text == "none" {
            return Err(Error::new(
                Code::HostRefused,
                "pm-test stage: expected freezer | devices | platform | processors | core | received none (a real sleep; this command never suspends the machine for real)",
            ));
        }
        Err(Error::new(
            Code::Usage,
            format!(
                "pm-test stage: expected freezer | devices | platform | processors | core | received {text:?}"
            ),
        ))
    }
}

/// How the run ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    /// One success counted, no failure counted.
    Pass,
    /// The kernel counted a failure or no success.
    Fail,
    /// The test could not be armed or run.
    Error,
}

impl Status {
    pub fn name(self) -> &'static str {
        match self {
            Status::Pass => "pass",
            Status::Fail => "fail",
            Status::Error => "error",
        }
    }
}

/// What a run recorded.
#[derive(Debug, Clone, Serialize)]
pub struct PmTestReport {
    pub stage: Stage,
    pub status: Status,
    pub boot_id: String,
    pub started: String,
    pub finished: String,
    pub mem_sleep: String,
    /// `/sys/power/suspend_stats` files before and after.
    pub before: BTreeMap<String, String>,
    pub after: BTreeMap<String, String>,
    /// After minus before, for the numeric counters.
    pub delta: BTreeMap<String, i64>,
    /// Whether `/sys/power/pm_test` read back as `none` after the restore. When false
    /// the next suspend of any kind stops at the stage's checkpoint until a person
    /// repairs it.
    pub restored_pm_test: bool,
    /// `/sys/power/pm_test` as read after the restore.
    pub pm_test_after: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Why the kernel messages are missing, when the log could not be read.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kernel_log_error: Option<String>,
}

/// A report and the bundle that preserves it.
#[derive(Debug)]
pub struct PmTestRun {
    pub report: PmTestReport,
    pub bundle: Bundle,
}

/// The word in brackets: `freezer devices [none]` selects `none`.
///
/// Example: `selected("[s2idle] deep")` is `Some("s2idle")`.
pub fn selected(text: &str) -> Option<&str> {
    let start = text.find('[')? + 1;
    let end = text[start..].find(']')? + start;
    Some(&text[start..end])
}

fn choices(text: &str) -> Vec<&str> {
    text.split_whitespace()
        .map(|word| word.trim_matches(|c| c == '[' || c == ']'))
        .collect()
}

fn read_required(files: &dyn HostFiles, path: &str) -> Result<String> {
    match files.read(path) {
        Ok(bytes) => Ok(String::from_utf8_lossy(&bytes).trim().to_string()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(Error::new(
            Code::PlatformUnsupported,
            format!(
                "{path}: expected a kernel with suspend debugging (CONFIG_PM_DEBUG) | received no such file"
            ),
        )),
        Err(e) => Err(Error::new(Code::Io, format!("{path}: {e}"))),
    }
}

fn suspend_stats(files: &dyn HostFiles) -> Result<BTreeMap<String, String>> {
    let mut stats = BTreeMap::new();
    let entries = files.entries(SUSPEND_STATS_PATH).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            Error::new(
                Code::PlatformUnsupported,
                format!("{SUSPEND_STATS_PATH}: expected the suspend counters (kernel 5.x or later with CONFIG_PM_SLEEP) | received no such directory"),
            )
        } else {
            Error::new(Code::Io, format!("{SUSPEND_STATS_PATH}: {e}"))
        }
    })?;
    for entry in entries {
        if entry.kind == EntryKind::File {
            let path = format!("{SUSPEND_STATS_PATH}/{}", entry.name);
            let value = read_trimmed(files, &path).unwrap_or_default();
            stats.insert(entry.name, value);
        }
    }
    Ok(stats)
}

/// Whether a suspend_stats file counts events (`success`, `fail`, `failed_*`).
fn is_counter(name: &str) -> bool {
    name == "success" || name == "fail" || name.starts_with("failed_")
}

fn counter(stats: &BTreeMap<String, String>, name: &str) -> Option<i64> {
    stats.get(name)?.parse().ok()
}

/// Run one suspend test stage and report the counters.
///
/// See the module documentation for the rules. Returns `Err` when a rule refuses the
/// run (nothing was written) and `Ok` with status `error` or `fail` when the test
/// ran or failed to arm after the checks passed; both keep `pm_test` at `none`.
///
/// Example: `pm_test(&surfaces, &RootedFiles::system(), Stage::Freezer)?.report.status == Status::Pass`.
pub fn pm_test(host: &HostSurfaces, power: &dyn HostWrite, stage: Stage) -> Result<PmTestRun> {
    require_root(host.privilege, "diag suspend pm-test")?;
    let modes = read_required(host.files, PM_TEST_PATH)?;
    let available = choices(&modes);
    if !available.contains(&stage.name()) || !available.contains(&"none") {
        return Err(Error::new(
            Code::HostRefused,
            format!(
                "{PM_TEST_PATH}: expected {} and none to be listed | received {modes:?}",
                stage.name()
            ),
        ));
    }
    if selected(&modes) != Some("none") {
        return Err(Error::new(
            Code::HostRefused,
            format!(
                "{PM_TEST_PATH} selection: expected none | received {:?} (a test is still armed, probably left by a run that was killed before it could restore; no suspend was triggered. If nothing else is running one, put it back with: echo none > {PM_TEST_PATH})",
                selected(&modes).unwrap_or("")
            ),
        ));
    }
    let states = read_required(host.files, STATE_PATH)?;
    if !choices(&states).contains(&"mem") {
        return Err(Error::new(
            Code::HostRefused,
            format!("{STATE_PATH}: expected mem to be listed | received {states:?}"),
        ));
    }
    let mem_sleep = read_trimmed(host.files, MEM_SLEEP_PATH).unwrap_or_default();
    let mode = selected(&mem_sleep).unwrap_or("");
    if stage.needs_deep_sleep() && mode != "deep" {
        return Err(Error::new(
            Code::HostRefused,
            format!(
                "{MEM_SLEEP_PATH} selection for stage {}: expected deep | received {mode:?} (without deep sleep the kernel never reaches this checkpoint and the write would be a real sleep)",
                stage.name()
            ),
        ));
    }

    let identity = HostIdentity::read(host.files)?;
    let started = host.clock.now();
    let before = suspend_stats(host.files)?;
    // A kernel log that cannot be read costs the messages, not the test.
    let mut kernel_log_error = None;
    let first_new_record = match host.kernel_log.records() {
        Ok(records) => records
            .iter()
            .map(|record| record.sequence + 1)
            .max()
            .unwrap_or(0),
        Err(e) => {
            kernel_log_error = Some(e.to_string());
            0
        }
    };
    // Whatever the machine buffered should not be lost if the test goes wrong.
    power.sync_filesystems();

    // A Ctrl-C or SIGTERM between arming and the restore would leave the next suspend
    // armed to stop at a checkpoint. Hold them until pm_test is back (SIGKILL and a
    // power cut still cannot be held; startup detects the leftover).
    let held = crate::signals::SignalBlock::new();
    let outcome = arm_and_trigger(host.files, power, stage);
    // Always, whatever happened above.
    let restore = power.write(PM_TEST_PATH, "none\n");
    let pm_test_after = read_trimmed(host.files, PM_TEST_PATH).unwrap_or_default();
    drop(held);
    let restored = restore.is_ok() && selected(&pm_test_after) == Some("none");
    // A failed restore is not an early return: the run's evidence is still sealed and
    // published, flagged, so the caller reports it with the repair.
    let restore_failure = (!restored).then(|| {
        format!(
            "{PM_TEST_PATH}: expected none restored after the {} test | received {pm_test_after:?}{} (set it back by hand: echo none > {PM_TEST_PATH})",
            stage.name(),
            restore
                .err()
                .map(|e| format!(" and write error {e}"))
                .unwrap_or_default()
        )
    });

    let finished = host.clock.now();
    let after = suspend_stats(host.files)?;
    let delta: BTreeMap<String, i64> = after
        .keys()
        .filter(|name| is_counter(name))
        .filter_map(|name| {
            Some((
                name.clone(),
                counter(&after, name)? - counter(&before, name)?,
            ))
        })
        .collect();
    let counted_failure = delta.get("fail").is_some_and(|fail| *fail > 0);
    let (mut status, mut error) = match outcome {
        // The kernel counted the failure it reported: a failed test, not a broken run.
        Err(message) if counted_failure => (Status::Fail, Some(message)),
        Err(message) => (Status::Error, Some(message)),
        Ok(()) if delta.get("success") == Some(&1) && delta.get("fail") == Some(&0) => {
            (Status::Pass, None)
        }
        Ok(()) => (Status::Fail, None),
    };
    if let Some(failure) = restore_failure {
        // Whatever the counters said, the machine is left armed: the run is an error.
        status = Status::Error;
        error = Some(match error {
            Some(earlier) => format!("{failure}; earlier: {earlier}"),
            None => failure,
        });
    }
    let new_messages: Vec<String> = match host.kernel_log.records() {
        Ok(records) => records
            .iter()
            .filter(|record| record.sequence >= first_new_record)
            .map(|record| record.render())
            .collect(),
        Err(e) => {
            kernel_log_error.get_or_insert_with(|| e.to_string());
            Vec::new()
        }
    };
    let report = PmTestReport {
        stage,
        status,
        boot_id: identity.boot_id.clone(),
        started: started.rfc3339(),
        finished: finished.rfc3339(),
        mem_sleep,
        before,
        after,
        delta,
        restored_pm_test: restored,
        pm_test_after,
        error,
        kernel_log_error,
    };
    let bundle = seal(&identity, finished, &report, &new_messages)?;
    Ok(PmTestRun { report, bundle })
}

/// Select the stage, check that the kernel took it, then trigger the test suspend.
/// The message of whatever stopped it is the error.
fn arm_and_trigger(
    files: &dyn HostFiles,
    power: &dyn HostWrite,
    stage: Stage,
) -> std::result::Result<(), String> {
    power
        .write(PM_TEST_PATH, &format!("{}\n", stage.name()))
        .map_err(|e| format!("{PM_TEST_PATH}: {e}"))?;
    let armed = read_trimmed(files, PM_TEST_PATH).unwrap_or_default();
    if selected(&armed) != Some(stage.name()) {
        return Err(format!(
            "{PM_TEST_PATH} selection: expected [{}] | received {armed:?} (the selection did not take effect; no suspend was triggered)",
            stage.name()
        ));
    }
    power
        .write(STATE_PATH, "mem\n")
        .map_err(|e| format!("{STATE_PATH}: {e}"))
}

fn seal(
    identity: &HostIdentity,
    at: Timestamp,
    report: &PmTestReport,
    kernel_messages: &[String],
) -> Result<Bundle> {
    let mut builder = BundleBuilder::new();
    builder.add("pm-test.json", biosmod_core::json::pretty(report))?;
    let mut log = kernel_messages.join("\n");
    if !log.is_empty() {
        log.push('\n');
    }
    builder.add("kernel/delta.log", log.into_bytes())?;
    let change = |name: &str| report.delta.get(name).copied().unwrap_or(0);
    let mut observations = vec![format!(
        "Stage {} ended {}: success counter {:+}, fail counter {:+}, pm_test restored to none: {} (read back as {:?}).",
        report.stage.name(),
        report.status.name(),
        change("success"),
        change("fail"),
        report.restored_pm_test,
        report.pm_test_after
    )];
    observations.push(format!("mem_sleep: {}", report.mem_sleep));
    if let Some(error) = &report.error {
        observations.push(format!("Error: {error}"));
    }
    match &report.kernel_log_error {
        None => observations.push(format!(
            "{} kernel messages followed the start of the run.",
            kernel_messages.len()
        )),
        Some(e) => observations.push(format!("Kernel messages unavailable: {e}")),
    }
    Ok(builder.seal(
        identity,
        at,
        Receipt {
            command: "diag suspend pm-test",
            title: format!("Suspend test stage {}", report.stage.name()),
            observations,
            limits: "pm_test stops at a debug checkpoint and unwinds: a pass says the kernel's steps up to that stage worked, not that the machine can enter and leave the sleep state. No real sleep occurred, and systemd's sleep hooks did not run. One stage, one run; intermittent failures need repeats.".into(),
            digests: BTreeMap::new(),
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::{
        FakePowerSysfs, FakePrivilege, FakeSysfs, FixedClock, UnreadableKernelLog,
    };

    fn run(fake: &FakePowerSysfs, privilege: &FakePrivilege, stage: Stage) -> Result<PmTestRun> {
        pm_test(
            &HostSurfaces {
                files: fake,
                kernel_log: fake,
                privilege,
                clock: &FixedClock,
            },
            fake,
            stage,
        )
    }

    fn run_as_root(fake: &FakePowerSysfs, stage: Stage) -> Result<PmTestRun> {
        run(fake, &FakePrivilege::root(), stage)
    }

    fn written(fake: &FakePowerSysfs) -> Vec<String> {
        fake.writes()
            .into_iter()
            .map(|(path, text)| format!("{path}={text}"))
            .collect()
    }

    #[test]
    fn stage_names_parse_and_none_is_refused_as_a_real_sleep() {
        for stage in Stage::ALL {
            assert_eq!(Stage::parse(stage.name()).unwrap(), stage);
        }
        let none = Stage::parse("none").unwrap_err();
        assert_eq!(none.code, Code::HostRefused, "{none}");
        assert!(none.message.contains("received none"), "{none}");
        let unknown = Stage::parse("deep").unwrap_err();
        assert_eq!(unknown.code, Code::Usage, "{unknown}");
        assert!(unknown.message.contains("received \"deep\""), "{unknown}");
    }

    #[test]
    fn only_the_late_stages_need_deep_sleep() {
        let needing: Vec<_> = Stage::ALL
            .into_iter()
            .filter(|stage| stage.needs_deep_sleep())
            .map(Stage::name)
            .collect();
        assert_eq!(needing, ["platform", "processors", "core"]);
    }

    #[test]
    fn selected_and_choices_read_the_bracketed_listing() {
        assert_eq!(selected("[s2idle] deep"), Some("s2idle"));
        assert_eq!(selected("s2idle [deep]\n"), Some("deep"));
        assert_eq!(selected("freeze mem"), None);
        assert_eq!(choices("freezer [none]"), ["freezer", "none"]);
    }

    #[test]
    fn only_event_counters_enter_the_delta() {
        assert!(is_counter("success") && is_counter("fail") && is_counter("failed_resume"));
        assert!(!is_counter("last_failed_errno") && !is_counter("last_failed_dev"));
    }

    #[test]
    fn a_freezer_pass_on_the_default_s2idle_machine_restores_pm_test() {
        let fake = FakePowerSysfs::mr9a_s2idle();
        let run = run_as_root(&fake, Stage::Freezer).unwrap();
        assert_eq!(run.report.status, Status::Pass, "{:?}", run.report);
        assert_eq!(run.report.delta["success"], 1);
        assert_eq!(run.report.delta["fail"], 0);
        assert!(!run.report.delta.contains_key("last_failed_errno"));
        assert_eq!(run.report.before["success"], "0");
        assert_eq!(run.report.after["success"], "1");
        assert!(run.report.restored_pm_test);
        assert_eq!(
            run.report.pm_test_after,
            "freezer devices platform processors core [none]"
        );
        assert_eq!(
            written(&fake),
            [
                "/sys/power/pm_test=freezer",
                "/sys/power/state=mem",
                "/sys/power/pm_test=none"
            ]
        );
        assert_eq!(fake.pm_test(), "none");
        assert_eq!(fake.real_sleeps(), 0);
        assert!(fake.violations().is_empty(), "{:?}", fake.violations());
        let log = String::from_utf8(run.bundle.get("kernel/delta.log").unwrap().to_vec()).unwrap();
        assert!(log.contains("PM: suspend entry (deep)"), "{log}");
        assert!(!log.contains("Registered nosave memory"), "{log}");
        let evidence: serde_json::Value =
            serde_json::from_slice(run.bundle.get("evidence.json").unwrap()).unwrap();
        assert_eq!(evidence["host"]["command"], "diag suspend pm-test");
        assert_eq!(evidence["host"]["boot_id"], FakeSysfs::BOOT_ID);
        let saved: serde_json::Value =
            serde_json::from_slice(run.bundle.get("pm-test.json").unwrap()).unwrap();
        assert_eq!(saved["stage"], "freezer");
        assert_eq!(saved["status"], "pass");
    }

    #[test]
    fn a_core_pass_needs_and_gets_deep_sleep() {
        let fake = FakePowerSysfs::mr9a_deep();
        let run = run_as_root(&fake, Stage::Core).unwrap();
        assert_eq!(run.report.status, Status::Pass);
        assert_eq!(run.report.mem_sleep, "s2idle [deep]");
        assert_eq!(written(&fake)[0], "/sys/power/pm_test=core");
    }

    #[test]
    fn late_stages_under_s2idle_are_refused_before_any_write() {
        for stage in [Stage::Platform, Stage::Processors, Stage::Core] {
            let fake = FakePowerSysfs::mr9a_s2idle();
            let error = run_as_root(&fake, stage).unwrap_err();
            assert_eq!(error.code, Code::HostRefused, "{error}");
            assert!(
                error
                    .message
                    .contains("expected deep | received \"s2idle\""),
                "{error}"
            );
            assert!(fake.writes().is_empty());
            assert_eq!(fake.real_sleeps(), 0);
        }
    }

    #[test]
    fn a_non_root_user_is_refused_before_any_read_or_write() {
        let fake = FakePowerSysfs::mr9a_deep();
        let error = run(&fake, &FakePrivilege::user(1000), Stage::Freezer).unwrap_err();
        assert_eq!(error.code, Code::HostRefused, "{error}");
        assert!(error.message.contains("received uid 1000"), "{error}");
        assert!(fake.writes().is_empty());
    }

    #[test]
    fn an_unlisted_stage_or_an_armed_test_is_refused_untouched() {
        let missing = FakePowerSysfs::mr9a_deep()
            .with_pm_test_listing("freezer devices platform processors [none]");
        let error = run_as_root(&missing, Stage::Core).unwrap_err();
        assert_eq!(error.code, Code::HostRefused, "{error}");
        assert!(
            error
                .message
                .contains("expected core and none to be listed"),
            "{error}"
        );
        assert!(missing.writes().is_empty());

        let armed = FakePowerSysfs::mr9a_deep()
            .with_pm_test_listing("[freezer] devices platform processors core none");
        let error = run_as_root(&armed, Stage::Freezer).unwrap_err();
        assert_eq!(error.code, Code::HostRefused, "{error}");
        assert!(
            error
                .message
                .contains("expected none | received \"freezer\""),
            "{error}"
        );
        assert!(armed.writes().is_empty());
        // A leftover from a killed run must come with the repair, not only the refusal.
        assert!(
            error.message.contains("echo none > /sys/power/pm_test"),
            "(leftover pm_test message): expected the repair command | received {error}"
        );
    }

    #[test]
    fn a_kernel_without_mem_is_refused() {
        let fake = FakePowerSysfs::mr9a_deep().with_states("freeze disk");
        let error = run_as_root(&fake, Stage::Freezer).unwrap_err();
        assert_eq!(error.code, Code::HostRefused, "{error}");
        assert!(
            error.message.contains("expected mem to be listed"),
            "{error}"
        );
        assert!(fake.writes().is_empty());
    }

    #[test]
    fn missing_kernel_files_are_an_unsupported_platform_not_a_failure() {
        let sysfs = FakeSysfs::mr9a();
        let files = sysfs.files();
        let fake = FakePowerSysfs::mr9a_deep();
        let error = pm_test(
            &HostSurfaces {
                files: &files,
                kernel_log: &fake,
                privilege: &FakePrivilege::root(),
                clock: &FixedClock,
            },
            &fake,
            Stage::Freezer,
        )
        .unwrap_err();
        assert_eq!(error.code, Code::PlatformUnsupported, "{error}");
        assert!(error.message.contains("/sys/power/pm_test"), "{error}");

        let no_stats = FakePowerSysfs::mr9a_deep().without_suspend_stats();
        let error = run_as_root(&no_stats, Stage::Freezer).unwrap_err();
        assert_eq!(error.code, Code::PlatformUnsupported, "{error}");
        assert!(error.message.contains("suspend_stats"), "{error}");
        assert!(no_stats.writes().is_empty());
    }

    #[test]
    fn an_ignored_selection_never_triggers_the_suspend() {
        let fake = FakePowerSysfs::mr9a_deep().ignoring_pm_test_writes();
        let run = run_as_root(&fake, Stage::Freezer).unwrap();
        assert_eq!(run.report.status, Status::Error);
        let error = run.report.error.as_deref().unwrap();
        assert!(
            error.contains("the selection did not take effect"),
            "{error}"
        );
        assert_eq!(
            written(&fake),
            ["/sys/power/pm_test=freezer", "/sys/power/pm_test=none"]
        );
        assert_eq!(fake.real_sleeps(), 0);
    }

    #[test]
    fn a_counted_failure_is_a_fail_and_still_restores() {
        let fake = FakePowerSysfs::mr9a_deep().failing_suspend();
        let run = run_as_root(&fake, Stage::Devices).unwrap();
        assert_eq!(run.report.status, Status::Fail);
        assert_eq!(run.report.delta["fail"], 1);
        assert_eq!(run.report.delta["failed_suspend"], 1);
        assert_eq!(run.report.delta["success"], 0);
        assert!(
            run.report
                .error
                .as_deref()
                .unwrap()
                .contains("input/output error")
        );
        assert_eq!(fake.pm_test(), "none");
        let log = String::from_utf8(run.bundle.get("kernel/delta.log").unwrap().to_vec()).unwrap();
        assert!(log.contains("Some devices failed to suspend"), "{log}");
    }

    #[test]
    fn a_rejected_state_write_without_counters_is_an_error() {
        let fake = FakePowerSysfs::mr9a_deep().rejecting_state_write();
        let run = run_as_root(&fake, Stage::Freezer).unwrap();
        assert_eq!(run.report.status, Status::Error);
        assert_eq!(run.report.delta["success"], 0);
        assert!(run.report.error.as_deref().unwrap().contains("busy"));
        assert_eq!(fake.pm_test(), "none");
    }

    #[test]
    fn a_failed_restore_is_still_sealed_flagged_and_names_the_manual_fix() {
        let fake = FakePowerSysfs::mr9a_deep().failing_pm_test_restore();
        let run = run_as_root(&fake, Stage::Freezer).unwrap();
        assert!(!run.report.restored_pm_test, "{:?}", run.report);
        assert_eq!(run.report.status, Status::Error);
        let error = run.report.error.as_deref().unwrap();
        assert!(
            error.contains("expected none restored after the freezer test"),
            "{error}"
        );
        assert!(error.contains("echo none > /sys/power/pm_test"), "{error}");
        assert_eq!(fake.pm_test(), "freezer");
        // The evidence of the half-finished run is not thrown away.
        let saved: serde_json::Value =
            serde_json::from_slice(run.bundle.get("pm-test.json").unwrap()).unwrap();
        assert_eq!(saved["restored_pm_test"], false);
        assert!(run.bundle.get("evidence.json").is_some());
    }

    /// Forwards to the fake and notes whether the stop signals were held at each write.
    #[cfg(unix)]
    struct SignalSpyPower<'a> {
        inner: &'a FakePowerSysfs,
        held: std::cell::RefCell<Vec<(String, bool)>>,
    }

    #[cfg(unix)]
    impl HostWrite for SignalSpyPower<'_> {
        fn write(&self, path: &str, text: &str) -> std::io::Result<()> {
            let blocked = crate::signals::is_blocked(libc::SIGINT)
                && crate::signals::is_blocked(libc::SIGTERM)
                && crate::signals::is_blocked(libc::SIGHUP);
            self.held
                .borrow_mut()
                .push((format!("{path}={text}"), blocked));
            self.inner.write(path, text)
        }
    }

    #[cfg(unix)]
    #[test]
    fn stop_signals_are_held_from_arming_to_the_restore_and_released_after() {
        let fake = FakePowerSysfs::mr9a_s2idle();
        let spy = SignalSpyPower {
            inner: &fake,
            held: Default::default(),
        };
        let host = HostSurfaces {
            files: &fake,
            kernel_log: &fake,
            privilege: &FakePrivilege::root(),
            clock: &FixedClock,
        };
        pm_test(&host, &spy, Stage::Freezer).unwrap();
        let held = spy.held.borrow();
        assert_eq!(
            held.len(),
            3,
            "(writes): expected arm, mem, restore | received {held:?}"
        );
        for (write, blocked) in held.iter() {
            assert!(
                blocked,
                "(signals at {write}): expected SIGINT, SIGTERM and SIGHUP blocked | received unblocked"
            );
        }
        assert!(
            !crate::signals::is_blocked(libc::SIGINT),
            "(signals after the run): expected SIGINT unblocked | received blocked"
        );
    }

    #[test]
    fn an_unreadable_kernel_log_costs_the_messages_not_the_test() {
        let fake = FakePowerSysfs::mr9a_deep();
        let unreadable = UnreadableKernelLog;
        let run = pm_test(
            &HostSurfaces {
                files: &fake,
                kernel_log: &unreadable,
                privilege: &FakePrivilege::root(),
                clock: &FixedClock,
            },
            &fake,
            Stage::Freezer,
        )
        .unwrap();
        assert_eq!(run.report.status, Status::Pass);
        assert!(
            run.report
                .kernel_log_error
                .as_deref()
                .unwrap()
                .contains("dmesg_restrict")
        );
        assert!(run.bundle.get("kernel/delta.log").unwrap().is_empty());
        let evidence =
            String::from_utf8(run.bundle.get("evidence.json").unwrap().to_vec()).unwrap();
        assert!(
            evidence.contains("Kernel messages unavailable"),
            "{evidence}"
        );
    }
}
