//! The Tools page session against the real CLI: status, choosing a location, resetting it
//! and a rejected choice. Installing Ghidra downloads archives, so no test runs it.

#![cfg(target_os = "linux")]

mod common;

use biosmod_gui::controller::{Action, Outcome, Session, ToolChange};
use biosmod_gui::engine::{Engine, LocatableTool};
use serde_json::Value;
use std::path::Path;

fn engine(root: &Path) -> Engine {
    Engine::new(common::test_engine(), root)
        .unwrap()
        .with_env("BME_CONFIG_HOME", root.join("config"))
        .with_env("BME_CACHE_HOME", root.join("cache"))
        .with_env("BME_DATA_HOME", root.join("data"))
        .with_env("GHIDRA_INSTALL_DIR", "")
        .with_env("BME_FLASHROM", "")
}

fn run(session: &mut Session, engine: &Engine, action: Action) {
    let job = session
        .prepare(action)
        .unwrap_or_else(|error| panic!("{action:?}: expected preparation | received {error}"));
    assert!(
        session.finish(job.run(engine)),
        "{action:?}: expected current result"
    );
}

fn flashrom_row(session: &Session) -> Value {
    session
        .tool_report
        .as_ref()
        .expect("tools: expected a report")["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["id"] == "flashrom")
        .cloned()
        .expect("tools: expected a flashrom row")
}

#[test]
fn session_lists_tools_then_chooses_and_resets_a_flashrom() {
    let directory = tempfile::tempdir().unwrap();
    let engine = engine(directory.path());
    let mut session = Session::new().unwrap();
    run(&mut session, &engine, Action::Connect);
    run(&mut session, &engine, Action::Tools);
    assert_eq!(session.outcome, Outcome::Idle, "{}", session.status);
    let ids: Vec<String> = session.tool_report.as_ref().unwrap()["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row["id"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(
        ids,
        ["ghidra", "firmware-utils", "java", "jdk", "git", "flashrom"]
    );

    let program = common::fake_flashrom_program(directory.path());
    session.queue_tool_change(ToolChange::Choose {
        tool: LocatableTool::Flashrom,
        path: program.clone(),
    });
    run(&mut session, &engine, Action::ToolChange);
    assert_eq!(session.outcome, Outcome::Idle, "{}", session.status);
    let row = flashrom_row(&session);
    assert_eq!(row["origin"], "config", "{row}");
    assert_eq!(row["path"], program.to_string_lossy().as_ref(), "{row}");
    assert_eq!(row["health"], "ready", "{row}");

    session.queue_tool_change(ToolChange::Reset {
        tool: LocatableTool::Flashrom,
    });
    run(&mut session, &engine, Action::ToolChange);
    assert_ne!(flashrom_row(&session)["origin"], "config");
}

#[test]
fn choosing_a_folder_without_ghidra_fails_naming_the_folder() {
    let directory = tempfile::tempdir().unwrap();
    let engine = engine(directory.path());
    let mut session = Session::new().unwrap();
    run(&mut session, &engine, Action::Connect);
    let empty = directory.path().join("not-ghidra");
    std::fs::create_dir(&empty).unwrap();
    session.queue_tool_change(ToolChange::Choose {
        tool: LocatableTool::Ghidra,
        path: empty.clone(),
    });
    run(&mut session, &engine, Action::ToolChange);
    assert_eq!(session.outcome, Outcome::Failed, "{}", session.status);
    assert!(
        session
            .status_detail
            .contains("expected an installation containing support/analyzeHeadless")
            && session.status_detail.contains(empty.to_str().unwrap()),
        "(status detail): expected the rejected folder and the expected shape | received {}",
        session.status_detail
    );
}
