mod governed_support;
mod support;

use governed_support::{accept, report_turn, select, Fixture};
use serde_json::{json, Value};
use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use tn_runtime::{ActionOutcome, Phase, State};
use tn_runtime::{
    AuditEvent, AuditRecord, DecisionAudit, GovernedRuntime, SensitiveTraceEvent,
    SensitiveTraceKind, SensitiveTraceSink,
};

#[test]
fn required_action_runs_in_the_runtime_after_the_models_decrypt_call() {
    let mut fixture = Fixture::new();
    fixture.require_compliance();
    fixture
        .config
        .report_contract
        .section_rules
        .get_mut("finance")
        .unwrap()
        .required_tool = Some("record_review_receipt".into());
    let request = fixture.request("calculation");
    let audit_path = fixture.config.audit_path.clone();
    let (_keys, runtime) = fixture.runtime();
    let mut session = runtime.start_session(&request).unwrap();
    let turn = report_turn(&mut session);
    assert_eq!(turn.permit.phase(), Phase::GovernedAction);
    let body: Value = serde_json::from_slice(&turn.request_json).unwrap();
    assert_eq!(body["tools"][0]["function"]["name"], "emit_governed_record");
    let runtime_result: Value = serde_json::from_str(
        body["messages"].as_array().unwrap().last().unwrap()["content"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(runtime_result["runtime_action"], "record_review_receipt");
    let assistant = body["messages"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|message| message["role"] == "assistant")
        .collect::<Vec<_>>();
    assert_eq!(assistant.len(), 1);
    assert_eq!(assistant[0]["tool_calls"][0]["function"]["name"], "decrypt_value");
    let control: Value =
        serde_json::from_str(body["messages"][1]["content"].as_str().unwrap()).unwrap();
    assert_eq!(
        control["applicable_source_governance"]["sources"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    let audit = std::fs::read_to_string(audit_path).unwrap();
    assert!(!audit.contains("sections_selected_runtime"));
    assert!(audit.contains("sections_selected"));
    assert!(audit.contains("governed_tool_executed_runtime"));
    assert_eq!(audit.matches("turn_begin_authorized").count(), 1);
    let ActionOutcome::GovernedRelease(release) = accept(
        &mut session,
        turn,
        "emit_governed_record",
        json!({"report_html":"<p>25% drawdown.</p>"}),
    )
    .unwrap() else {
        panic!("report release")
    };
    assert_eq!(release.tool_objects.len(), 1);
    assert_eq!(session.state(), State::Complete);
}

#[test]
fn multiple_sections_are_all_offered_to_the_decrypt_call() {
    let mut fixture = Fixture::new();
    fixture
        .config
        .report_contract
        .allowed_input_sections
        .insert("audit".into());
    let request = fixture.request("calculation");
    let (_keys, runtime) = fixture.runtime();
    let mut session = runtime.start_session(&request).unwrap();
    let turn = session.next_model_turn().unwrap();
    assert_eq!(turn.permit.phase(), Phase::SectionSelection);
    let body: Value = serde_json::from_slice(&turn.request_json).unwrap();
    assert_eq!(body["tools"][0]["function"]["name"], "decrypt_value");
}

#[test]
fn required_action_readback_failure_blocks_any_model_turn() {
    let mut fixture = Fixture::new();
    fixture.require_compliance();
    let request = fixture.request("calculation");
    std::fs::copy(
        fixture.config.reader_key_dir.join("tn.agents.btn.mykit"),
        fixture
            .config
            .output_reader_key_dir
            .join("tn.agents.btn.mykit"),
    )
    .unwrap();
    let (_keys, runtime) = fixture.runtime();
    let mut session = runtime.start_session(&request).unwrap();
    select(&mut session, &["finance"]).unwrap();
    assert_eq!(
        session.next_model_turn().unwrap_err().code(),
        "tn_output_readback_failed"
    );
    assert_eq!(session.state(), State::Failed);
    assert!(runtime.start_session(&request).is_ok());
}

#[test]
fn an_outstanding_report_permit_cannot_repeat_runtime_actions() {
    let mut fixture = Fixture::new();
    fixture.require_compliance();
    let request = fixture.request("calculation");
    let audit_path = fixture.config.audit_path.clone();
    let (_keys, runtime) = fixture.runtime();
    let mut session = runtime.start_session(&request).unwrap();
    let _turn = report_turn(&mut session);
    assert_eq!(
        session.next_model_turn().unwrap_err().code(),
        "tn_turn_outstanding"
    );
    let audit = std::fs::read_to_string(audit_path).unwrap();
    assert_eq!(audit.matches("governed_tool_executed_runtime").count(), 1);
    assert_eq!(session.state(), State::Failed);
}

struct AuditSink {
    fail: Option<&'static str>,
    events: Mutex<Vec<AuditEvent>>,
}
impl DecisionAudit for AuditSink {
    fn append(&self, event: AuditEvent) -> io::Result<AuditRecord> {
        if self.fail == Some(event.kind.as_str()) {
            return Err(io::Error::other("audit unavailable"));
        }
        self.events.lock().unwrap().push(event);
        Ok(AuditRecord {
            prev_hash: "sha256:previous".into(),
            row_hash: "sha256:record".into(),
        })
    }
}
struct TraceSink {
    prepared_turns: AtomicUsize,
}
impl SensitiveTraceSink for TraceSink {
    fn append(&self, event: SensitiveTraceEvent<'_>) -> io::Result<()> {
        if event.kind == SensitiveTraceKind::TurnPrepared {
            self.prepared_turns
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |left| left.checked_sub(1))
                .map_err(|_| io::Error::other("trace unavailable"))?;
        }
        Ok(())
    }
}

#[test]
fn runtime_action_audit_failure_blocks_inference_and_release() {
    for kind in [
        "sections_selected",
        "governed_tool_executed_runtime",
        "tool_result_accepted_runtime",
    ] {
        let mut fixture = Fixture::new();
        fixture.require_compliance();
        let request = fixture.request("calculation");
        let audit = Arc::new(AuditSink {
            fail: Some(kind),
            events: Mutex::new(vec![]),
        });
        let sink = audit.clone();
        let runtime = GovernedRuntime::from_config_with_sink_factories(
            fixture.config,
            move |_| Ok(sink.clone() as Arc<dyn DecisionAudit>),
            |_| {
                Ok(Arc::new(TraceSink {
                    prepared_turns: AtomicUsize::new(usize::MAX),
                }) as Arc<dyn SensitiveTraceSink>)
            },
        )
        .unwrap();
        let mut session = runtime.start_session(&request).unwrap();
        let error = select(&mut session, &["finance"])
            .and_then(|()| session.next_model_turn().map(|_| ()))
            .unwrap_err();
        assert_eq!(error.code(), "tn_audit_append_failed");
        assert_eq!(session.state(), State::Failed);
        let events = audit.events.lock().unwrap();
        let begun = events
            .iter()
            .filter(|event| event.kind == "turn_begin_authorized")
            .count();
        assert_eq!(begun, 1, "only the decrypt turn ran");
        assert!(events
            .iter()
            .all(|event| event.kind != "standalone_use_completed"));
        drop(events);
        assert!(runtime.start_session(&request).is_ok());
    }
}

#[test]
fn report_trace_failure_blocks_the_model_after_runtime_actions() {
    let mut fixture = Fixture::new();
    fixture.require_compliance();
    let request = fixture.request("calculation");
    let audit = Arc::new(AuditSink {
        fail: None,
        events: Mutex::new(vec![]),
    });
    let sink = audit.clone();
    let runtime = GovernedRuntime::from_config_with_sink_factories(
        fixture.config,
        move |_| Ok(sink.clone() as Arc<dyn DecisionAudit>),
        |_| {
            Ok(Arc::new(TraceSink {
                prepared_turns: AtomicUsize::new(1),
            }) as Arc<dyn SensitiveTraceSink>)
        },
    )
    .unwrap();
    let mut session = runtime.start_session(&request).unwrap();
    let turn = report_turn(&mut session);
    assert_eq!(
        turn.permit
            .prepare(
                &turn.request_json,
                b"report",
                &support::literal_runnable_manifest(2048)
            )
            .unwrap_err()
            .code(),
        "tn_sensitive_trace_append_failed"
    );
    assert_eq!(session.state(), State::Failed);
    let events = audit.events.lock().unwrap();
    assert_eq!(
        events
            .iter()
            .filter(|event| event.kind == "tool_result_accepted_runtime")
            .count(),
        1
    );
    let begun = events
        .iter()
        .filter(|event| event.kind == "turn_begin_authorized")
        .count();
    assert_eq!(begun, 1, "only the decrypt turn ran");
    assert!(events
        .iter()
        .all(|event| event.kind != "standalone_use_completed"));
}
