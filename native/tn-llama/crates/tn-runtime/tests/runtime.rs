mod governed_support;
mod support;

use std::fs;
use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use std::thread;

use governed_support::{Fixture, SessionHarness};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use support::{canonical_json, literal_runnable_manifest, prepare_and_begin};
use tn_runtime::{
    ActionOutcome, AuditEvent, AuditFacts, AuditRecord, DecisionAudit, GovernedReportRelease,
    GovernedRuntime, ModelTurn, SensitiveTraceEvent, SensitiveTraceKind, SensitiveTraceSink, State,
};

#[test]
fn runtime_accepts_group_capability_writer_authority_for_a_configured_event_type() {
    let Fixture {
        legacy: _keys,
        mut config,
        ..
    } = Fixture::new();
    config.expected_event_type = "configured.source.event".to_string();

    GovernedRuntime::from_config(config).unwrap();
}

#[test]
fn one_long_lived_runtime_owns_admission_and_abort_or_drop_releases_it() {
    let fixture = Fixture::new();
    let request = fixture.request("calculation");
    let (_keys, runtime) = fixture.runtime();

    let mut first = runtime.start_session(&request).unwrap();
    let error = runtime.start_session(&request).unwrap_err();
    assert_eq!(error.code(), "tn_active_session_limit");
    first.abort().unwrap();
    assert_eq!(first.state(), State::Failed);

    let second = runtime.start_session(&request).unwrap();
    drop(second);
    runtime.start_session(&request).unwrap();
}

#[test]
fn a_second_turn_cannot_be_issued_while_one_is_outstanding() {
    let mut harness = SessionHarness::new("one outstanding turn");
    let _turn = harness.session.next_model_turn().unwrap();

    let error = harness.session.next_model_turn().unwrap_err();

    assert_eq!(error.code(), "tn_turn_outstanding");
    assert_eq!(harness.session.state(), State::Failed);
}

#[test]
fn concurrent_start_session_calls_admit_exactly_one_request() {
    let fixture = Fixture::new();
    let raw = Arc::new(fixture.request("calculation"));
    let (_keys, runtime) = fixture.runtime();
    let runtime = Arc::new(runtime);
    let barrier = Arc::new(Barrier::new(3));
    let finish = Arc::new(Barrier::new(3));
    let mut workers = Vec::new();

    for _ in 0..2 {
        let runtime = Arc::clone(&runtime);
        let raw = Arc::clone(&raw);
        let barrier = Arc::clone(&barrier);
        let finish = Arc::clone(&finish);
        workers.push(thread::spawn(move || {
            barrier.wait();
            let result = runtime.start_session(&raw);
            finish.wait();
            result.is_ok()
        }));
    }
    barrier.wait();
    finish.wait();
    let successes = workers
        .into_iter()
        .map(|worker| usize::from(worker.join().unwrap()))
        .sum::<usize>();

    assert_eq!(successes, 1);
}

#[test]
fn admission_audit_records_reservation_then_governance_and_binds_terminal_denial() {
    let fixture = Fixture::new();
    let request = fixture.request_with("truthful admission audit");
    let audit = Arc::new(RecordingAudit::passing());
    let trace = Arc::new(RecordingTrace::passing());
    let (keys, runtime) = runtime_with_sinks(fixture, Arc::clone(&audit), trace);
    let harness = SessionHarness::with_runtime(keys, runtime.clone(), request);

    let admission_error = runtime.start_session(&harness.raw_request).unwrap_err();
    assert_eq!(admission_error.code(), "tn_active_session_limit");

    let events = audit.events.lock().unwrap();
    assert_eq!(events.len(), 3);
    let reserved = &events[0];
    assert_eq!(reserved.kind, "standalone_object_reserved");
    assert_eq!(reserved.state_before, "received");
    assert_eq!(reserved.state_after, "governance_admission");
    assert_eq!(reserved.target_row_hash, harness.object_id);
    assert_eq!(reserved.outcome, "allow");
    assert_eq!(reserved.error_code, None);
    assert_eq!(
        reserved.facts,
        AuditFacts {
            hashes_verified: Some(true),
            signature_verified: Some(true),
            ..AuditFacts::default()
        }
    );

    let governance = &events[1];
    assert_eq!(governance.kind, "governance_opened_and_verified");
    assert_eq!(governance.state_before, "governance_admission");
    assert_eq!(governance.state_after, "section_selection");
    assert_eq!(governance.target_row_hash, harness.object_id);
    assert_eq!(governance.request_digest, reserved.request_digest);
    assert_eq!(governance.facts.hashes_verified, Some(true));
    assert!(governance
        .facts
        .governance_value_count
        .is_some_and(|count| count > 0));
    assert_eq!(
        governance.facts.governance_value_count,
        governance.facts.governance_commitment_count
    );
    assert!(governance.llama_task_id.is_none());

    let denied = &events[2];
    assert_eq!(denied.kind, "terminal_error");
    assert_eq!(denied.state_before, "received");
    assert_eq!(denied.state_after, "failed");
    assert_eq!(denied.target_row_hash, harness.object_id);
    assert_eq!(denied.request_digest, reserved.request_digest);
    assert_eq!(denied.outcome, "deny");
    assert_eq!(
        denied.error_code.as_deref(),
        Some("tn_active_session_limit")
    );
    assert_eq!(denied.facts, AuditFacts::default());
}

#[test]
fn pre_verification_parse_failure_records_only_unbound_safe_error_evidence() {
    let audit = Arc::new(RecordingAudit::passing());
    let trace = Arc::new(RecordingTrace::passing());
    let (_keys, runtime) = runtime_with_sinks(Fixture::new(), Arc::clone(&audit), trace);

    let error = runtime.start_session(b"{").unwrap_err();

    assert_eq!(error.code(), "tn_request_shape");
    let events = audit.events.lock().unwrap();
    assert_eq!(events.len(), 1);
    let denied = &events[0];
    assert_eq!(denied.kind, "terminal_error");
    assert_eq!(denied.state_before, "received");
    assert_eq!(denied.state_after, "failed");
    assert_eq!(denied.target_row_hash, "");
    assert_eq!(denied.request_digest, "");
    assert_eq!(denied.outcome, "deny");
    assert_eq!(denied.error_code.as_deref(), Some("tn_request_shape"));
    assert_eq!(denied.facts, AuditFacts::default());
}

#[test]
fn admission_error_is_masked_only_when_its_terminal_audit_append_fails() {
    let fixture = Fixture::new();
    let request = fixture.request("calculation");
    let audit = Arc::new(RecordingAudit::failing_once("terminal_error"));
    let trace = Arc::new(RecordingTrace::passing());
    let (_keys, runtime) = runtime_with_sinks(fixture, Arc::clone(&audit), trace);
    let first = runtime.start_session(&request).unwrap();

    let error = runtime.start_session(&request).unwrap_err();

    assert_eq!(error.code(), "tn_audit_append_failed");
    assert_eq!(audit.failed_appends(), 1);
    drop(first);
}

#[test]
fn every_rejected_runnable_mode_terminalizes_before_begin_or_a_later_turn() {
    let base = literal_runnable_manifest(2048);
    let mut cases = vec![
        ("schema", manifest_with(&base, &["schema"], json!("other"))),
        (
            "context shift",
            manifest_with(&base, &["effective_ctx_shift"], json!(true)),
        ),
        (
            "task type",
            manifest_with(&base, &["task", "type"], json!("embedding")),
        ),
        (
            "empty tokens",
            manifest_with(&base, &["task", "tokens"], json!([])),
        ),
        (
            "mtmd tokens",
            manifest_with(&base, &["task", "tokens_has_mtmd"], json!(true)),
        ),
        (
            "assigned slot",
            manifest_with(&base, &["task", "id_slot"], json!(0)),
        ),
        (
            "parent task",
            manifest_with(&base, &["task", "id_parent"], json!(7)),
        ),
        (
            "child task",
            manifest_with(&base, &["task", "child_count"], json!(1)),
        ),
        (
            "cli mode",
            manifest_with(&base, &["task", "cli"], json!(true)),
        ),
        (
            "cli prompt",
            manifest_with(&base, &["task", "cli_prompt_byte_length"], json!(1)),
        ),
        (
            "cli file",
            manifest_with(&base, &["task", "cli_file_count"], json!(1)),
        ),
        (
            "streaming",
            manifest_with(&base, &["params", "stream"], json!(true)),
        ),
        (
            "prompt cache",
            manifest_with(&base, &["params", "cache_prompt"], json!(true)),
        ),
        (
            "cache reuse",
            manifest_with(&base, &["params", "n_cache_reuse"], json!(1)),
        ),
        (
            "multiple completions",
            manifest_with(&base, &["params", "n_cmpl"], json!(2)),
        ),
        (
            "phase token budget",
            manifest_with(&base, &["params", "n_predict"], json!(127)),
        ),
        (
            "lora",
            manifest_with(
                &base,
                &["params", "lora"],
                json!([{"path": "adapter.gguf"}]),
            ),
        ),
        (
            "result type",
            manifest_with(&base, &["params", "res_type"], json!("tokens")),
        ),
        (
            "speculation",
            manifest_with(&base, &["speculative", "types"], json!(["draft"])),
        ),
        (
            "unknown field",
            manifest_with(&base, &["unknown"], json!(0)),
        ),
        (
            "wrong type",
            manifest_with(&base, &["effective_ctx_shift"], json!("false")),
        ),
    ];
    let base_text = String::from_utf8(base.clone()).unwrap();
    cases.push((
        "duplicate field",
        base_text
            .replacen(
                "\"schema\":",
                "\"schema\":\"tn.llama.runnable-task.v1\",\"schema\":",
                1,
            )
            .into_bytes(),
    ));

    let fixture = Fixture::new();
    let request = fixture.request("calculation");
    let audit = Arc::new(RecordingAudit::passing());
    let trace = Arc::new(RecordingTrace::passing());
    let (_keys, runtime) = runtime_with_sinks(fixture, Arc::clone(&audit), trace);
    for (index, (name, manifest)) in cases.into_iter().enumerate() {
        let mut session = runtime.start_session(&request).unwrap();
        let turn = session.next_model_turn().unwrap();

        let error = turn
            .permit
            .prepare(&turn.request_json, b"rendered prompt", &manifest)
            .unwrap_err();

        assert_eq!(error.code(), "tn_runnable_manifest_invalid", "{name}");
        assert_eq!(session.state(), State::Failed, "{name}");
        assert_eq!(
            session.next_model_turn().unwrap_err().code(),
            "tn_session_state",
            "{name}"
        );
        assert!(
            audit
                .events
                .lock()
                .unwrap()
                .iter()
                .all(|event| event.kind != "turn_begin_authorized"),
            "{name} at case {index}"
        );
    }
}

#[test]
fn sequential_sessions_append_to_one_runtime_evidence_without_truncating_the_first() {
    let fixture = Fixture::new();
    let audit_path = fixture.config.audit_path.clone();
    let trace_dir = fixture.config.raw_trace_dir.clone();
    let second = fixture.request_with("second sequential request");
    let first = fixture.request_with("first sequential request");
    let (keys, runtime) = fixture.runtime();
    let mut harness = SessionHarness::with_runtime(keys, runtime.clone(), first);
    complete_report(&mut harness, 101);
    let audit_after_first = fs::read(&audit_path).unwrap();
    let trace_path = fs::read_dir(&trace_dir)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let trace_after_first = fs::read(&trace_path).unwrap();

    let mut second_session = runtime.start_session(&second).unwrap();
    let second_turn = second_session.next_model_turn().unwrap();
    second_turn
        .permit
        .prepare(
            &second_turn.request_json,
            b"second-decrypt",
            &literal_runnable_manifest(2048),
        )
        .unwrap();

    let audit_after_second = fs::read(&audit_path).unwrap();
    let trace_after_second = fs::read(&trace_path).unwrap();
    assert!(audit_after_second.starts_with(&audit_after_first));
    assert!(audit_after_second.len() > audit_after_first.len());
    assert!(trace_after_second.starts_with(&trace_after_first));
    assert!(trace_after_second.len() > trace_after_first.len());
    assert_eq!(fs::read_dir(&trace_dir).unwrap().count(), 1);
}

#[test]
fn begin_audit_and_trace_bind_the_exact_body_prompt_manifest_and_task() {
    let fixture = Fixture::new();
    let request = fixture.request_with("digest binding");
    let audit = Arc::new(RecordingAudit::passing());
    let trace = Arc::new(RecordingTrace::passing());
    let (keys, runtime) = runtime_with_sinks(fixture, Arc::clone(&audit), Arc::clone(&trace));
    let mut harness = SessionHarness::with_runtime(keys, runtime, request);
    let turn = harness.session.next_model_turn().unwrap();
    let request = turn.request_json.clone();
    let manifest = literal_runnable_manifest(2048);
    let prompt = b"exact rendered prompt";
    turn.permit.prepare(&request, prompt, &manifest).unwrap();
    turn.permit
        .begin(102, 7, &request, prompt, &manifest)
        .unwrap();

    let events = audit.events.lock().unwrap();
    let begun = events
        .iter()
        .find(|event| event.kind == "turn_begin_authorized")
        .unwrap();
    assert_eq!(begun.llama_task_id, Some(102));
    assert_eq!(begun.llama_slot_id, Some(7));
    assert_eq!(
        begun.facts.model_request_digest.as_ref().unwrap().as_str(),
        domain_digest(b"tn.llama.model-request.v1\0", &request)
    );
    assert_eq!(
        begun
            .facts
            .rendered_prompt_digest
            .as_ref()
            .unwrap()
            .as_str(),
        domain_digest(b"tn.llama.rendered-prompt.v1\0", prompt)
    );
    assert_eq!(
        begun.facts.runnable_task_digest.as_ref().unwrap().as_str(),
        domain_digest(b"tn.llama.runnable-task.v1\0", &manifest)
    );
    drop(events);

    let traces = trace.events.lock().unwrap();
    assert_eq!(traces.len(), 3);
    assert_eq!(traces[0].kind, SensitiveTraceKind::Ingress);
    assert_eq!(
        traces[0].request_json.as_deref(),
        Some(harness.raw_request.as_slice())
    );
    assert_eq!(traces[1].kind, SensitiveTraceKind::TurnPrepared);
    assert_eq!(traces[1].request_json.as_deref(), Some(request.as_slice()));
    assert_eq!(
        traces[1].rendered_prompt.as_deref(),
        Some(prompt.as_slice())
    );
    assert_eq!(
        traces[1].runnable_manifest.as_deref(),
        Some(manifest.as_slice())
    );
    assert_eq!(traces[2].kind, SensitiveTraceKind::TurnStarted);
    assert_eq!(traces[2].task_id, Some(102));
    assert_eq!(traces[2].slot_id, Some(7));
}

#[test]
fn sensitive_local_trace_captures_the_exact_ingress_and_closed_release_bytes() {
    let fixture = Fixture::new();
    let request = fixture.request_with("trace this exact governed request");
    let audit = Arc::new(RecordingAudit::passing());
    let trace = Arc::new(RecordingTrace::passing());
    let (keys, runtime) = runtime_with_sinks(fixture, audit, Arc::clone(&trace));
    let mut harness = SessionHarness::with_runtime(keys, runtime, request);
    let ingress = harness.raw_request.clone();

    let release = complete_report(&mut harness, 111);
    let release_bytes = release.to_json_bytes().unwrap();

    let traces = trace.events.lock().unwrap();
    let ingress_event = traces
        .iter()
        .find(|event| event.kind == SensitiveTraceKind::Ingress)
        .unwrap();
    assert_eq!(
        ingress_event.request_json.as_deref(),
        Some(ingress.as_slice())
    );
    let release_event = traces
        .iter()
        .find(|event| event.kind == SensitiveTraceKind::Release)
        .unwrap();
    assert_eq!(
        release_event.parsed_content.as_deref(),
        Some(release_bytes.as_slice())
    );
}

#[test]
fn audit_failures_stop_at_each_real_boundary_and_release_the_session() {
    for kind in [
        "standalone_object_reserved",
        "governance_opened_and_verified",
        "turn_begin_authorized",
        "governance_context_bound",
        "sections_selected",
        "output_emitted_and_read_back",
        "standalone_use_completed",
    ] {
        let fixture = Fixture::new();
        let request = fixture.request_with(kind);
        let audit = Arc::new(RecordingAudit::failing_once(kind));
        let trace = Arc::new(RecordingTrace::passing());
        let (keys, runtime) = runtime_with_sinks(fixture, Arc::clone(&audit), trace);

        if matches!(
            kind,
            "standalone_object_reserved" | "governance_opened_and_verified"
        ) {
            let error = runtime.start_session(&request).unwrap_err();
            assert_eq!(error.code(), "tn_audit_append_failed", "{kind}");
            runtime.start_session(&request).unwrap();
            continue;
        }

        let mut harness = SessionHarness::with_runtime(keys, runtime.clone(), request);
        let error = match kind {
            "turn_begin_authorized" | "governance_context_bound" => {
                let turn = harness.session.next_model_turn().unwrap();
                let manifest = literal_runnable_manifest(2048);
                turn.permit
                    .prepare(&turn.request_json, b"prompt", &manifest)
                    .unwrap();
                turn.permit
                    .begin(91, 0, &turn.request_json, b"prompt", &manifest)
                    .unwrap_err()
            }
            "sections_selected" => {
                let turn = harness.session.next_model_turn().unwrap();
                prepare_and_begin(&turn, b"decrypt", 2048, 94);
                let result = harness.decrypt_result(&turn, &["finance"]);
                harness
                    .session
                    .accept_model_action(turn.permit, result.native())
                    .unwrap_err()
            }
            "output_emitted_and_read_back" | "standalone_use_completed" => {
                let turn = advance_to_emit(&mut harness, 94);
                prepare_and_begin(&turn, b"report", 2048, 95);
                let result = harness.action_result(
                    "emit-audit-failure",
                    "emit_governed_record",
                    report_proposal(),
                );
                harness
                    .session
                    .accept_model_action(turn.permit, result.native())
                    .unwrap_err()
            }
            _ => unreachable!(),
        };

        assert_eq!(error.code(), "tn_audit_append_failed", "{kind}");
        assert_eq!(harness.session.state(), State::Failed, "{kind}");
        runtime.start_session(&harness.raw_request).unwrap();
        assert_eq!(audit.failed_appends(), 1, "{kind}");
    }
}

#[test]
fn sensitive_trace_failures_stop_prepare_begin_and_model_result_boundaries() {
    let cases = [
        (SensitiveTraceKind::TurnPrepared, None),
        (SensitiveTraceKind::TurnStarted, None),
        (
            SensitiveTraceKind::ModelResult,
            Some(tn_runtime::Phase::SectionSelection),
        ),
        (
            SensitiveTraceKind::ModelResult,
            Some(tn_runtime::Phase::GovernedAction),
        ),
    ];

    for (index, (kind, phase)) in cases.into_iter().enumerate() {
        let fixture = Fixture::new();
        let request = fixture.request_with(&format!("trace failure {index}"));
        let audit = Arc::new(RecordingAudit::passing());
        let trace = Arc::new(RecordingTrace::failing_once(kind, phase));
        let (keys, runtime) = runtime_with_sinks(fixture, audit, Arc::clone(&trace));
        let mut harness = SessionHarness::with_runtime(keys, runtime.clone(), request);

        let error = match (kind, phase) {
            (SensitiveTraceKind::TurnPrepared, _) => {
                let turn = harness.session.next_model_turn().unwrap();
                turn.permit
                    .prepare(
                        &turn.request_json,
                        b"prompt",
                        &literal_runnable_manifest(2048),
                    )
                    .unwrap_err()
            }
            (SensitiveTraceKind::TurnStarted, _) => {
                let turn = harness.session.next_model_turn().unwrap();
                let manifest = literal_runnable_manifest(2048);
                turn.permit
                    .prepare(&turn.request_json, b"prompt", &manifest)
                    .unwrap();
                turn.permit
                    .begin(96, 0, &turn.request_json, b"prompt", &manifest)
                    .unwrap_err()
            }
            (SensitiveTraceKind::ModelResult, Some(tn_runtime::Phase::SectionSelection)) => {
                let turn = harness.session.next_model_turn().unwrap();
                prepare_and_begin(&turn, b"decrypt", 2048, 97);
                let result = harness.decrypt_result(&turn, &["finance"]);
                harness
                    .session
                    .accept_model_action(turn.permit, result.native())
                    .unwrap_err()
            }
            (SensitiveTraceKind::ModelResult, Some(tn_runtime::Phase::GovernedAction)) => {
                let turn = advance_to_emit(&mut harness, 98);
                prepare_and_begin(&turn, b"report", 2048, 99);
                let result = harness.action_result(
                    "emit-trace-failure",
                    "emit_governed_record",
                    report_proposal(),
                );
                harness
                    .session
                    .accept_model_action(turn.permit, result.native())
                    .unwrap_err()
            }
            _ => unreachable!(),
        };

        assert_eq!(error.code(), "tn_sensitive_trace_append_failed");
        assert_eq!(harness.session.state(), State::Failed);
        runtime.start_session(&harness.raw_request).unwrap();
        assert_eq!(trace.failed_appends(), 1);
    }
}

/// Decrypt the finance group and return the report turn that follows.
fn advance_to_emit(harness: &mut SessionHarness, task_id: i64) -> ModelTurn {
    let selection = harness.session.next_model_turn().unwrap();
    prepare_and_begin(&selection, b"rendered-decrypt", 2048, task_id);
    let result = harness.decrypt_result(&selection, &["finance"]);
    let outcome = harness
        .session
        .accept_model_action(selection.permit, result.native())
        .unwrap();
    assert!(matches!(outcome, ActionOutcome::Continue));
    harness.session.next_model_turn().unwrap()
}

fn complete_report(harness: &mut SessionHarness, task_id: i64) -> GovernedReportRelease {
    let emission = advance_to_emit(harness, task_id);
    prepare_and_begin(&emission, b"rendered-report", 2048, task_id + 1);
    let result = harness.action_result("emit-report", "emit_governed_record", report_proposal());
    let ActionOutcome::GovernedRelease(release) = harness
        .session
        .accept_model_action(emission.permit, result.native())
        .unwrap()
    else {
        panic!("the report did not produce a closed release");
    };
    release
}

fn report_proposal() -> Value {
    json!({"report_html": "<div><p>Maximum drawdown report.</p></div>"})
}

fn runtime_with_sinks(
    fixture: Fixture,
    audit: Arc<RecordingAudit>,
    trace: Arc<RecordingTrace>,
) -> (tn_test_tools::RealTnFixture, GovernedRuntime) {
    let Fixture { legacy, config, .. } = fixture;
    let runtime = GovernedRuntime::from_config_with_sink_factories(
        config,
        move |_| {
            let sink: Arc<dyn DecisionAudit> = audit.clone();
            Ok::<Arc<dyn DecisionAudit>, io::Error>(sink)
        },
        move |_| {
            let sink: Arc<dyn SensitiveTraceSink> = trace.clone();
            Ok::<Arc<dyn SensitiveTraceSink>, io::Error>(sink)
        },
    )
    .unwrap();
    (legacy, runtime)
}

struct RecordingAudit {
    events: Mutex<Vec<AuditEvent>>,
    fail_kind: Option<&'static str>,
    failures_remaining: AtomicUsize,
    failed_appends: AtomicUsize,
}

impl RecordingAudit {
    fn passing() -> Self {
        Self {
            events: Mutex::new(Vec::new()),
            fail_kind: None,
            failures_remaining: AtomicUsize::new(0),
            failed_appends: AtomicUsize::new(0),
        }
    }

    fn failing_once(kind: &'static str) -> Self {
        Self {
            events: Mutex::new(Vec::new()),
            fail_kind: Some(kind),
            failures_remaining: AtomicUsize::new(1),
            failed_appends: AtomicUsize::new(0),
        }
    }

    fn failed_appends(&self) -> usize {
        self.failed_appends.load(Ordering::SeqCst)
    }
}

impl DecisionAudit for RecordingAudit {
    fn append(&self, event: AuditEvent) -> io::Result<AuditRecord> {
        if self.fail_kind == Some(event.kind.as_str())
            && self
                .failures_remaining
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                    remaining.checked_sub(1)
                })
                .is_ok()
        {
            self.failed_appends.fetch_add(1, Ordering::SeqCst);
            return Err(io::Error::other("injected audit failure"));
        }
        self.events.lock().unwrap().push(event);
        Ok(AuditRecord {
            prev_hash: "sha256:test-prev".to_string(),
            row_hash: "sha256:test-row".to_string(),
        })
    }
}

struct RecordingTrace {
    events: Mutex<Vec<TraceSnapshot>>,
    fail_kind: Option<SensitiveTraceKind>,
    fail_phase: Option<tn_runtime::Phase>,
    failures_remaining: AtomicUsize,
    failed_appends: AtomicUsize,
}

impl RecordingTrace {
    fn passing() -> Self {
        Self {
            events: Mutex::new(Vec::new()),
            fail_kind: None,
            fail_phase: None,
            failures_remaining: AtomicUsize::new(0),
            failed_appends: AtomicUsize::new(0),
        }
    }

    fn failing_once(kind: SensitiveTraceKind, phase: Option<tn_runtime::Phase>) -> Self {
        Self {
            events: Mutex::new(Vec::new()),
            fail_kind: Some(kind),
            fail_phase: phase,
            failures_remaining: AtomicUsize::new(1),
            failed_appends: AtomicUsize::new(0),
        }
    }

    fn failed_appends(&self) -> usize {
        self.failed_appends.load(Ordering::SeqCst)
    }
}

impl SensitiveTraceSink for RecordingTrace {
    fn append(&self, event: SensitiveTraceEvent<'_>) -> io::Result<()> {
        let phase_matches = self.fail_phase.is_none() || self.fail_phase == event.phase;
        if self.fail_kind == Some(event.kind)
            && phase_matches
            && self
                .failures_remaining
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                    remaining.checked_sub(1)
                })
                .is_ok()
        {
            self.failed_appends.fetch_add(1, Ordering::SeqCst);
            return Err(io::Error::other("injected trace failure"));
        }
        self.events.lock().unwrap().push(TraceSnapshot {
            kind: event.kind,
            task_id: event.task_id,
            slot_id: event.slot_id,
            request_json: event.request_json.map(<[u8]>::to_vec),
            rendered_prompt: event.rendered_prompt.map(<[u8]>::to_vec),
            runnable_manifest: event.runnable_manifest.map(<[u8]>::to_vec),
            parsed_content: event.parsed_content.map(<[u8]>::to_vec),
        });
        Ok(())
    }
}

struct TraceSnapshot {
    kind: SensitiveTraceKind,
    task_id: Option<i64>,
    slot_id: Option<i32>,
    request_json: Option<Vec<u8>>,
    rendered_prompt: Option<Vec<u8>>,
    runnable_manifest: Option<Vec<u8>>,
    parsed_content: Option<Vec<u8>>,
}

fn domain_digest(domain: &[u8], bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(bytes);
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

fn manifest_with(base: &[u8], path: &[&str], replacement: Value) -> Vec<u8> {
    let mut manifest: Value = serde_json::from_slice(base).unwrap();
    let (field, parents) = path.split_last().unwrap();
    let mut parent = &mut manifest;
    for segment in parents {
        parent = &mut parent[*segment];
    }
    parent[*field] = replacement;
    canonical_json(&manifest)
}
