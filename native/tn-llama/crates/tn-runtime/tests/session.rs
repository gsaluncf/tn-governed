mod support;
use serde_json::{json, Value};
use support::{canonical_json, literal_runnable_manifest, prepare_and_begin, SessionHarness};
use tn_runtime::{NativeToolResult, State};

#[test]
fn turn_one_requires_one_complete_exact_bound_native_call() {
    enum Mutation {
        EmptyId,
        InvalidId,
        WrongName,
        Malformed,
        Duplicate,
        Extra,
        UnknownSection,
        EmptySelection,
        Truncated,
        StopLimit,
    }
    let cases = [
        ("empty id", Mutation::EmptyId, "tn_tool_call_id_invalid"),
        ("invalid id", Mutation::InvalidId, "tn_tool_call_id_invalid"),
        ("wrong name", Mutation::WrongName, "tn_action_not_allowed"),
        (
            "malformed",
            Mutation::Malformed,
            "tn_tool_arguments_invalid",
        ),
        (
            "duplicate",
            Mutation::Duplicate,
            "tn_tool_arguments_invalid",
        ),
        ("extra", Mutation::Extra, "tn_section_selection_invalid"),
        (
            "unknown section",
            Mutation::UnknownSection,
            "tn_section_selection_invalid",
        ),
        (
            "empty selection",
            Mutation::EmptySelection,
            "tn_section_selection_invalid",
        ),
        ("truncated", Mutation::Truncated, "tn_model_turn_incomplete"),
        (
            "stop limit",
            Mutation::StopLimit,
            "tn_model_turn_incomplete",
        ),
    ];

    for (name, mutation, code) in cases {
        let mut harness = SessionHarness::new(name);
        let turn = harness.session.next_model_turn().unwrap();
        prepare_and_begin(&turn, b"turn-one", 2048, 21);
        let mut result = harness.section_selection_result(&["firm_data"]);
        match mutation {
            Mutation::EmptyId => result.id.clear(),
            Mutation::InvalidId => result.id = vec![0xff],
            Mutation::WrongName => result.name = b"continue_with_governance".to_vec(),
            Mutation::Malformed => result.arguments = b"{".to_vec(),
            Mutation::Duplicate => {
                result.arguments = format!(
                    r#"{{"request_digest":"{}","row_hash":"{}","row_hash":"{}"}}"#,
                    harness.request_digest, harness.row_hash, harness.row_hash
                )
                .into_bytes();
            }
            Mutation::Extra => {
                let mut value: Value = serde_json::from_slice(&result.arguments).unwrap();
                value["extra"] = json!(true);
                result.arguments = canonical_json(&value);
            }
            Mutation::UnknownSection => {
                let mut value: Value = serde_json::from_slice(&result.arguments).unwrap();
                value["sections"] = json!(["unknown"]);
                result.arguments = canonical_json(&value);
            }
            Mutation::EmptySelection => {
                let mut value: Value = serde_json::from_slice(&result.arguments).unwrap();
                value["sections"] = json!([]);
                result.arguments = canonical_json(&value);
            }
            Mutation::Truncated => result.truncated = true,
            Mutation::StopLimit => result.stop_limit = true,
        }

        let error = harness
            .session
            .accept_model_action(turn.permit, result.native())
            .unwrap_err();

        assert_eq!(error.code(), code, "{name}");
        assert_eq!(harness.session.state(), State::Failed, "{name}");
        assert!(harness.session.next_model_turn().is_err(), "{name}");
    }
}

#[test]
fn permits_cannot_cross_sessions_or_accept_before_begin_or_survive_abort() {
    let mut before_begin = SessionHarness::new("before begin");
    let turn = before_begin.session.next_model_turn().unwrap();
    let result = before_begin.section_selection_result(&["firm_data"]);
    let error = before_begin
        .session
        .accept_model_action(turn.permit, result.native())
        .unwrap_err();
    assert_eq!(error.code(), "tn_turn_not_begun");

    let mut origin = SessionHarness::new("origin session");
    let mut target = SessionHarness::new("target session");
    let origin_turn = origin.session.next_model_turn().unwrap();
    prepare_and_begin(&origin_turn, b"origin", 2048, 83);
    let _target_turn = target.session.next_model_turn().unwrap();
    let result = target.section_selection_result(&["firm_data"]);
    let error = target
        .session
        .accept_model_action(origin_turn.permit, result.native())
        .unwrap_err();
    assert_eq!(error.code(), "tn_turn_session_mismatch");
    assert_eq!(target.session.state(), State::Failed);

    let mut aborted = SessionHarness::new("aborted permit");
    let turn = aborted.session.next_model_turn().unwrap();
    aborted.session.abort().unwrap();
    let manifest = literal_runnable_manifest(2048);
    let error = turn
        .permit
        .prepare(&turn.request_json, b"prompt", &manifest)
        .unwrap_err();
    assert_eq!(error.code(), "tn_turn_consumed");
}

#[test]
fn permit_order_reuse_and_task_binding_fail_closed() {
    struct Case {
        name: &'static str,
        run: fn(&mut SessionHarness) -> &'static str,
        code: &'static str,
    }

    fn begin_before_prepare(harness: &mut SessionHarness) -> &'static str {
        let turn = harness.session.next_model_turn().unwrap();
        let manifest = literal_runnable_manifest(2048);
        turn.permit
            .begin(1, 0, &turn.request_json, b"prompt", &manifest)
            .unwrap_err()
            .code()
    }

    fn prepare_twice(harness: &mut SessionHarness) -> &'static str {
        let turn = harness.session.next_model_turn().unwrap();
        let manifest = literal_runnable_manifest(2048);
        turn.permit
            .prepare(&turn.request_json, b"prompt", &manifest)
            .unwrap();
        turn.permit
            .prepare(&turn.request_json, b"prompt", &manifest)
            .unwrap_err()
            .code()
    }

    fn begin_twice(harness: &mut SessionHarness) -> &'static str {
        let turn = harness.session.next_model_turn().unwrap();
        let manifest = literal_runnable_manifest(2048);
        turn.permit
            .prepare(&turn.request_json, b"prompt", &manifest)
            .unwrap();
        turn.permit
            .begin(1, 0, &turn.request_json, b"prompt", &manifest)
            .unwrap();
        turn.permit
            .begin(1, 0, &turn.request_json, b"prompt", &manifest)
            .unwrap_err()
            .code()
    }

    fn changed_body(harness: &mut SessionHarness) -> &'static str {
        let turn = harness.session.next_model_turn().unwrap();
        let manifest = literal_runnable_manifest(2048);
        let mut body = turn.request_json.clone();
        body.push(b' ');
        turn.permit
            .prepare(&body, b"prompt", &manifest)
            .unwrap_err()
            .code()
    }

    fn changed_prompt_at_begin(harness: &mut SessionHarness) -> &'static str {
        let turn = harness.session.next_model_turn().unwrap();
        let manifest = literal_runnable_manifest(2048);
        turn.permit
            .prepare(&turn.request_json, b"prompt", &manifest)
            .unwrap();
        turn.permit
            .begin(1, 0, &turn.request_json, b"changed", &manifest)
            .unwrap_err()
            .code()
    }

    fn changed_manifest_at_begin(harness: &mut SessionHarness) -> &'static str {
        let turn = harness.session.next_model_turn().unwrap();
        let manifest = literal_runnable_manifest(2048);
        let mut changed_value: Value = serde_json::from_slice(&manifest).unwrap();
        changed_value["task"]["tokens"][0] = json!(99);
        let changed = canonical_json(&changed_value);
        turn.permit
            .prepare(&turn.request_json, b"prompt", &manifest)
            .unwrap();
        turn.permit
            .begin(1, 0, &turn.request_json, b"prompt", &changed)
            .unwrap_err()
            .code()
    }

    for case in [
        Case {
            name: "begin before prepare",
            run: begin_before_prepare,
            code: "tn_turn_not_prepared",
        },
        Case {
            name: "prepare twice",
            run: prepare_twice,
            code: "tn_turn_already_prepared",
        },
        Case {
            name: "begin twice",
            run: begin_twice,
            code: "tn_turn_already_begun",
        },
        Case {
            name: "changed body",
            run: changed_body,
            code: "tn_turn_binding_mismatch",
        },
        Case {
            name: "changed prompt at begin",
            run: changed_prompt_at_begin,
            code: "tn_turn_binding_mismatch",
        },
        Case {
            name: "changed manifest at begin",
            run: changed_manifest_at_begin,
            code: "tn_turn_binding_mismatch",
        },
    ] {
        let mut harness = SessionHarness::new(case.name);
        assert_eq!((case.run)(&mut harness), case.code, "{}", case.name);
        assert_eq!(harness.session.state(), State::Failed, "{}", case.name);
        assert!(harness.session.next_model_turn().is_err(), "{}", case.name);
    }
}

#[test]
fn zero_or_two_native_calls_never_open_business_values_or_advance() {
    for call_count in [0, 2] {
        let mut harness = SessionHarness::new("call count test");
        let turn = harness.session.next_model_turn().unwrap();
        let manifest = literal_runnable_manifest(2048);
        turn.permit
            .prepare(&turn.request_json, b"prompt", &manifest)
            .unwrap();
        turn.permit
            .begin(1, 0, &turn.request_json, b"prompt", &manifest)
            .unwrap();
        let result = NativeToolResult {
            call_count,
            call: None,
            content: b"",
            raw_model_output: b"native result",
            truncated: false,
            stop_limit: false,
        };

        let error = harness
            .session
            .accept_model_action(turn.permit, result)
            .unwrap_err();

        assert_eq!(error.code(), "tn_tool_call_count");
        assert_eq!(harness.session.state(), State::Failed);
        assert!(harness.session.next_model_turn().is_err());
    }
}
