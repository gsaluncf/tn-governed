mod governed_support;
mod support;

use governed_support::SessionHarness;
use serde_json::{json, Value};
use support::prepare_and_begin;
use tn_runtime::State;

const USER_REQUEST: &str = "Explain the maximum drawdown.";

/// Decrypt the finance group and return the report turn that follows.
fn report_turn(harness: &mut SessionHarness, task_id: i64) -> tn_runtime::ModelTurn {
    let selection = harness.session.next_model_turn().unwrap();
    prepare_and_begin(&selection, b"rendered-decrypt", 2048, task_id);
    let result = harness.decrypt_result(&selection, &["finance"]);
    harness
        .session
        .accept_model_action(selection.permit, result.native())
        .unwrap();
    harness.session.next_model_turn().unwrap()
}

#[test]
fn emission_tool_schema_requests_business_content_only() {
    let mut harness = SessionHarness::new(USER_REQUEST);
    let turn = report_turn(&mut harness, 31);
    let body: Value = serde_json::from_slice(&turn.request_json).unwrap();
    assert_eq!(
        body["tools"][0]["function"]["parameters"],
        json!({"type":"object", "properties":{"report_html":{"type":"string","minLength":1}}, "required":["report_html"], "additionalProperties":false})
    );
    let description = body["tools"][0]["function"]["description"]
        .as_str()
        .unwrap();
    assert!(
        description.contains("no attributes, styles, or scripts"),
        "{description}"
    );
}

#[test]
fn wrong_action_is_terminal_in_every_state() {
    for state in ["section_selection", "governed_action"] {
        let mut harness = SessionHarness::new(USER_REQUEST);
        let turn = match state {
            "section_selection" => harness.session.next_model_turn().unwrap(),
            "governed_action" => report_turn(&mut harness, 32),
            _ => unreachable!(),
        };
        prepare_and_begin(&turn, b"rendered-wrong-action", 2048, 33);
        let result = harness.action_result("wrong-call", "unregistered_action", json!({}));

        let error = harness
            .session
            .accept_model_action(turn.permit, result.native())
            .unwrap_err();

        assert_eq!(error.code(), "tn_action_not_allowed", "{state}");
        assert_eq!(harness.session.state(), State::Failed, "{state}");
    }
}

#[test]
fn incomplete_multiple_call_and_prose_action_results_fail_terminally() {
    for (name, expected_code) in [
        ("incomplete", "tn_model_turn_incomplete"),
        ("multiple", "tn_tool_call_count"),
        ("prose", "tn_model_prose_not_allowed"),
    ] {
        let mut harness = SessionHarness::new(USER_REQUEST);
        let turn = harness.session.next_model_turn().unwrap();
        prepare_and_begin(&turn, b"rendered-invalid-native-result", 2048, 34);
        let mut result = harness.decrypt_result(&turn, &["finance"]);
        match name {
            "incomplete" => result.stop_limit = true,
            "multiple" => result.call_count = 2,
            "prose" => result.content = b"extra prose".to_vec(),
            _ => unreachable!(),
        }

        let error = harness
            .session
            .accept_model_action(turn.permit, result.native())
            .unwrap_err();

        assert_eq!(error.code(), expected_code, "{name}");
        assert_eq!(harness.session.state(), State::Failed, "{name}");
    }
}

#[test]
fn markup_outside_the_profile_is_refused_before_any_release() {
    for html in [
        "<div><p>Report</p><script>hidden</script></div>",
        "<p style=\"font-size:0\">Report</p>",
        "<article><p>Report</p></article>",
    ] {
        let mut harness = SessionHarness::new(USER_REQUEST);
        let turn = report_turn(&mut harness, 35);
        prepare_and_begin(&turn, b"rendered-markup", 2048, 36);
        let result = harness.action_result(
            "emit-markup",
            "emit_governed_record",
            json!({"report_html": html}),
        );

        let error = harness
            .session
            .accept_model_action(turn.permit, result.native())
            .unwrap_err();

        assert_eq!(error.code(), "tn_report_markup_invalid", "{html}");
        assert_eq!(harness.session.state(), State::Failed, "{html}");
    }
}
