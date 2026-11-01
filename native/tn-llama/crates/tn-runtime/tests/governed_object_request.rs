use serde_json::{json, Value};
use tn_runtime::{
    parse_and_verify_request, parse_governed_object_request, GovernedInputConfig, RequestLimits,
};

fn fixture() -> (Value, GovernedInputConfig, RequestLimits) {
    let manifest: Value =
        serde_json::from_str(include_str!("fixtures/governed/manifest.json")).unwrap();
    let config = serde_json::from_value(json!({
        "native_reader_config_path":"unused", "metadata_store_path":"unused",
        "use_context":manifest["uses"]["model"], "destinations":["internal-client"],
        "trusted_writers":[manifest["writer"]], "authority_writers":[manifest["writer"]], "contracts":[]
    })).unwrap();
    let mut limits = RequestLimits::test();
    limits.expected_event_type = "calculation.result".into();
    limits.allowed_input_groups = ["finance".into(), "audit".into()].into();
    let request = json!({"protocol":"tn.llama.request.v2", "tn_object":manifest["publications"]["calculation"]["wire"],
        "use":manifest["uses"]["model"],"destination":"internal-client","messages":[{"role":"user","content":"Explain the result."}],"stream":false});
    (request, config, limits)
}

#[test]
fn exact_wire_and_native_identity_survive_transport() {
    let (request, config, limits) = fixture();
    let accepted =
        parse_governed_object_request(&serde_json::to_vec(&request).unwrap(), &limits, &config)
            .unwrap();
    assert_eq!(
        accepted.object.wire(),
        request["tn_object"].as_str().unwrap()
    );
    let manifest: Value =
        serde_json::from_str(include_str!("fixtures/governed/manifest.json")).unwrap();
    assert_eq!(
        accepted.object.id(),
        manifest["publications"]["calculation"]["object_id"]
            .as_str()
            .unwrap()
    );
    assert!(parse_and_verify_request(&serde_json::to_vec(&request).unwrap(), &limits).is_err());
}

#[test]
fn closed_profile_refuses_use_changes_types_and_tampering() {
    let (request, config, limits) = fixture();
    for (pointer, value) in [
        ("/use/application", json!("claimed-app")),
        ("/use/purpose", json!("advertising")),
        ("/use/operation", json!("redistribute")),
        ("/destination", json!("public")),
        ("/stream", json!(true)),
        ("/protocol", json!("tn.llama.request.v1")),
        ("/tn_object", json!({})),
        ("/messages/0/role", json!("system")),
    ] {
        let mut bad = request.clone();
        *bad.pointer_mut(pointer).unwrap() = value;
        assert!(
            parse_governed_object_request(&serde_json::to_vec(&bad).unwrap(), &limits, &config)
                .is_err(),
            "{pointer}"
        );
    }
    let mut extra = request.clone();
    extra["temperature"] = json!(1);
    assert!(
        parse_governed_object_request(&serde_json::to_vec(&extra).unwrap(), &limits, &config)
            .is_err()
    );
    let raw = serde_json::to_string(&request).unwrap();
    let duplicate = format!("{{\"stream\":false,{}", &raw[1..]);
    assert!(parse_governed_object_request(duplicate.as_bytes(), &limits, &config).is_err());
    let mut changed = request.clone();
    let mut object: Value = serde_json::from_str(changed["tn_object"].as_str().unwrap()).unwrap();
    object["event_type"] = json!("calculation.forged");
    changed["tn_object"] = json!(object.to_string());
    assert!(parse_governed_object_request(
        &serde_json::to_vec(&changed).unwrap(),
        &limits,
        &config
    )
    .is_err());
}

#[test]
fn lineage_bounds_default_and_validate_independently() {
    let (_, config, _) = fixture();
    assert_eq!(config.lineage_max_objects, 1024);
    assert_eq!(config.lineage_max_depth, 64);
    let manifest: Value =
        serde_json::from_str(include_str!("fixtures/governed/manifest.json")).unwrap();
    let mut profile = json!({
        "native_reader_config_path":"unused", "metadata_store_path":"unused",
        "use_context":manifest["uses"]["model"], "destinations":["internal-client"],
        "trusted_writers":[manifest["writer"]], "authority_writers":[manifest["writer"]],
        "contracts":[], "lineage_max_objects":65536, "lineage_max_depth":256
    });
    let expanded: GovernedInputConfig = serde_json::from_value(profile.clone()).unwrap();
    assert!(expanded.lineage_verifier().is_ok());
    for (field, value) in [
        ("lineage_max_objects", 0),
        ("lineage_max_objects", 65537),
        ("lineage_max_depth", 0),
        ("lineage_max_depth", 257),
    ] {
        let original = profile[field].clone();
        profile[field] = json!(value);
        assert!(serde_json::from_value::<GovernedInputConfig>(profile.clone()).is_err());
        profile[field] = original;
    }
}

#[test]
fn configured_lineage_verifies_more_than_a_thousand_exact_parents() {
    use std::collections::BTreeMap;
    use tn_core::governed::{DatasetCatalog, PolicyDag};
    use tn_core::runtime::Objects;

    let text = "## finance.input\n### instruction\nCalculate the aggregate.\n### use_for\nResearch.\n### do_not_use_for\nPublic disclosure.\n### consequences\nReview.\n### on_violation_or_error\nRefuse.\n";
    let objects = Objects::ephemeral(text, "policy.md", &["finance"]).unwrap();
    let policy = objects.draft("finance.input").unwrap().governance().clone();
    let mut aggregate = None;
    let mut parents = BTreeMap::new();
    for index in 0..1024 {
        let data = objects
            .create_obj(
                "finance.input",
                policy.clone(),
                "finance",
                json!({"value": index}),
            )
            .unwrap();
        let publication = data.snapshot().unwrap().clone();
        parents.insert(publication.id().to_owned(), publication);
        if let Some(combined) = aggregate.as_mut() {
            tn_core::governed::DataObject::include(combined, &data).unwrap();
        } else {
            aggregate = Some(data);
        }
    }
    let output = objects
        .release(
            &mut aggregate.unwrap(),
            "finance.result",
            "research",
            "recipient",
            |_| Ok(true),
        )
        .unwrap();
    let reader = objects.reader().unwrap();
    let view = reader.governance(&output).unwrap();
    let (_, mut profile, _) = fixture();
    let catalog = DatasetCatalog::new();
    let dag = PolicyDag::new();
    assert!(profile
        .lineage_verifier()
        .unwrap()
        .verify(&view, &catalog, &dag, |id| reader.governance(&parents[id]))
        .is_err());
    profile.lineage_max_objects = 4096;
    let verified = profile
        .lineage_verifier()
        .unwrap()
        .verify(&view, &catalog, &dag, |id| reader.governance(&parents[id]))
        .unwrap();
    assert_eq!(verified.object_ids().len(), 1025);
}
