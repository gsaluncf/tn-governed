"""Governed Polars plans preserve native authority across general computation."""

import polars as pl
import pytest
import tn
from test_publications import POLICY
from tn_polars import Decision

USE = tn.UseContext("analytics", "portfolio_analysis", "compute")


@pytest.fixture
def relation():
    with tn.Session(POLICY, groups=["finance", "evidence"]) as session:
        policy = session.policy("portfolio.feed.data.v1")
        data = session.create(
            {
                "rows": [
                    {"id": 1, "group": "a", "amount": 2.0},
                    {"id": 2, "group": "a", "amount": 4.0},
                    {"id": 3, "group": "b", "amount": 7.0},
                ]
            },
            policy,
            object_type="portfolio.feed.data.v1",
            group="finance",
        )
        source = data.release(use=USE, to="analytics", decide=lambda _: True)
        yield session, policy, source


def admit(relation, callback=None):
    from tn_polars import EndpointEvaluator, load_relation
    from tn_polars.authority import policy_identity

    session, policy, source = relation
    evaluator = EndpointEvaluator(
        "organization:analytics",
        "purpose-policy",
        "1",
        {"purpose": "portfolio_analysis"},
        callback
        or (lambda request: Decision(True, "approved", "decision:" + request["operation"])),
    )
    return load_relation(
        source,
        session=session,
        use=USE,
        evaluators={policy_identity(policy): evaluator},
        decide=lambda _: True,
    )


def opened(session, publication):
    from tn_polars import open_audited_frame

    audit = open_audited_frame(publication, session=session, use=USE, decide=lambda _: True)
    data = session.receive(publication, use=USE, groups=["finance"], decide=lambda _: True)
    return data.get("rows", group="finance"), audit


def test_arbitrary_lazy_plan_keeps_control_dependencies_and_governance(relation):
    from tn_polars import PlanTransform

    frame = admit(relation)
    transformed = frame.transform(
        PlanTransform(
            "deduplicate-normalize",
            "1",
            lambda source: (
                source.unique(subset="group", keep="first", maintain_order=True)
                .with_columns((pl.col("amount").log() + 1).alias("score"))
                .select("group", "score")
            ),
        )
    )
    publication = transformed.release_tn(use=USE, to="internal", decide=lambda _: True)
    rows, audit = opened(relation[0], publication)
    assert [row["group"] for row in rows] == ["a", "b"]
    assert audit["support"]["known"] is False
    assert audit["output"]["row_selection_sources"]
    assert {item["policy_revision"] for item in audit["policies"]} == set(
        frame._tn.policies.revision_ids
    )
    operation = next(
        event
        for event in audit["events"]
        if event["kind"] == "operation" and event["details"]["name"] == "transform"
    )
    assert operation["details"]["parameters"]["identifier"] == "deduplicate-normalize"
    assert operation["details"]["parameters"]["plan_digest"].startswith("sha256:")


def test_transform_authorization_precedes_callback_and_unknown_support_can_be_refused(relation):
    from tn_polars import PlanTransform, PolicyDenied

    calls = []
    frame = admit(
        relation, lambda request: Decision(request["operation"] != "transform", "blocked", "d")
    )
    with pytest.raises(PolicyDenied):
        frame.transform(PlanTransform("opaque", "1", lambda source: calls.append(True) or source))
    assert calls == []
    frame = admit(
        relation,
        lambda request: Decision(
            request["operation"] != "release" or request["aggregate_support"]["known"],
            "precision",
            "d",
        ),
    )
    transformed = frame.transform(PlanTransform("opaque", "1", lambda source: source))
    with pytest.raises(PolicyDenied):
        transformed.release_tn(use=USE, to="internal", decide=lambda _: True)


def test_expression_selectors_and_window_plans_preserve_source_columns(relation):
    frame = admit(relation)
    selected = frame.with_columns(pl.col("amount").mean().over("group").alias("mean")).select(
        pl.all()
    )
    rows, audit = opened(
        relation[0], selected.release_tn(use=USE, to="internal", decide=lambda _: True)
    )
    assert [row["mean"] for row in rows] == [3.0, 3.0, 7.0]
    assert set(audit["output"]["columns"]) == {"id", "group", "amount", "mean"}
    assert audit["output"]["columns"]["mean"]
    assert audit["support"]["known"] is True
    source_id = relation[2].id
    assert audit["support"]["rows"][0][source_id] == [source_id + "::0", source_id + "::1"]
    assert audit["support"]["rows"][2][source_id] == [source_id + "::2"]


def test_two_input_transform_keeps_both_source_policies():
    from tn_polars import PlanTransform

    text = POLICY + POLICY[POLICY.index("## ") :].replace(
        "portfolio.feed.data.v1", "portfolio.reference.data"
    )
    with tn.Session(text, groups=["finance"]) as session:
        frames = []
        for name, amount in (("portfolio.feed.data.v1", 3), ("portfolio.reference.data", 7)):
            policy = session.policy(name)
            data = session.create(
                {"rows": [{"amount": amount}]}, policy, object_type=name, group="finance"
            )
            source = data.release(use=USE, to="analytics", decide=lambda _: True)
            frames.append(admit((session, policy, source)))
        result = frames[0].transform(
            PlanTransform("vertical-union", "1", lambda a, b: pl.concat([a, b])), frames[1]
        )
        rows, audit = opened(
            session, result.release_tn(use=USE, to="internal", decide=lambda _: True)
        )
        assert [row["amount"] for row in rows] == [3, 7]
        assert len(audit["policies"]) == 2
        assert len(audit["inputs"]) == 2
        assert len(frames[0]._tn.policies.audit.records()) < len(
            result._tn.policies.audit.records()
        )


def test_same_contract_can_cover_different_source_schemas(relation):
    session, policy, _ = relation
    data = session.create(
        {"rows": [{"id": 1, "label": "a"}, {"id": 3, "label": "b"}]},
        policy,
        object_type="portfolio.feed.data.v1",
        group="finance",
    )
    source = data.release(use=USE, to="analytics", decide=lambda _: True)
    result = admit(relation).join(admit((session, policy, source)), on="id")
    rows, audit = opened(session, result.release_tn(use=USE, to="internal", decide=lambda _: True))
    assert [row["label"] for row in rows] == ["a", "b"]
    assert len(audit["policies"]) == 1
    assert len(audit["inputs"]) == 2
    assert all(len(row) == 2 for row in audit["support"]["rows"])


def test_native_frame_rejects_plain_collection_and_plain_transform_result(relation):
    from tn_polars import PlanTransform, PolicyDenied

    frame = admit(relation)
    with pytest.raises(PolicyDenied):
        frame.collect()
    with pytest.raises(TypeError, match="LazyFrame"):
        frame.transform(PlanTransform("invalid", "1", lambda _: pl.DataFrame({"x": [1]})))


def test_struct_unnest_explode_and_unique_retain_contributor_rows(relation):
    session, policy, _ = relation
    data = session.create(
        {
            "rows": [
                {"key": "a", "values": [2, 4], "details": {"label": "first", "weight": 3}},
                {"key": "a", "values": [4], "details": {"label": "second", "weight": 5}},
                {"key": "b", "values": [8], "details": {"label": "third", "weight": 7}},
            ]
        },
        policy,
        object_type="portfolio.feed.data.v1",
        group="finance",
    )
    source = data.release(use=USE, to="analytics", decide=lambda _: True)
    frame = admit((session, policy, source)).unnest("details").explode("values")
    rows, audit = opened(session, frame.release_tn(use=USE, to="internal", decide=lambda _: True))
    assert [row["values"] for row in rows] == [2, 4, 4, 8]
    assert audit["output"]["columns"]["weight"] == [source.id + "::details"]
    assert audit["output"]["row_selection_sources"] == [source.id + "::values"]
    assert audit["support"]["rows"][1] == {source.id: [source.id + "::0"]}
    unique = frame.unique(subset=["key", "values"], keep="first", maintain_order=True)
    rows, audit = opened(session, unique.release_tn(use=USE, to="internal", decide=lambda _: True))
    assert [row["values"] for row in rows] == [2, 4, 8]
    assert audit["support"]["known"] is True
    assert audit["support"]["rows"][1] == {source.id: [source.id + "::0", source.id + "::1"]}
    assert audit["output"]["row_selection_sources"] == [source.id + "::key", source.id + "::values"]


def test_selector_reductions_and_partition_windows_keep_hidden_columns_private(relation):
    frame = admit(relation)
    rows, audit = opened(
        relation[0],
        frame.select(pl.exclude("group").sum()).release_tn(
            use=USE, to="internal", decide=lambda _: True
        ),
    )
    assert rows == [{"id": 6, "amount": 13.0}]
    assert audit["support"]["known"] is True
    window = frame.with_columns(
        pl.col("amount").mean().over("group").alias("group_mean"),
        pl.col("amount").max().over("id").alias("individual_max"),
    )
    rows, audit = opened(
        relation[0], window.release_tn(use=USE, to="internal", decide=lambda _: True)
    )
    assert [row["group_mean"] for row in rows] == [3, 3, 7]
    assert [row["individual_max"] for row in rows] == [2, 4, 7]
    assert audit["support"]["known"] is True


def test_readmission_retains_prior_audit_and_does_not_count_derived_rows_as_sources(relation):
    from tn_polars import PlanTransform, PolicyDenied

    frame = admit(relation)
    duplicated = frame.transform(
        PlanTransform("duplicate", "1", lambda source: pl.concat([source, source, source]))
    )
    publication = duplicated.release_tn(use=USE, to="internal", decide=lambda _: True)
    prior = opened(relation[0], publication)[1]
    received = admit(
        (relation[0], relation[1], publication),
        lambda request: Decision(
            request["operation"] != "release" or request["aggregate_support"]["known"],
            "known contributors required",
            "d",
        ),
    )
    assert received._support.known is False
    load = next(
        event
        for event in received._tn.policies.audit.records()
        if event["kind"] == "operation" and event["details"]["name"] == "load"
    )
    assert load["details"]["parameters"]["upstream"]["audit_id"] == prior["id"]
    with pytest.raises(PolicyDenied):
        received.group_by("group").agg(pl.col("amount").sum()).release_tn(
            use=USE, to="internal", decide=lambda _: True
        )


def test_relation_admission_refuses_lossy_mixed_numeric_conversion(relation):
    session, policy, _ = relation
    data = session.create(
        {"rows": [{"x": 9007199254740993}, {"x": 1.5}]},
        policy,
        object_type="portfolio.feed.data.v1",
        group="finance",
    )
    source = data.release(use=USE, to="analytics", decide=lambda _: True)
    with pytest.raises(ValueError, match="changes values or types"):
        admit((session, policy, source))


def test_signed_claim_identity_and_subject_survive_general_plan_and_recipient_verification(
    tmp_path,
):
    from tn_polars import EndpointEvaluator, PlanTransform, load_relation, open_audited_frame
    from tn_polars.authority import policy_identity

    from tn_governed.publications import PublicationStore
    from tn_governed.values.evidence import EvidenceRecorder
    from tn_governed.values.string import ValueReference

    text = (
        POLICY
        + "\n"
        + POLICY[POLICY.index("## ") :].replace("portfolio.feed.data.v1", "experiment.evidence")
    )
    with tn.Session(text, groups=["finance", "evidence"]) as session:
        policy = session.policy("portfolio.feed.data.v1")
        recorder = EvidenceRecorder(
            session, PublicationStore(tmp_path / "records"), session.policy("experiment.evidence")
        )
        data = session.create(
            {"rows": [{"amount": 12}]},
            policy,
            object_type="portfolio.feed.data.v1",
            group="finance",
        )
        original = data.release(use=USE, to="analytics", decide=lambda _: True)
        subject = ValueReference(original.id, "rows", "finance")
        claim_id = recorder.append(
            "Claim",
            call_id="attest",
            application="publisher",
            purpose="source-description",
            operation="attest",
            inputs=(subject,),
            details={
                "subjects": [subject.to_dict()],
                "statement": "Synthetic account observations",
            },
        )
        working = session.receive(original, use=USE, groups=["finance"], decide=lambda _: True)
        working.set(None, {"manifest": {"claims": [claim_id]}}, group="evidence")
        source = working.release(use=USE, to="analytics", decide=lambda _: True)
        observed = []

        def evaluate(request):
            observed.append(request)
            return Decision(bool(request.get("claims")), "requires attributed source", "d")

        evaluator = EndpointEvaluator("finance", "attribution", "1", {}, evaluate)
        frame = load_relation(
            source,
            session=session,
            use=USE,
            evaluators={policy_identity(policy): evaluator},
            decide=lambda _: True,
            verify_claim=recorder.read,
        )
        transformed = frame.transform(
            PlanTransform(
                "increment",
                "1",
                lambda source: source.with_columns((pl.col("amount") + 7).alias("amount")),
            )
        )
        publication = transformed.release_tn(use=USE, to="internal", decide=lambda _: True)
        audit = open_audited_frame(
            publication, session=session, use=USE, decide=lambda _: True, verify_claim=recorder.read
        )
        original_claim = recorder.read(claim_id)
        assert audit["claims"] == [
            {"id": claim_id, "writer": original_claim.writer, "body": original_claim.body}
        ]
        assert all(request["claims"][0]["id"] == claim_id for request in observed)
        assert original_claim.body["inputs"] == [subject.to_dict()]
        assert original.id != publication.id
        with pytest.raises(Exception, match="verifier"):
            open_audited_frame(publication, session=session, use=USE, decide=lambda _: True)
