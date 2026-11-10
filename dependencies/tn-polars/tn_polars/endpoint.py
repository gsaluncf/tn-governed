"""Claim-preserving native dataframe admission into an endpoint artifact."""

import tn

from .audit import AuditError, verify_audit, verify_frame_metadata, verify_native_frame


def import_frame(
    endpoint,
    publication,
    *,
    publications=(),
    decide=None,
    metadata_group="evidence",
    operation="import",
):
    """Verify carried metadata before authorizing and opening the business rows."""
    with endpoint._lock:
        return _import_frame(
            endpoint,
            publication,
            publications=publications,
            decide=decide,
            metadata_group=metadata_group,
            operation=operation,
        )


def _import_frame(endpoint, publication, *, publications, decide, metadata_group, operation):
    for wire in publications:
        endpoint.store.put(tn.GovernedObject.parse(wire))
    endpoint.store.put(publication)
    if metadata_group not in publication.envelope:
        raise AuditError("frame import requires a separately accessible audit metadata group")
    use = tn.UseContext(endpoint.application, endpoint.purpose, operation)

    def accept(context):
        return endpoint.accept_metadata(context) is True and (
            decide is None or decide(context) is True
        )

    governance = endpoint.session.governance(publication).governance
    metadata = endpoint.session.receive(
        publication, use=use, groups=[metadata_group], decide=accept
    )
    try:
        descriptor = metadata.get("tn_polars_governance", group=metadata_group)
    except KeyError:
        descriptor = None
    if descriptor is not None:
        expected = verify_frame_metadata(metadata, metadata_group, endpoint.read_record)
        group, rows_field = expected["group"], expected["rows_field"]
        claim_ids = tuple(expected["claims"])
    else:
        audit = verify_audit(
            metadata.get("tn_polars_audit", group=metadata_group),
            expected_sources=[source.object_id for source in governance.sources],
        )
        claims = metadata.get("tn_polars_claims", group=metadata_group)
        if claims != audit.get("claims", []):
            raise AuditError("frame metadata claims differ from its audit")
        for item in claims:
            record = endpoint.read_record(item["id"])
            if (
                record.writer != item["writer"]
                or record.body != item["body"]
                or record.body["kind"] != "Claim"
            ):
                raise AuditError("frame metadata claim differs from its signed record")
        terminal = next(event for event in audit["events"] if event["id"] == audit["heads"][0])
        group = terminal["details"]["parameters"]["group"]
        rows_field = terminal["details"]["parameters"]["rows_field"]
        expected = audit
        claim_ids = tuple(item["id"] for item in claims)
    if group == metadata_group:
        raise AuditError("frame business rows require a separate metadata group")

    def validate(data):
        observed = verify_native_frame(
            data,
            governance=governance,
            group=group,
            rows_field=rows_field,
            verify_claim=endpoint.read_record,
        )
        if observed != expected:
            raise AuditError("frame business audit differs from its admitted metadata")
        return True

    return endpoint.import_publication(
        publication,
        group=group,
        field=rows_field,
        operation=operation,
        claims=claim_ids,
        actions=tuple(expected.get("actions", ())),
        decide=decide,
        validate=validate,
    )
