"""Prepared batch metadata can be reused while content access is authorized separately."""

import pytest
from test_batched_primitives import context as context
from test_batched_primitives import publish
from tn.governed import UseDenied

from tn_governed.values import primitives
from tn_governed.values.evidence import EvidenceError


def prepare(context, values):
    request, metadata, _ = context._prepare("add", values, None, (), "calculation")
    return request, metadata


def test_content_open_reuses_the_prepared_signed_manifest(context, monkeypatch):
    values = publish(context, [7, 8, 9])
    reads = []
    original = primitives.signed_manifest

    def manifest(data):
        reads.append(data.snapshot.id)
        return original(data)

    monkeypatch.setattr(primitives, "signed_manifest", manifest)
    request, metadata = prepare(context, values)
    opened = context._open_values(request, values, metadata=metadata)
    assert [content for _, content in opened] == [7, 8, 9]
    assert len(reads) == 1


def test_prepared_metadata_does_not_reuse_a_content_permit(context):
    values = publish(context, [7, 8])
    request, metadata = prepare(context, values)
    context.metadata_accept = lambda _: False
    with pytest.raises(UseDenied):
        context._open_values(request, values, metadata=metadata)


def test_prepared_metadata_requires_the_same_ordered_field_references(context):
    values = publish(context, [7, 8])
    request, metadata = prepare(context, values)
    with pytest.raises(EvidenceError, match="prepared metadata"):
        context._open_values(request, tuple(reversed(values)), metadata=metadata)


def test_ordinary_metadata_list_cannot_supply_prepared_manifests(context):
    values = publish(context, [7, 8])
    request, metadata = prepare(context, values)
    with pytest.raises(EvidenceError, match="prepared metadata"):
        context._open_values(request, values, metadata=list(metadata))
