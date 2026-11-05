"""Received primitive values are constructed once and retain checked bindings."""

from decimal import Decimal

import pytest
from test_batched_primitives import context as context
from test_batched_primitives import publish
from tn.governed import UseDenied

from tn_governed.values.evidence import EvidenceError
from tn_governed.values.numeric import TNNumeric
from tn_governed.values.string import TNString


@pytest.mark.parametrize("contents", [
    ["Ada", "Grace"], [7, 8], [0.125, 1.25],
    [Decimal("1.2500"), Decimal("2.3750")],
])
def test_hydration_constructs_each_received_value_once(context, monkeypatch, contents):
    sources = publish(context, contents)
    calls = []
    if isinstance(sources[0], TNString):
        original = TNString.__new__

        def construct(cls, *args, **kwargs):
            calls.append(args[0])
            return original(cls, *args, **kwargs)

        monkeypatch.setattr(TNString, "__new__", staticmethod(construct))
    else:
        original = TNNumeric.__init__

        def initialize(self, *args, **kwargs):
            calls.append(args[0])
            original(self, *args, **kwargs)

        monkeypatch.setattr(TNNumeric, "__init__", initialize)
    values = context.hydrate_many([
        (value.reference, value.decision_id, value.result_id, type(content).__name__)
        for value, content in zip(sources, contents, strict=True)
    ])
    assert len(calls) == 2
    for value, source, content in zip(values, sources, contents, strict=True):
        assert value is not source
        assert value.reference == source.reference
        assert value.metadata_provider is context.string_metadata
        assert value.publication.object.id == value.reference.object_id
        actual = value.reveal(context, destination="console")
        assert type(actual) is type(content) and actual == content
        with pytest.raises(AttributeError, match="read-only"):
            value.publication = source.publication


def test_hydration_rejects_type_substitution(context):
    value = publish(context, [7])[0]
    with pytest.raises(EvidenceError, match="requested type differs"):
        context.hydrate_many([(value.reference, None, None, "float")])


def test_hydration_rechecks_metadata_admission(context):
    value = publish(context, [7])[0]
    handles = [(value.reference, None, None, "int")]
    context.hydrate_many(handles)
    context.metadata_accept = lambda _: False
    with pytest.raises(UseDenied):
        context.hydrate_many(handles)


@pytest.mark.parametrize("replacement", ["another_publication", "ordinary_object"])
def test_hydration_rejects_an_invalid_carrier(context, monkeypatch, replacement):
    value = publish(context, [7])[0]
    other = publish(context, [8])[0]
    carrier = other.publication if replacement == "another_publication" else object()
    monkeypatch.setattr(context, "_received_carrier", lambda *args, **kwargs: carrier)
    with pytest.raises(ValueError, match="carried publication differs"):
        context.hydrate_many([(value.reference, None, None, "int")])
