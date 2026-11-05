"""Shared carriers are adopted once while every cell keeps its exact binding."""

from types import SimpleNamespace

import pytest
import tn

from tn_governed.native_objects import CarriedPublication, NativeObjects
from tn_governed.values.evidence import EvidenceError
from tn_governed.values.runtime import Context

from test_native_objects import POLICY


@pytest.mark.parametrize("mismatched_last", [False, True])
def test_adoption_visits_shared_carrier_once_and_checks_each_reference(mismatched_last):
    with tn.Session(POLICY, groups=["values", "evidence"]) as session:
        publication = session.create(
            {"value": 3}, session.policy("finance.account"), group="values"
        ).snapshot
        carrier = CarriedPublication(publication)

        class CountingObjects(NativeObjects):
            calls = 0

            def include(self, carried):
                self.calls += 1
                super().include(carried)

        store = CountingObjects()
        context = Context.__new__(Context)
        context.recorder = SimpleNamespace(store=store)
        values = [SimpleNamespace(publication=carrier,
                                  reference=SimpleNamespace(object_id=publication.id))
                  for _ in range(100)]
        if mismatched_last:
            values[-1].reference.object_id = "sha256:" + "0" * 64
            with pytest.raises(EvidenceError, match="differs from the value reference"):
                context._adopt(values)
        else:
            context._adopt(values)
            assert store.read(publication.id) is publication
        assert store.calls == 1
