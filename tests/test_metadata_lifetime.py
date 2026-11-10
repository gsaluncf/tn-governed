"""Carried values do not retain the producing endpoint or its reader keys."""

import gc
import weakref

import pytest
from test_carried_values import _context, _originate
from test_carried_values import enrolled as enrolled

from tn_governed.values.string import MetadataUnavailable


def test_declared_metadata_does_not_keep_the_producing_context_alive(enrolled):
    sessions, policy, audit = enrolled
    writers = {session.did for session in sessions.values()}
    producer = _context(sessions["producer"], policy, audit, writers)
    (value,) = _originate(producer, ("Ada",), policy)
    provider = value.metadata_provider
    owner = weakref.ref(producer)
    assert len(value) == 3
    producer.session.close()
    del producer
    gc.collect()
    assert owner() is None
    with pytest.raises(MetadataUnavailable):
        provider.facts(value)
    recipient = _context(sessions["recipient"], policy, audit, writers)
    with recipient:
        assert len(value) == 3
    assert value.reveal(recipient, destination="internal") == "Ada"
