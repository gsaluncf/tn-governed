"""Declared primitive facts, bound inside native signed publications.

No payload opening happens here. Process-local Python hashes are cached only
where authorized source/compute code already held the content; never exported.
"""

import hashlib
import json
import weakref

from .numeric import TNNumeric
from .numeric_codec import NUMERIC_TYPES, encode, equality_key
from .string import MetadataUnavailable, TNString

_PROCESS_HASHES = {}


def fingerprint(content):
    if type(content) is str:
        encoded = b"str\x00" + content.encode("utf-8", "surrogatepass")
    elif type(content) is int:
        encoded = b"int\x00" + str(content).encode("ascii")
    elif type(content) in NUMERIC_TYPES:
        encoded = type(content).__name__.encode() + b"\x00" + encode(content).encode("ascii")
    else:
        raise TypeError("unsupported primitive facts")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def numeric_equality_fingerprint(content):
    key = equality_key(content)
    if key is None:
        return None
    if key[0] == "ratio" and key[2] == "1":
        return fingerprint(int(key[1]))
    return "sha256:" + hashlib.sha256(json.dumps(key).encode("ascii")).hexdigest()


def describe(content):
    identity = fingerprint(content)
    # An int always has an equality key; skip computing it.
    if type(content) is str or type(content) is int or equality_key(content) is not None:
        _PROCESS_HASHES[identity] = hash(content)
    facts = {
        "kind": type(content).__name__,
        "fingerprint": identity,
        "fingerprint_scheme": "tn.primitive.content.v1",
    }
    if type(content) is str:
        facts["length"] = len(content)
    elif type(content) is int:
        facts.update(bit_length=content.bit_length(), bit_count=content.bit_count())
    else:
        facts["equality_fingerprint"] = numeric_equality_fingerprint(content)
    return facts


_SCHEME = "tn.primitive.content.v1"


def column_facts(contents):
    """``describe`` of every cell, as columns in its key order; None outside str and int columns."""
    kinds = set(map(type, contents))
    if kinds == {str}:
        prints = ["sha256:" + hashlib.sha256(b"str\x00" + content.encode("utf-8", "surrogatepass")).hexdigest()
                  for content in contents]
        _PROCESS_HASHES.update(zip(prints, map(hash, contents)))
        size = len(contents)
        return {"kind": ["str"] * size, "fingerprint": prints, "fingerprint_scheme": [_SCHEME] * size,
                "length": list(map(len, contents))}
    if kinds == {int}:
        prints = ["sha256:" + hashlib.sha256(b"int\x00" + str(content).encode("ascii")).hexdigest()
                  for content in contents]
        _PROCESS_HASHES.update(zip(prints, map(hash, contents)))
        size = len(contents)
        return {"kind": ["int"] * size, "fingerprint": prints, "fingerprint_scheme": [_SCHEME] * size,
                "bit_length": [content.bit_length() for content in contents],
                "bit_count": [content.bit_count() for content in contents]}
    return None


class DeclaredMetadata:
    def __init__(self, context):
        self._context = weakref.ref(context)

    @property
    def context(self):
        context = self._context()
        if context is None:
            raise MetadataUnavailable("declared metadata requires an active receiving context")
        return context

    def facts(self, value):
        _, binding, _ = self.context._metadata(value)
        facts = binding.get("declared")
        if not isinstance(facts, dict):
            raise MetadataUnavailable("publication has no declared primitive facts")
        return facts

    def length(self, value):
        return self.facts(value)["length"]

    def fingerprint(self, value):
        return self.facts(value)["fingerprint"]

    def python_hash(self, value):
        digest = self.fingerprint(value)
        if digest not in _PROCESS_HASHES:
            raise MetadataUnavailable(
                "no plaintext-equivalent hash has been computed in this process"
            )
        return _PROCESS_HASHES[digest]

    def equals(self, left, right):
        facts = self.facts(left)
        other = self.facts(right) if isinstance(right, (TNString, TNNumeric)) else None
        if facts["kind"] == "str":
            if other is not None:
                return other["kind"] == "str" and facts["fingerprint"] == other["fingerprint"]
            return type(right) is str and facts["fingerprint"] == fingerprint(right)
        right_kind = other["kind"] if other else type(right).__name__
        if right_kind == "str":
            return False
        if {facts["kind"], right_kind} == {"Decimal", "float"}:
            raise MetadataUnavailable("Decimal/float comparison uses the active decimal context")
        left_key = (
            facts["fingerprint"] if facts["kind"] == "int" else facts.get("equality_fingerprint")
        )
        if other:
            right_key = (
                other["fingerprint"]
                if other["kind"] == "int"
                else other.get("equality_fingerprint")
            )
        else:
            if type(right) is bool:
                right = int(right)
            if type(right) not in NUMERIC_TYPES:
                return False
            right_key = numeric_equality_fingerprint(right)
        if left_key is None or right_key is None:
            raise MetadataUnavailable("non-reflexive numbers require protected comparison")
        return left_key == right_key

    def compare(self, left, right):
        if self.equals(left, right):
            return 0
        raise MetadataUnavailable("no declared sort key; comparison needs the protected runtime")
