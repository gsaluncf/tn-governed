import hashlib
import json
from dataclasses import dataclass
from copy import deepcopy


def policy_sha256(policy):
    """Canonical content hash of a compiled policy document."""
    canonical = json.dumps(policy.to_dict(), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class CompiledPolicy:
    schema: str
    policy_ref: str
    fields: dict[str, str]
    release: dict

    def __post_init__(self):
        if self.schema != "tn.polars-policy.v1":
            raise ValueError("unsupported tn-polars policy schema")
        if not isinstance(self.policy_ref, str) or not self.policy_ref.strip():
            raise ValueError("compiled policy requires policy_ref")
        if not isinstance(self.fields, dict) or any(
            not isinstance(name, str) or not name or not isinstance(level, str)
            or level not in {"public", "internal", "confidential"}
            for name, level in self.fields.items()
        ):
            raise ValueError("compiled policy requires supported field classifications")
        if not isinstance(self.release, dict) or set(self.release) - {"public"}:
            raise ValueError("unsupported release audience requirements")
        if "public" in self.release:
            rule = self.release["public"]
            if not isinstance(rule, dict) or set(rule) != {"allow_aggregates", "min_group_size"}:
                raise ValueError("unsupported public release rule shape")
            if type(rule["allow_aggregates"]) is not bool:
                raise ValueError("allow_aggregates must be boolean")
            if type(rule["min_group_size"]) is not int or rule["min_group_size"] < 1:
                raise ValueError("min_group_size must be a positive integer")
        object.__setattr__(self, "fields", deepcopy(self.fields))
        object.__setattr__(self, "release", deepcopy(self.release))

    @classmethod
    def from_dict(cls, value: dict) -> "CompiledPolicy":
        if not isinstance(value, dict) or set(value) != {"schema", "policy_ref", "fields", "release"}:
            raise ValueError("unsupported compiled policy fields")
        if value.get("schema") != "tn.polars-policy.v1":
            raise ValueError("unsupported tn-polars policy schema")
        if not isinstance(value.get("policy_ref"), str) or not value["policy_ref"]:
            raise ValueError("compiled policy requires policy_ref")
        if not isinstance(value.get("fields"), dict):
            raise ValueError("compiled policy requires field classifications")
        return cls(
            schema=value["schema"],
            policy_ref=value["policy_ref"],
            fields=dict(value["fields"]),
            release=value["release"],
        )

    def level(self, source: str) -> str:
        """Classification for a source column; unknown names fail closed.

        A source the policy never classified is treated as confidential, not
        public. A typo or an unexpected column must surface as a denial to
        investigate, never as public data.
        """
        return self.fields.get(source, "confidential")

    def to_dict(self) -> dict:
        """Return the persisted policy document consumed by tn-polars runtime code."""
        return {
            "schema": self.schema,
            "policy_ref": self.policy_ref,
            "fields": dict(self.fields),
            "release": deepcopy(self.release),
        }


_LEVELS = {"public", "internal", "confidential"}


def candidate_to_policy(candidate, tn_governance, declared_fields):
    if not isinstance(candidate, dict) or set(candidate) != {"schema", "policy_ref", "fields", "release"}:
        raise ValueError("unsupported policy candidate fields")
    if candidate.get("schema") != "tn.polars-policy-candidate.v1":
        raise ValueError("unexpected OpenRouter policy-candidate schema")
    if candidate.get("policy_ref") != tn_governance.get("policy"):
        raise ValueError("OpenRouter candidate is not bound to this TN policy reference")
    fields = candidate.get("fields")
    if not isinstance(fields, dict) or set(fields) != set(declared_fields):
        raise ValueError("candidate fields must match the declared Polars input schema")
    if not all(isinstance(level, str) and level in _LEVELS for level in fields.values()):
        raise ValueError("candidate uses an unsupported field classification")
    return CompiledPolicy.from_dict({
        "schema": "tn.polars-policy.v1",
        "policy_ref": candidate["policy_ref"],
        "fields": fields,
        "release": candidate["release"],
    })
