from dataclasses import dataclass


class PolicyDenied(Exception):
    pass


@dataclass(frozen=True)
class Decision:
    allow: bool
    reason: str
    decision_id: str


