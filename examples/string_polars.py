"""Transform a governed string in Polars and print encrypted and readable value and policy."""

import json
from dataclasses import replace
from pathlib import Path

import polars as pl
import tn
from local_policy import originate

from tn_governed.native_objects import NativeObjects
from tn_governed.values import Assessment, Context, EvidenceRecorder, Rules, TNString
from tn_governed.values.primitives import VALUE_TYPE


def demonstrate(context, policy):
    name = originate(context, "alice", policy, "name")
    frame = pl.DataFrame({"name": [name]}, schema={"name": pl.Object})

    with context:
        frame = frame.with_columns(
            frame["name"].map_elements(TNString.upper, return_dtype=pl.Object)
        )

    result = frame["name"][0]
    ciphertext = result.publication.object.envelope["values"]["ciphertext"]
    print("Encrypted:", ciphertext)
    print("Decrypted:", result.reveal(context, destination="console"))
    publication = result.publication.object
    print("Encrypted policy:", publication.envelope["tn.agents"]["ciphertext"])
    carried_policy = context.session.governance(publication).governance.policies[0]
    print("Decrypted policy:", json.dumps(carried_policy.fields, indent=2))
    return result


def main():
    policy_text = Path(__file__).with_name("string_processing.policy").read_text(encoding="utf-8")
    with (
        tn.Session(
            policy_text, groups=["values", "evidence"], policy_id="string_processing.policy",
        ) as session,
        NativeObjects() as store,
    ):
        policy = session.policy("string.processing")
        recorder = EvidenceRecorder(session, store, session.policy("operation.records"))
        rules = Rules(
            writers=frozenset({session.did}),
            policies=(policy,),
            operations=frozenset({"select", "upper", "reveal"}),
            destinations=frozenset({"console"}),
        )

        def evaluate(request):
            if request.application != "string-polars" or request.purpose != "normalization":
                return Assessment(False, "Application or purpose is not permitted.")
            decision = rules(request)
            return replace(decision, obligations=("monitor",)) if decision.permit else decision

        def accept_metadata(arrived):
            return (
                arrived.writer in rules.writers
                and arrived.object_type == VALUE_TYPE
                and bool(arrived.policies)
                and all(item.matches_contract(policy) for item in arrived.policies)
            )

        context = Context(
            session, recorder, evaluate,
            application="string-polars", purpose="normalization", actor="developer",
            metadata_accept=accept_metadata,
        )
        demonstrate(context, policy)


if __name__ == "__main__":
    main()
