"""Execute a registered tool over a governed value and inspect its retained claims."""

import json
from pathlib import Path

import tn

from tn_governed.endpoints import Endpoint
from tn_governed.tool_runtime import Call, ToolRegistry, ToolSpec, ToolWorkflow
from tn_governed.values import Assessment, Rules


def main():
    policy_text = Path(__file__).with_name("tool_workflow.policy").read_text(encoding="utf-8")
    with tn.Session(
        policy_text, groups=["values", "evidence"], policy_id="tool_workflow.policy",
    ) as session:
        policy = session.policy("tool.input")
        rules = Rules(
            writers=frozenset({session.did}),
            policies=(policy,),
            operations=frozenset({
                "originate", "attest", "tool.call", "workflow.release", "reveal",
            }),
            destinations=frozenset({"console"}),
        )

        def evaluate(request):
            if request.application != "tool-example" or request.purpose != "calculation":
                return Assessment(False, "Application or purpose is not permitted.")
            return rules(request)

        def accept_metadata(arrived):
            return (
                arrived.writer in rules.writers
                and bool(arrived.policies)
                and all(item.matches_contract(policy) for item in arrived.policies)
            )

        endpoint = Endpoint(
            session=session,
            evidence_policy=session.policy("operation.records"),
            evaluator=evaluate,
            application="tool-example",
            purpose="calculation",
            accept_metadata=accept_metadata,
        )
        amount = endpoint.originate(12, policies=(policy,))
        amount = endpoint.attest(amount, "This reading is an estimate.")
        tools = ToolRegistry((ToolSpec(
            "scale",
            input_schema={
                "type": "object",
                "properties": {"factor": {"type": "number"}},
                "required": ["factor"],
                "additionalProperties": False,
            },
            output_schema={"type": "number"},
            handler=lambda invocation: invocation.values[0] * invocation.arguments["factor"],
        ),))
        workflow = ToolWorkflow(endpoint, tools, {"amount": amount}, required_tools=("scale",))
        workflow.execute(Call("scaled", "scale", {"factor": 3}, inputs=("amount",)))
        result = workflow.finish(
            {"scaled": workflow.expose("result:scaled", destination="console")},
            schema={"type": "object", "properties": {"scaled": {"type": "number"}},
                    "required": ["scaled"], "additionalProperties": False},
            destination="console",
        )
        print(json.dumps(endpoint.reveal(result, destination="console")))
        print(f"Retained claims: {len(endpoint.claims(result))}")
        print(f"Verified signed records: {len(endpoint.records())}")


if __name__ == "__main__":
    main()
