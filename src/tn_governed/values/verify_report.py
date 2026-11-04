"""The files a completed verification writes: its summary, the readable graph, and Mermaid views."""

import json

# Default count of source cells above which the written graph has one node per source publication.
GRAPH_CELL_LIMIT = 10000


def report_graph(nodes, edges, policy_edges, cell_limit=GRAPH_CELL_LIMIT):
    """The graph a reader can open. The in-memory cell graph is what was verified.

    Above ``cell_limit`` source cells each source publication is one node; None keeps every cell.
    """
    cells = {node["id"]: node for node in nodes if node["operation"] == "select"}
    if cell_limit is None or len(cells) <= cell_limit:
        return {"nodes": nodes, "edges": edges, "policy_edges": policy_edges}
    publications = {}
    for node in cells.values():
        item = publications.setdefault(node["object_id"], {
            "id": node["object_id"], "object_id": node["object_id"], "kind": node["kind"],
            "operation": "select", "cells": 0, "policy_revisions": node["policy_revisions"],
            "claims": [], "source": {k: v for k, v in node["source"].items() if k != "row"}})
        item["cells"] += 1
    linked = {(cells[edge["parent"]]["object_id"] if edge["parent"] in cells else edge["parent"],
               edge["child"], edge["operation"]): None for edge in edges}
    return {"nodes": [node for node in nodes if node["id"] not in cells] + list(publications.values()),
            "edges": [{"parent": parent, "child": child, "operation": operation}
                      for parent, child, operation in linked],
            "policy_edges": policy_edges, "source_cells": "one node per source publication"}


def write_reports(root, summary, graph):
    """Write the summary, the graph, its Mermaid view, and the model graph of a completed report."""
    (root / "verification.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    (root / "dag.json").write_text(json.dumps(graph), encoding="utf-8")
    names, mermaid = _mermaid(graph)
    (root / "dag.mmd").write_text("\n".join(mermaid) + "\n", encoding="utf-8")
    model = summary.get("model", {})
    if model.get("completed"):
        _write_model_graph(root, model, graph, names, mermaid)
    _print_summary(root, summary)


def _mermaid(graph):
    names = {node["id"]: "n" + str(i) for i, node in enumerate(graph["nodes"])}
    mermaid = ["flowchart LR"]
    for node in graph["nodes"]:
        identity, source = node["id"], node["source"]
        place = f" row {source['row']}" if source and "row" in source else f" {node.get('cells')} cells"
        label = (source["column"] + place) if source else node["operation"]
        mermaid.append(f'  {names[identity]}["{node["kind"]}: {label}<br/>{identity[7:17]}"]')
    mermaid.extend(f'  {names[e["parent"]]} --> {names[e["child"]]}' for e in graph["edges"])
    return names, mermaid


def _write_model_graph(root, model, graph, names, mermaid):
    """Add the native compliance, report, and pending review nodes to the verified graph."""
    native_nodes = [{"id": identity, "kind": "native-compliance", "operation": "log_compliance_creation"}
                    for identity in model["tool_object_ids"]]
    native_nodes.append({"id": model["output_object_id"], "kind": "native-report", "operation": "generate_report"})
    review_edges = []
    if model.get("review"):
        review = model["review"]
        native_nodes.append({"id": review["record_id"], "kind": "pending-review-evidence",
                             "operation": "request_review"})
        review_edges.append({"parent": model["output_object_id"], "child": review["record_id"],
                             "operation": "request_review", "relation": "signed-subject-reference"})
    model_graph = {"nodes": graph["nodes"] + native_nodes,
                   "edges": graph["edges"] + model["native_edges"] + review_edges,
                   "policy_edges": graph["policy_edges"]}
    for node in native_nodes:
        names[node["id"]] = "n" + str(len(names))
        mermaid.append(f'  {names[node["id"]]}["{node["kind"]}<br/>{node["id"][7:17]}"]')
    mermaid.extend(f'  {names[e["parent"]]} --> {names[e["child"]]}' for e in model["native_edges"])
    mermaid.extend(f'  {names[e["parent"]]} -. "review requested" .-> {names[e["child"]]}' for e in review_edges)
    (root / "model-dag.json").write_text(json.dumps(model_graph), encoding="utf-8")
    (root / "model-dag.mmd").write_text("\n".join(mermaid) + "\n", encoding="utf-8")


def _print_summary(root, summary):
    print(json.dumps({k: summary[k] for k in ("network_used", "record_count", "record_kinds", "incarnations",
                                              "derivation_edges", "source_editions", "policy_revisions")},
                     indent=2))
    print(f"Offline evidence and DAG: {root / 'verification.json'}")
    model = summary.get("model", {})
    if model.get("completed"):
        print(f"Native report and visible disclosure verified: {model['output_object_id']}")
        if model.get("review"):
            print("Compensatory action: report generated, model notified, "
                  f"signed review request pending for {model['review']['assignee']}.")
