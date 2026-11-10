"""Source assignment scope and aggregate policy metadata."""

from test_polars_plans import relation as relation

def test_legacy_origin_union_merges_rows_and_keeps_distinct_scopes():
    from tn_governed.values.manifests import origin_rows, unique_origins

    first = {"publication": "one", "row": 1, "column": "price",
             "snapshot": {"tables": ["market"], "epoch": 1}}
    equal = {"snapshot": {"epoch": 1.0, "tables": ["market"]}, "column": "price",
             "row": True, "publication": "one"}
    other_row = {**first, "row": 2}
    other_column = {**first, "column": "name"}
    other_publication = {**first, "publication": "two"}
    inputs = [first, other_row, equal, other_column, other_publication, dict(first)]
    union = unique_origins(inputs)
    scope = {key: item for key, item in first.items() if key != "row"}
    assert union == [{**scope, "rows": [[1, 2]]}, other_column, other_publication]
    assert unique_origins(union) == union
    assert origin_rows(union) == 4
    assert first == equal


def test_frame_policy_descriptor_is_independent_of_group_membership(relation):
    from test_polars_plans import USE, admit, opened
    import polars as pl

    frame = admit(relation)
    descriptors = []
    for threshold in (0, 3, 50):
        filtered = frame.filter(pl.col("amount") > threshold).group_by("group").agg(pl.col("amount").sum())
        publication = filtered.release_tn(use=USE, to="internal", decide=lambda _: True)
        rows, descriptor = opened(relation[0], publication)
        assert len(rows) == (2 if threshold < 50 else 0)
        assert all(row["amount"] > threshold for row in rows)
        assert not relation[0].governance(publication).governance.sources
        descriptors.append(descriptor)
    assert descriptors[0] == descriptors[1] == descriptors[2]
