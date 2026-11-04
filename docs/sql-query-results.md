`GovernedSQL.execute_query(sql, parameters)` executes an authorized read-only
SQLite query and returns a `GovernedQueryResult`. SQLite evaluates predicates,
joins, expressions, grouping, windows, subqueries, and set operations. The
gateway resolves source assignments before execution and asks the configured
endpoint policy evaluator to authorize the union of value and control sources.
Queries that read an unenrolled source or a refused source do not execute.

```python
result = driver.execute_query(
    """SELECT a.region, sum(s.amount * :rate) AS total
       FROM sales AS s JOIN accounts AS a ON s.account_id = a.id
       WHERE a.active = :active GROUP BY a.region""",
    {"rate": 2, "active": 1},
)
admitted = result.open_for_processing("select", "reporting-service")
frame = tn_polars.from_admitted_query(
    admitted, use=use, evaluators=endpoint_evaluators,
)
```

The SQL processing admission evaluates the requested operation and destination,
performs required actions, verifies the signed result and typed values, and
returns a native governed working object. The receiving adapter supplies its
own endpoint evaluators for every carried policy. `reveal(destination)` is the
separate boundary for extracting ordinary Python values. Duplicate SQL aliases
remain distinguishable by column position; the Polars bridge requires explicit
unique output names when aliases repeat.

The signed query binding records the original statement, typed parameters,
database snapshot, source assignments, SQLite version, configured functions,
lineage strategy, actual instrumented statement, and positional output schema.
The read transaction remains open through publication. SQLite files with active
WAL content are refused until the source snapshot is checkpointed. The result
retains SQL NULL, bytes, exact supported numeric encodings, duplicate rows, and
empty relations without using value equality to infer contributor identities.

For SELECTs over base tables, the built-in strategy appends private row identity
projections to the same business statement. Scalar expressions execute once.
Source row IDs, or composite primary keys for WITHOUT ROWID tables, identify
positive value contributors. Predicate, join, grouping, ordering, and relation
presence dependencies are recorded separately. Grouped values collect group
members; aggregate windows collect their frame members. Current-row operands
and window operands retain their respective dependencies. Ranking and navigation
functions retain the partition as conservative support. Outer-join NULLs do not
create source row identities.

The manifest stores each output row's identities once for each source table in
`contributor_rows`, and `contributor_columns` lists the sources of each output
column with the identity list each one uses. A group of n source rows therefore
costs n identities rather than n for every column and dependency. A lone integer
row identity stays a number. `lineage_cells(lineage)` expands this to contributors
for each result position.

`execute_query(sql, parameters, contributor_tracking=False)` skips row identity
projections and records source columns with `row_support="unknown"`.

Selection and absence also depend on the source snapshot, including excluded
rows. Those dependencies remain snapshot-scoped, so the built-in manifest uses
`precision="conservative"` even when positive row identities are known. Queries
whose projection augmentation could alter SQLite semantics, including DISTINCT,
CTEs, subqueries, set operations, views, and combined grouping/window plans,
execute the original statement with the authorized source scope and
`row_support="unknown"`. These queries retain every admitted source policy.
The precision fields let endpoint policy decide whether that evidence suffices
for the requested use.

`SQLFunction` registrations identify trusted endpoint callbacks, their arity,
authority, determinism, and additional source dependencies. Declared external
dependencies participate in source admission and produce partial row support
when their row mappings are unavailable. Overridden SQLite built-in functions
use the original statement and source-scope lineage. A configured
`LineageProvider` can supply result-position mappings with a separate validation
callback; exact precision requires identified contributors and coverage of each
result position. The gateway checks these structural requirements and the
configured validator's answer before publication.

```python
from tn_governed.values.query_result import GovernedQueryResult, QueryTransport

wire = result.export().to_bytes()
carried = QueryTransport.from_bytes(wire)
received = GovernedQueryResult.receive(recipient_context, carried)
admitted = received.open_for_processing("select", "recipient-reporting")
```

The transport carries canonical native TN wires, signed source assignments,
policy revisions, dataset edition evidence, and the query's Decision and Result
ancestry. It requires no publisher object store, source database, or online
catalog at receipt. The recipient resolves the carried assignments against its
own trust configuration, verifies the native signatures and signed bindings,
and evaluates its own requested use. Transport metadata supplies no authority
by itself. Attributed claims are signed Claim records with their original
subjects and writers; ordinary unsigned catalog fields do not become claims.
