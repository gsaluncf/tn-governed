import polars as pl


def customer_totals(orders):
    """Return governed customer totals for nonnegative order amounts."""
    return (
        orders.filter(pl.col("amount") >= 0)
        .group_by("customer_id")
        .agg(pl.col("amount").sum().alias("total"))
        .sort("customer_id")
    )
