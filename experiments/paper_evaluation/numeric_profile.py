"""Explicit SQL numeric types and their signed Polars storage profiles."""

from decimal import Decimal
import polars as pl

from tn_governed.values.numeric_codec import encode


def numeric_profile(kind, precision=38, scale=None):
    if kind == 'int':
        return {'kind': 'int', 'dtype': 'Int64'}
    if kind == 'float':
        return {'kind': 'float', 'dtype': 'Float64'}
    if kind == 'Decimal':
        if (type(precision) is not int or type(scale) is not int
                or not 1 <= precision <= 38 or not 0 <= scale <= precision):
            raise ValueError('Decimal requires explicit precision 1..38 and scale 0..precision')
        return {'kind': kind, 'dtype': str(pl.Decimal(precision, scale)),
                'precision': precision, 'scale': scale}
    raise TypeError('dataframe numerics support int, float, or Decimal')


def polars_dtype(profile):
    expected = numeric_profile(profile['kind'], profile.get('precision', 38), profile.get('scale'))
    if profile != expected:
        raise ValueError('numeric profile has inconsistent type or parameters')
    return {'int': pl.Int64, 'float': pl.Float64}.get(profile['kind']) or pl.Decimal(
        profile['precision'], profile['scale'])


def build_frame(rows, profile):
    """Construct exactly the declared schema; reject implicit lossy conversion."""
    dtype = polars_dtype(profile)
    if isinstance(rows, dict):
        names, values = rows['name'], rows['value']
    else:
        names, values = [row['name'] for row in rows], [row['value'] for row in rows]
    if len(names) != len(values):
        raise ValueError('column lengths differ')
    pytype = {'int': int, 'float': float, 'Decimal': Decimal}[profile['kind']]
    if any(type(value) is not pytype for value in values) or any(type(name) is not str for name in names):
        raise TypeError('SQL cells differ from the signed dataframe numeric type')
    if pytype is int and any(not -(2**63) <= value < 2**63 for value in values):
        raise OverflowError('integer exceeds the signed Int64 storage range')
    if pytype is Decimal:
        for value in values:
            if not value.is_finite():
                raise ValueError('Polars Decimal requires finite values')
            # Check coefficient/scale without rounding through the Decimal context.
            _, digits, exponent = value.as_tuple()
            coefficient = int(''.join(map(str, digits)))
            shift = exponent + profile['scale']
            if coefficient == 0:
                continue
            if shift < 0:
                if -shift > len(digits):
                    raise ValueError('Decimal digits would be lost at the signed scale')
                divisor = 10 ** (-shift)
                if coefficient % divisor:
                    raise ValueError('Decimal digits would be lost at the signed scale')
                coefficient //= divisor
            else:
                if coefficient and len(digits) + shift > profile['precision']:
                    raise OverflowError('Decimal exceeds the signed precision')
                coefficient *= 10 ** shift
            if len(str(coefficient)) > profile['precision']:
                raise OverflowError('Decimal exceeds the signed precision')
    frame = pl.DataFrame({'name': names, 'value': values}, schema={'name': pl.String, 'value': dtype}, strict=True)
    for value, converted in zip(values, frame['value'].to_list(), strict=True):
        if pytype is Decimal:
            if value != converted or (value.is_zero() and value.is_signed() != converted.is_signed()):
                raise ValueError('Decimal representation would lose value or zero sign')
        elif encode(value) != encode(converted):
            raise ValueError('numeric value changed during dataframe construction')
    return frame


def check_fixed_plan_range(frame, profile):
    """Reject integer/Decimal overflow in this adapter's add-250-and-sum plan."""
    if profile['kind'] == 'float':
        return
    values = [value for value in frame['value'].to_list() if value >= 0]
    if profile['kind'] == 'int':
        coefficients, increment, maximum = values, 250, 2**63 - 1
    else:
        coefficients = [int(''.join(map(str, value.as_tuple().digits))) for value in values]
        increment = 250 * 10 ** profile['scale']
        maximum = 10 ** profile['precision'] - 1
    adjusted = [value + increment for value in coefficients]
    if any(value > maximum for value in adjusted) or sum(adjusted) > maximum:
        raise OverflowError('dataframe arithmetic exceeds the signed numeric storage range')
