from __future__ import annotations


_FORMULA_PREFIXES = ("=", "+", "-", "@")


def csv_safe(value):
    """Keep numeric cells numeric while neutralizing spreadsheet formulas."""

    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return value
    text = "" if value is None else str(value)
    if text.startswith(_FORMULA_PREFIXES):
        return "'" + text
    return text


def csv_safe_row(values):
    return [csv_safe(value) for value in values]
