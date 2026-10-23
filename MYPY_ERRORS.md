# Mypy Errors

This document records the current type-checking failures in the repository.
It is a snapshot of the command below, not a waiver for the pre-commit quality
gate.

## Reproduce

From the repository root, with the project virtual environment installed:

```bash
.venv/bin/mypy .
```

Captured on **October 22, 2026** with the repository's configured mypy command.
The run checked **74 source files** and reported **32 errors in 4 files**.

The final mypy summary was:

```text
Found 32 errors in 4 files (checked 74 source files)
```

## Summary

| File | Error count | Main issue |
| --- | ---: | --- |
| `tools/check_dependency_exceptions.py` | 2 | Exception variable is used outside its `except` block. |
| `tools/check_doc_counts.py` | 24 | The `CHECKS` tuple annotation uses registry-key strings where runtime code expects integer indexes, and the later lookup types do not match. |
| `tests/test_reporting_terminal.py` | 1 | Mypy cannot infer the type of a lambda. |
| `tests/test_sarif_report.py` | 5 | An untyped dictionary expansion cannot be proven compatible with `EnrichedFinding`. |

The run also emitted informational notes for untyped function bodies in
`tf_eu_guard/mapping/loader.py` and `tests/test_registry.py`. These notes are
not counted as errors.

## Detailed failures

### `tools/check_dependency_exceptions.py`

```text
tools/check_dependency_exceptions.py:96: error: Assignment to variable "error" outside except: block  [misc]
tools/check_dependency_exceptions.py:97: error: Trying to read deleted variable "error"  [misc]
```

The exception target is treated as deleted after the `except` block by Python's
exception-variable scoping rules. The code should copy the exception into a
separate variable inside the block before using it afterward, or keep all uses
inside the `except` block.

### `tools/check_doc_counts.py`

The first 22 failures are reported for entries in the `CHECKS` list:

```text
tools/check_doc_counts.py:84: error: List item 0 has incompatible type "tuple[str, Pattern[Any], str, str]"; expected "tuple[str, Pattern[Any], int | tuple[int, ...], str]"  [list-item]
tools/check_doc_counts.py:85: error: List item 1 has incompatible type "tuple[str, Pattern[Any], str, str]"; expected "tuple[str, Pattern[Any], int | tuple[int, ...], str]"  [list-item]
tools/check_doc_counts.py:86: error: List item 2 has incompatible type "tuple[str, Pattern[Any], str, str]"; expected "tuple[str, Pattern[Any], int | tuple[int, ...], str]"  [list-item]
tools/check_doc_counts.py:87: error: List item 3 has incompatible type "tuple[str, Pattern[Any], str, str]"; expected "tuple[str, Pattern[Any], int | tuple[int, ...], str]"  [list-item]
tools/check_doc_counts.py:93: error: List item 4 has incompatible type "tuple[str, Pattern[Any], str, str]"; expected "tuple[str, Pattern[Any], int | tuple[int, ...], str]"  [list-item]
tools/check_doc_counts.py:94: error: List item 5 has incompatible type "tuple[str, Pattern[Any], str, str]"; expected "tuple[str, Pattern[Any], int | tuple[int, ...], str]"  [list-item]
tools/check_doc_counts.py:95: error: List item 6 has incompatible type "tuple[str, Pattern[Any], str, str]"; expected "tuple[str, Pattern[Any], int | tuple[int, ...], str]"  [list-item]
tools/check_doc_counts.py:96: error: List item 7 has incompatible type "tuple[str, Pattern[Any], str, str]"; expected "tuple[str, Pattern[Any], int | tuple[int, ...], str]"  [list-item]
tools/check_doc_counts.py:97: error: List item 8 has incompatible type "tuple[str, Pattern[Any], str, str]"; expected "tuple[str, Pattern[Any], int | tuple[int, ...], str]"  [list-item]
tools/check_doc_counts.py:98: error: List item 9 has incompatible type "tuple[str, Pattern[Any], str, str]"; expected "tuple[str, Pattern[Any], int | tuple[int, ...], str]"  [list-item]
tools/check_doc_counts.py:101: error: List item 10 has incompatible type "tuple[str, Pattern[Any], str, str]"; expected "tuple[str, Pattern[Any], int | tuple[int, ...], str]"  [list-item]
tools/check_doc_counts.py:107: error: List item 11 has incompatible type "tuple[str, Pattern[Any], str, str]"; expected "tuple[str, Pattern[Any], int | tuple[int, ...], str]"  [list-item]
tools/check_doc_counts.py:113: error: List item 12 has incompatible type "tuple[str, Pattern[Any], str, str]"; expected "tuple[str, Pattern[Any], int | tuple[int, ...], str]"  [list-item]
tools/check_doc_counts.py:122: error: List item 13 has incompatible type "tuple[str, Pattern[Any], str, str]"; expected "tuple[str, Pattern[Any], int | tuple[int, ...], str]"  [list-item]
tools/check_doc_counts.py:132: error: List item 14 has incompatible type "tuple[str, Pattern[Any], str, str]"; expected "tuple[str, Pattern[Any], int | tuple[int, ...], str]"  [list-item]
tools/check_doc_counts.py:133: error: List item 15 has incompatible type "tuple[str, Pattern[Any], str, str]"; expected "tuple[str, Pattern[Any], int | tuple[int, ...], str]"  [list-item]
tools/check_doc_counts.py:134: error: List item 16 has incompatible type "tuple[str, Pattern[Any], str, str]"; expected "tuple[str, Pattern[Any], int | tuple[int, ...], str]"  [list-item]
tools/check_doc_counts.py:135: error: List item 17 has incompatible type "tuple[str, Pattern[Any], str, str]"; expected "tuple[str, Pattern[Any], int | tuple[int, ...], str]"  [list-item]
tools/check_doc_counts.py:142: error: List item 18 has incompatible type "tuple[str, Pattern[Any], str, str]"; expected "tuple[str, Pattern[Any], int | tuple[int, ...], str]"  [list-item]
tools/check_doc_counts.py:148: error: List item 19 has incompatible type "tuple[str, Pattern[Any], tuple[str, str], str]"; expected "tuple[str, Pattern[Any], int | tuple[int, ...], str]"  [list-item]
tools/check_doc_counts.py:154: error: List item 20 has incompatible type "tuple[str, Pattern[Any], tuple[str, str, str, str, str], str]"; expected "tuple[str, Pattern[Any], int | tuple[int, ...], str]"  [list-item]
tools/check_doc_counts.py:160: error: List item 21 has incompatible type "tuple[str, Pattern[Any], tuple[str, str, str, str, str], str]"; expected "tuple[str, Pattern[Any], int | tuple[int, ...], str]"  [list-item]
```

Two additional failures occur when the captured match values are used as
dictionary indexes:

```text
tools/check_doc_counts.py:198: error: Invalid index type "int" for "dict[str, int]"; expected type "str"  [index]
tools/check_doc_counts.py:202: error: Invalid index type "int" for "dict[str, int]"; expected type "str"  [index]
```

The type declaration for `CHECKS` currently says its third tuple element is an
integer or tuple of integers, but the actual values are registry-key strings
such as `"total"` and tuples of those strings. The annotation and the loop
variables should model the runtime data, for example with a type alias for a
string key or tuple of string keys.

### `tests/test_reporting_terminal.py`

```text
tests/test_reporting_terminal.py:39: error: Cannot infer type of lambda  [misc]
```

The lambda used by the test needs an explicit callable annotation or a typed
replacement function so mypy can infer its parameter and return types.

### `tests/test_sarif_report.py`

```text
tests/test_sarif_report.py:49: error: Argument 1 to "EnrichedFinding" has incompatible type "**dict[str, Sequence[object]]"; expected "str"  [arg-type]
tests/test_sarif_report.py:49: error: Argument 1 to "EnrichedFinding" has incompatible type "**dict[str, Sequence[object]]"; expected "list[int]"  [arg-type]
tests/test_sarif_report.py:49: error: Argument 1 to "EnrichedFinding" has incompatible type "**dict[str, Sequence[object]]"; expected "str | None"  [arg-type]
tests/test_sarif_report.py:49: error: Argument 1 to "EnrichedFinding" has incompatible type "**dict[str, Sequence[object]]"; expected "list[ArticleReference]"  [arg-type]
tests/test_sarif_report.py:49: error: Argument 1 to "EnrichedFinding" has incompatible type "**dict[str, Sequence[object]]"; expected "Severity"  [arg-type]
```

The test constructs `EnrichedFinding` with `**` expansion from an untyped or
inadequately typed dictionary. Replacing the expansion with named constructor
arguments, or defining a `TypedDict`/typed fixture matching `EnrichedFinding`,
will make the expected field types visible to mypy.

## Current quality-gate status

- Ruff: passes.
- Pytest: **525 passed, 7 skipped**.
- Mypy: fails with the 32 errors listed above.

The pre-commit hook therefore continues to reject a commit until mypy passes.
This report documents the failures; it does not suppress or ignore them.
