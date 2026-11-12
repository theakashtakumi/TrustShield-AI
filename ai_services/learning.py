"""Metrics for curated, partitioned labels. No training or auto-labeling occurs."""

from __future__ import annotations

from collections import defaultdict


POSITIVE_LABELS = {"confirmed malicious activity"}
NEGATIVE_LABELS = {"legitimate business"}
ELIGIBLE = POSITIVE_LABELS | NEGATIVE_LABELS


def evaluate_predictions(records):
    """Compute binary metrics only for explicit, reviewable positive/negative pairs."""
    groups = defaultdict(list)
    all_rows = []
    seen = set()
    excluded = 0
    for row in records:
        case_id = row.get("case_id")
        if case_id in seen:
            excluded += 1
            continue
        seen.add(case_id)
        label = str(row.get("label", "")).casefold()
        prediction = row.get("prediction")
        if label not in ELIGIBLE or prediction not in {"suspicious_indicators", "no_clear_indicators"}:
            excluded += 1
            continue
        actual = label in POSITIVE_LABELS
        predicted = prediction == "suspicious_indicators"
        values = (actual, predicted)
        groups[str(row.get("category", "unknown"))].append(values)
        all_rows.append(values)
    return {"overall": _metrics(all_rows), "by_category": {key: _metrics(values) for key, values in sorted(groups.items())},
            "eligible_cases": len(all_rows), "excluded_cases": excluded,
            "limitations": "Metrics apply only to explicitly curated binary labels. Disputed, unresolved, insufficient-evidence, and duplicate cases are excluded."}


def _metrics(rows):
    tp = sum(1 for actual, predicted in rows if actual and predicted)
    tn = sum(1 for actual, predicted in rows if not actual and not predicted)
    fp = sum(1 for actual, predicted in rows if not actual and predicted)
    fn = sum(1 for actual, predicted in rows if actual and not predicted)
    count = len(rows)
    return {"true_positive": tp, "true_negative": tn, "false_positive": fp, "false_negative": fn,
            "precision": _ratio(tp, tp + fp), "recall": _ratio(tp, tp + fn),
            "false_positive_rate": _ratio(fp, fp + tn), "false_negative_rate": _ratio(fn, fn + tp),
            "accuracy": _ratio(tp + tn, count), "sample_count": count}


def _ratio(numerator, denominator):
    return round(numerator / denominator, 4) if denominator else None
