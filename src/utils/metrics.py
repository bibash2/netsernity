"""
Classification metrics — implemented from scratch.

Precision, recall, F1, confusion matrix, ROC-AUC, PR-AUC.
Only uses NumPy; written to match the mathematical definitions so results
are reproducible and auditable without pulling in scikit-learn.
"""

from __future__ import annotations

from typing import Optional

import numpy as np


def confusion_matrix(y_true: np.ndarray, y_pred: np.ndarray, n_classes: Optional[int] = None) -> np.ndarray:
    """Return an (n_classes x n_classes) matrix where entry [i, j] is the number
    of samples with true label i and predicted label j."""
    y_true = np.asarray(y_true, dtype=np.int64)
    y_pred = np.asarray(y_pred, dtype=np.int64)
    if n_classes is None:
        n_classes = int(max(y_true.max(), y_pred.max())) + 1
    cm = np.zeros((n_classes, n_classes), dtype=np.int64)
    for t, p in zip(y_true, y_pred):
        cm[int(t), int(p)] += 1
    return cm


def accuracy(y_true: np.ndarray, y_pred: np.ndarray) -> float:
    return float(np.mean(np.asarray(y_true) == np.asarray(y_pred)))


def precision_recall_f1(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    n_classes: Optional[int] = None,
    average: str = "macro",
) -> dict:
    """Compute precision, recall, F1 per class plus macro/micro/weighted averages.

    Returns a dict with keys: per_class, macro, micro, weighted.
    """
    cm = confusion_matrix(y_true, y_pred, n_classes=n_classes)
    n_cls = cm.shape[0]

    per_class = {}
    precisions = np.zeros(n_cls)
    recalls = np.zeros(n_cls)
    f1s = np.zeros(n_cls)
    supports = cm.sum(axis=1)

    for c in range(n_cls):
        tp = cm[c, c]
        fp = cm[:, c].sum() - tp
        fn = cm[c, :].sum() - tp
        prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0.0
        per_class[c] = {"precision": float(prec), "recall": float(rec), "f1": float(f1), "support": int(supports[c])}
        precisions[c] = prec
        recalls[c] = rec
        f1s[c] = f1

    total_support = supports.sum()
    macro = {
        "precision": float(precisions.mean()),
        "recall": float(recalls.mean()),
        "f1": float(f1s.mean()),
    }
    weighted = {
        "precision": float(np.sum(precisions * supports) / total_support) if total_support > 0 else 0.0,
        "recall": float(np.sum(recalls * supports) / total_support) if total_support > 0 else 0.0,
        "f1": float(np.sum(f1s * supports) / total_support) if total_support > 0 else 0.0,
    }
    # Micro == accuracy for multiclass single-label classification
    micro_f1 = accuracy(y_true, y_pred)
    micro = {"precision": micro_f1, "recall": micro_f1, "f1": micro_f1}

    return {
        "per_class": per_class,
        "macro": macro,
        "micro": micro,
        "weighted": weighted,
        "confusion_matrix": cm.tolist(),
    }


def roc_auc_binary(y_true: np.ndarray, y_score: np.ndarray) -> float:
    """Compute ROC AUC for binary classification via the trapezoidal rule."""
    y_true = np.asarray(y_true).astype(np.int64)
    y_score = np.asarray(y_score).astype(np.float64)
    if len(np.unique(y_true)) < 2:
        return float("nan")

    order = np.argsort(-y_score)
    y_sorted = y_true[order]

    # Build TPR/FPR curves by stepping thresholds high->low
    total_pos = int(np.sum(y_sorted == 1))
    total_neg = int(np.sum(y_sorted == 0))
    if total_pos == 0 or total_neg == 0:
        return float("nan")

    tps = np.cumsum(y_sorted == 1)
    fps = np.cumsum(y_sorted == 0)
    tpr = tps / total_pos
    fpr = fps / total_neg

    # Prepend (0,0)
    tpr = np.concatenate([[0.0], tpr])
    fpr = np.concatenate([[0.0], fpr])

    # Trapezoidal integration — np.trapezoid in NumPy 2.x, np.trapz in 1.x
    trapezoid = getattr(np, "trapezoid", None) or np.trapz  # type: ignore[attr-defined]
    auc = float(trapezoid(tpr, fpr))
    return auc


def classification_report(y_true: np.ndarray, y_pred: np.ndarray, labels: Optional[list] = None) -> str:
    """Pretty printed metrics table."""
    report = precision_recall_f1(y_true, y_pred)
    lines = ["Classification Report", "=" * 70]
    header = f"{'class':<15} {'precision':>10} {'recall':>10} {'f1':>10} {'support':>10}"
    lines.append(header)
    lines.append("-" * 70)
    for c, vals in report["per_class"].items():
        name = labels[c] if labels and c < len(labels) else f"class_{c}"
        lines.append(
            f"{name:<15} {vals['precision']:>10.4f} {vals['recall']:>10.4f} "
            f"{vals['f1']:>10.4f} {vals['support']:>10}"
        )
    lines.append("-" * 70)
    lines.append(
        f"{'macro avg':<15} {report['macro']['precision']:>10.4f} "
        f"{report['macro']['recall']:>10.4f} {report['macro']['f1']:>10.4f}"
    )
    lines.append(
        f"{'weighted avg':<15} {report['weighted']['precision']:>10.4f} "
        f"{report['weighted']['recall']:>10.4f} {report['weighted']['f1']:>10.4f}"
    )
    lines.append(f"{'accuracy':<15} {report['micro']['f1']:>10.4f}")
    return "\n".join(lines)
