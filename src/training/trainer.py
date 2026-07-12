"""
End-to-end training pipeline.

Orchestrates: data generation → preprocessing → model training → evaluation →
artifact persistence → report generation. Idempotent and safe to re-run.
"""

from __future__ import annotations

import json
import time
from dataclasses import asdict
from pathlib import Path
from typing import Optional

import numpy as np

from ..data import CLASS_NAMES, FEATURE_NAMES, Preprocessor, load_or_generate
from ..models import (
    EnsembleNIDS,
    IsolationForest,
    MLPClassifier,
    RandomForestClassifier,
)
from ..utils import get_logger, metrics
from ..utils.config import Config

logger = get_logger(__name__)


class TrainingPipeline:
    """Runs the full training workflow and writes artifacts to disk."""

    def __init__(self, config: Config) -> None:
        self.config = config
        self.models_dir = Path(config.paths.models_dir)
        self.reports_dir = Path(config.paths.reports_dir)
        self.models_dir.mkdir(parents=True, exist_ok=True)
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        self.metrics_report: dict = {}

    # ------------------------------------------------------------------
    def run(self) -> dict:
        t0 = time.time()
        logger.info("Training pipeline starting")

        # 1) Data
        X, y, feature_names, class_names = load_or_generate(
            self.config.data.dataset_path,
            n_samples=self.config.data.n_samples,
            random_state=self.config.data.random_state,
        )
        logger.info("Loaded dataset: %d samples, %d features", X.shape[0], X.shape[1])

        # 2) Split
        pre = Preprocessor(feature_names=feature_names, top_k_features=None)
        X_tr, y_tr, X_val, y_val, X_te, y_te = pre.stratified_split(
            X, y,
            test_size=self.config.data.test_size,
            val_size=self.config.data.val_size,
            random_state=self.config.data.random_state,
        )
        logger.info("Split sizes: train=%d val=%d test=%d", len(y_tr), len(y_val), len(y_te))

        # 3) Fit preprocessor on train only
        pre.fit(X_tr, y_tr)
        X_tr_s = pre.transform(X_tr)
        X_val_s = pre.transform(X_val)
        X_te_s = pre.transform(X_te)
        pre_path = self.models_dir / "preprocessor.pkl"
        pre.save(pre_path)
        logger.info("Preprocessor saved to %s", pre_path)

        # 4) Train Random Forest
        rf_cfg = self.config.model
        logger.info(
            "Training RandomForest (trees=%d, max_depth=%d)",
            rf_cfg.rf_n_estimators, rf_cfg.rf_max_depth,
        )
        rf = RandomForestClassifier(
            n_estimators=rf_cfg.rf_n_estimators,
            max_depth=rf_cfg.rf_max_depth,
            min_samples_leaf=rf_cfg.rf_min_samples_leaf,
            n_jobs=rf_cfg.rf_n_jobs,
            random_state=self.config.data.random_state,
            oob_score=True,
            verbose=False,
        )
        rf.fit(X_tr_s, y_tr)
        logger.info(
            "RF trained in %.1fs. OOB=%.4f",
            rf.training_time_, rf.oob_score_ or float("nan"),
        )
        rf.save(self.models_dir / "random_forest.pkl")

        # 5) Train MLP
        logger.info("Training MLP (hidden=%s)", rf_cfg.mlp_hidden_layers)
        mlp = MLPClassifier(
            hidden_layers=tuple(rf_cfg.mlp_hidden_layers),
            epochs=rf_cfg.mlp_epochs,
            learning_rate=rf_cfg.mlp_learning_rate,
            batch_size=rf_cfg.mlp_batch_size,
            dropout=rf_cfg.mlp_dropout,
            l2_reg=rf_cfg.mlp_l2_reg,
            random_state=self.config.data.random_state,
            verbose=False,
        )
        mlp.fit(X_tr_s, y_tr, X_val=X_val_s, y_val=y_val)
        logger.info("MLP trained in %.1fs", mlp.training_time_)
        mlp.save(self.models_dir / "mlp.pkl")

        # 6) Train Isolation Forest on BENIGN only
        logger.info("Training IsolationForest on benign traffic")
        benign_mask = y_tr == 0
        iso = IsolationForest(
            n_estimators=rf_cfg.iso_n_estimators,
            subsample_size=rf_cfg.iso_subsample_size,
            contamination=rf_cfg.iso_contamination,
            random_state=self.config.data.random_state,
        )
        iso.fit(X_tr_s[benign_mask])
        logger.info("IF trained in %.1fs", iso.training_time_)
        import pickle
        with open(self.models_dir / "isolation_forest.pkl", "wb") as f:
            pickle.dump(iso, f, protocol=pickle.HIGHEST_PROTOCOL)

        # 7) Assemble ensemble
        ensemble = EnsembleNIDS(
            rf=rf, mlp=mlp, iso=iso,
            rf_weight=rf_cfg.ensemble_rf_weight,
            mlp_weight=rf_cfg.ensemble_mlp_weight,
            anomaly_boost=rf_cfg.ensemble_anomaly_boost,
        )
        ensemble.is_fitted = True
        ensemble.n_features_ = X_tr_s.shape[1]
        ensemble.classes_ = np.unique(y_tr)
        ensemble.n_classes_ = int(ensemble.classes_.max()) + 1
        ensemble.save(self.models_dir / "ensemble.pkl")

        # 8) Evaluate all models on the test set
        report = self._evaluate_all(rf, mlp, iso, ensemble, X_te_s, y_te, class_names)
        report["total_training_time_sec"] = round(time.time() - t0, 2)
        report["dataset_size"] = int(X.shape[0])
        report["feature_count"] = int(X.shape[1])

        # 9) Save metrics report
        metrics_path = self.reports_dir / "training_metrics.json"
        with open(metrics_path, "w") as f:
            json.dump(report, f, indent=2)
        logger.info("Saved metrics report to %s", metrics_path)

        self.metrics_report = report
        logger.info("Pipeline complete in %.1fs", report["total_training_time_sec"])
        return report

    # ------------------------------------------------------------------
    def _evaluate_all(
        self,
        rf: RandomForestClassifier,
        mlp: MLPClassifier,
        iso: IsolationForest,
        ensemble: EnsembleNIDS,
        X_te: np.ndarray,
        y_te: np.ndarray,
        class_names: list[str],
    ) -> dict:
        report: dict = {"test_size": int(len(y_te)), "class_names": class_names, "models": {}}

        for name, model in (("random_forest", rf), ("mlp", mlp), ("ensemble", ensemble)):
            t0 = time.time()
            preds = model.predict(X_te)
            latency_ms = (time.time() - t0) / max(1, len(y_te)) * 1000
            rpt = metrics.precision_recall_f1(y_te, preds)
            acc = metrics.accuracy(y_te, preds)
            fpr = metrics.false_positive_rate(y_te, preds)
            fnr = metrics.false_negative_rate(y_te, preds)
            dr = metrics.detection_rate(y_te, preds)
            report["models"][name] = {
                "accuracy": acc,
                "macro_f1": rpt["macro"]["f1"],
                "weighted_f1": rpt["weighted"]["f1"],
                "false_positive_rate": fpr,
                "false_negative_rate": fnr,
                "detection_rate": dr,
                "per_class": rpt["per_class"],
                "confusion_matrix": rpt["confusion_matrix"],
                "avg_latency_ms_per_sample": round(latency_ms, 3),
                "training_time_sec": round(getattr(model, "training_time_", 0.0), 2),
            }
            logger.info(
                "%s | accuracy=%.4f macro_f1=%.4f FPR=%.4f FNR=%.4f DR=%.4f",
                name, acc, rpt["macro"]["f1"], fpr, fnr, dr,
            )

        # Isolation Forest: binary benign vs anomaly evaluation
        y_bin = (y_te != 0).astype(np.int64)  # 1 = attack
        iso_pred = iso.is_anomaly(X_te).astype(np.int64)
        iso_rpt = metrics.precision_recall_f1(y_bin, iso_pred, n_classes=2)
        iso_scores = iso.anomaly_score(X_te)
        iso_auc = metrics.roc_auc_binary(y_bin, iso_scores)
        report["models"]["isolation_forest"] = {
            "accuracy": metrics.accuracy(y_bin, iso_pred),
            "binary_f1": iso_rpt["per_class"][1]["f1"],
            "roc_auc": iso_auc,
            "confusion_matrix": iso_rpt["confusion_matrix"],
            "training_time_sec": round(iso.training_time_, 2),
        }
        logger.info(
            "isolation_forest | accuracy=%.4f binary_F1=%.4f AUC=%.4f",
            report["models"]["isolation_forest"]["accuracy"],
            iso_rpt["per_class"][1]["f1"],
            iso_auc,
        )
        return report
