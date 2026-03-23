"""Online inference utilities for SDN DDoS detection.

This module keeps feature engineering strictly aligned with `ml/train_ddos_rf.py`.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List

import joblib
import numpy as np
import pandas as pd


@dataclass
class DetectionResult:
    src_ip: str
    dst_ip: str
    score: float
    label: int
    confidence: float


class DDoSInferenceService:
    """Load model artifacts and run online inference for flow statistics."""

    def __init__(self, model_path: str, scaler_path: str, meta_path: str):
        self.model = joblib.load(model_path)
        self.scaler = joblib.load(scaler_path)

        with open(meta_path, "r", encoding="utf-8") as f:
            self.meta = json.load(f)

        self.base_features: List[str] = self.meta["base_features"]
        self.final_features: List[str] = self.meta["final_features"]
        self.threshold: float = float(self.meta.get("threshold", 0.5))
        self.flow_duration_unit: str = self.meta.get("flow_duration_unit", "microseconds")

        if self.flow_duration_unit != "microseconds":
            raise ValueError(
                "Unsupported flow_duration_unit in meta. "
                "Expected 'microseconds' to match training pipeline."
            )

    def _ensure_base_features(self, df: pd.DataFrame) -> pd.DataFrame:
        df = df.copy()
        for feat in self.base_features:
            if feat not in df.columns:
                df[feat] = 0
        return df

    def _add_engineered_features(self, df: pd.DataFrame) -> pd.DataFrame:
        df = df.copy()

        for col in self.base_features:
            df[col] = pd.to_numeric(df[col], errors="coerce")

        df = df.replace([np.inf, -np.inf], np.nan).dropna()

        duration_us = df["Flow Duration"].clip(lower=1.0)
        duration_s = duration_us / 1_000_000.0

        fwd_pkts = df["Total Fwd Packets"].clip(lower=0.0)
        bwd_pkts = df["Total Backward Packets"].clip(lower=0.0)
        fwd_bytes = df["Total Length of Fwd Packets"].clip(lower=0.0)
        bwd_bytes = df["Total Length of Bwd Packets"].clip(lower=0.0)

        total_pkts = fwd_pkts + bwd_pkts
        total_bytes = fwd_bytes + bwd_bytes

        eps = 1e-6

        df["Total Packets"] = total_pkts
        df["Total Bytes"] = total_bytes
        df["Flow Packets/s"] = total_pkts / (duration_s + eps)
        df["Flow Bytes/s"] = total_bytes / (duration_s + eps)
        df["Fwd Packets/s"] = fwd_pkts / (duration_s + eps)
        df["Bwd Packets/s"] = bwd_pkts / (duration_s + eps)
        df["Fwd Bytes/s"] = fwd_bytes / (duration_s + eps)
        df["Bwd Bytes/s"] = bwd_bytes / (duration_s + eps)
        df["Fwd Packet Ratio"] = fwd_pkts / (total_pkts + eps)
        df["Fwd Byte Ratio"] = fwd_bytes / (total_bytes + eps)
        df["Fwd/Bwd Packet Ratio"] = fwd_pkts / (bwd_pkts + 1.0)
        df["Fwd/Bwd Byte Ratio"] = fwd_bytes / (bwd_bytes + 1.0)

        long_tail_cols = [
            "Flow Duration",
            "Total Fwd Packets",
            "Total Length of Fwd Packets",
            "Total Backward Packets",
            "Total Length of Bwd Packets",
            "Average Packet Size",
            "Total Packets",
            "Total Bytes",
            "Flow Packets/s",
            "Flow Bytes/s",
            "Fwd Packets/s",
            "Bwd Packets/s",
            "Fwd Bytes/s",
            "Bwd Bytes/s",
            "Fwd/Bwd Packet Ratio",
            "Fwd/Bwd Byte Ratio",
        ]

        for col in long_tail_cols:
            df[col] = np.log1p(df[col].clip(lower=0.0))

        return df

    def preprocess(self, flows: Iterable[Dict[str, Any]]) -> pd.DataFrame:
        df = pd.DataFrame(flows)
        if df.empty:
            return df

        df.columns = df.columns.str.strip()
        df = self._ensure_base_features(df)
        df = self._add_engineered_features(df)
        return df

    def predict(self, flows: Iterable[Dict[str, Any]]) -> List[DetectionResult]:
        source_df = pd.DataFrame(flows)
        feat_df = self.preprocess(flows)
        if feat_df.empty:
            return []

        x = feat_df[self.final_features]
        x_scaled = self.scaler.transform(x)
        scores = self.model.predict_proba(x_scaled)[:, 1]
        labels = (scores >= self.threshold).astype(int)

        results: List[DetectionResult] = []
        feat_index = feat_df.index

        for i, idx in enumerate(feat_index):
            row = source_df.loc[idx]
            score = float(scores[i])
            label = int(labels[i])
            confidence = score if label == 1 else 1.0 - score

            results.append(
                DetectionResult(
                    src_ip=str(row.get("src_ip", "Unknown")),
                    dst_ip=str(row.get("dst_ip", "Unknown")),
                    score=score,
                    label=label,
                    confidence=float(confidence),
                )
            )

        return results


def load_service_from_artifacts(artifacts_dir: str | Path) -> DDoSInferenceService:
    artifacts_dir = Path(artifacts_dir)
    return DDoSInferenceService(
        model_path=str(artifacts_dir / "ddos_final_model.pkl"),
        scaler_path=str(artifacts_dir / "final_scaler.pkl"),
        meta_path=str(artifacts_dir / "model_meta.json"),
    )
