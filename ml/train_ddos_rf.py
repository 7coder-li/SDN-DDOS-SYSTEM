import argparse
import glob
import json
import os
import warnings

import joblib
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    auc,
    average_precision_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_curve,
)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import RobustScaler

warnings.filterwarnings("ignore")

BASE_FEATURES = [
    "Protocol",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Length of Fwd Packets",
    "Total Backward Packets",
    "Total Length of Bwd Packets",
    "Average Packet Size",
]

FINAL_FEATURES = [
    "Protocol",
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
    "Fwd Packet Ratio",
    "Fwd Byte Ratio",
    "Fwd/Bwd Packet Ratio",
    "Fwd/Bwd Byte Ratio",
]


def standardize_columns(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df.columns = df.columns.str.strip()

    rename_map = {
        "Fwd Packets Length Total": "Total Length of Fwd Packets",
        "Packet Length Mean": "Average Packet Size",
        "Fwd Packet Length Mean": "Average Packet Size",
        "Bwd Packets Total": "Total Backward Packets",
        "Bwd Packets Length Total": "Total Length of Bwd Packets",
    }

    for old_name, new_name in rename_map.items():
        if old_name in df.columns and new_name not in df.columns:
            df.rename(columns={old_name: new_name}, inplace=True)

    return df


def ensure_base_features(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    for feat in BASE_FEATURES:
        if feat not in df.columns:
            df[feat] = 0
    return df


def add_engineered_features(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()

    for col in BASE_FEATURES:
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


def pick_best_threshold(y_true: np.ndarray, y_score: np.ndarray, beta: float = 2.0) -> float:
    precisions, recalls, thresholds = precision_recall_curve(y_true, y_score)

    best_threshold = 0.5
    best_score = -1.0

    for i, th in enumerate(thresholds):
        p = precisions[i]
        r = recalls[i]
        denom = beta**2 * p + r
        if denom == 0:
            continue
        fbeta = (1 + beta**2) * p * r / denom
        if fbeta > best_score:
            best_score = fbeta
            best_threshold = th

    return float(best_threshold)


def get_attack_data(train_attack_path: str, test_attack_path: str, cache_path: str, target_samples: int) -> pd.DataFrame:
    if os.path.exists(cache_path):
        print(f"[+] 发现攻击缓存 {cache_path}，直接加载")
        attack_df = pd.read_parquet(cache_path)
        if len(attack_df) > target_samples:
            attack_df = attack_df.sample(n=target_samples, random_state=42)
        return attack_df

    print(f"[!] 未发现缓存，开始扫描攻击 CSV，目标样本数 {target_samples}")
    all_files = glob.glob(os.path.join(train_attack_path, "*.csv")) + glob.glob(
        os.path.join(test_attack_path, "*.csv")
    )
    attack_list = []

    for file in all_files:
        print(f"  - 扫描 {os.path.basename(file)}")
        try:
            for chunk in pd.read_csv(file, chunksize=200000, low_memory=False):
                chunk.columns = chunk.columns.str.strip()
                if "Label" not in chunk.columns:
                    continue

                is_benign = chunk["Label"].astype(str).str.strip().str.upper() == "BENIGN"
                a_chunk = chunk[~is_benign]

                if not a_chunk.empty:
                    attack_list.append(a_chunk)

                cur_len = sum(len(df) for df in attack_list)
                if cur_len > target_samples * 1.15:
                    break
        except Exception:
            continue

        cur_len = sum(len(df) for df in attack_list)
        if cur_len > target_samples * 1.15:
            print("  => 攻击样本收集充足，提前结束")
            break

    if not attack_list:
        raise RuntimeError("未从 CSV 中提取到任何攻击样本，请检查数据路径与标签列。")

    attack_df = pd.concat(attack_list, ignore_index=True)

    if len(attack_df) > target_samples:
        attack_df = attack_df.sample(n=target_samples, random_state=42)

    for col in attack_df.select_dtypes(include=["object"]).columns:
        attack_df[col] = attack_df[col].astype(str)

    attack_df.to_parquet(cache_path, index=False)
    print(f"[+] 攻击样本已缓存至 {cache_path}")
    return attack_df


def evaluate_and_plot(y_true, y_pred, y_score, model, feature_names, output_dir: str):
    print("\n" + "=" * 60)
    print("改进版随机森林：跨数据集验证报告")
    print("=" * 60)
    print(classification_report(y_true, y_pred, target_names=["Benign", "Attack"], digits=4))
    print(f"Precision: {precision_score(y_true, y_pred):.4f}")
    print(f"Recall   : {recall_score(y_true, y_pred):.4f}")
    print(f"F1-score : {f1_score(y_true, y_pred):.4f}")
    print(f"PR-AUC   : {average_precision_score(y_true, y_score):.4f}")

    sns.set_theme(style="whitegrid")

    cm_path = os.path.join(output_dir, "thesis_confusion_matrix.png")
    roc_path = os.path.join(output_dir, "thesis_roc_curve.png")
    fi_path = os.path.join(output_dir, "thesis_feature_importance.png")

    plt.figure(figsize=(8, 6))
    cm = confusion_matrix(y_true, y_pred)
    sns.heatmap(cm, annot=True, fmt="d", cmap="Blues", xticklabels=["Benign", "Attack"], yticklabels=["Benign", "Attack"])
    plt.title("Confusion Matrix (Improved RF)")
    plt.ylabel("True Label")
    plt.xlabel("Predicted Label")
    plt.tight_layout()
    plt.savefig(cm_path, dpi=300)
    plt.close()

    plt.figure(figsize=(8, 6))
    fpr, tpr, _ = roc_curve(y_true, y_score)
    roc_auc = auc(fpr, tpr)
    plt.plot(fpr, tpr, lw=2, label=f"ROC curve (AUC = {roc_auc:.4f})")
    plt.plot([0, 1], [0, 1], linestyle="--", lw=2)
    plt.xlabel("False Positive Rate")
    plt.ylabel("True Positive Rate")
    plt.title("ROC Curve")
    plt.legend(loc="lower right")
    plt.tight_layout()
    plt.savefig(roc_path, dpi=300)
    plt.close()

    plt.figure(figsize=(10, 7))
    importances = model.feature_importances_
    indices = np.argsort(importances)[::-1]
    sorted_features = [feature_names[i] for i in indices]
    sns.barplot(x=importances[indices], y=sorted_features, palette="viridis")
    plt.title("Feature Importance (Improved RF)")
    plt.xlabel("Relative Importance")
    plt.tight_layout()
    plt.savefig(fi_path, dpi=300)
    plt.close()


def main():
    parser = argparse.ArgumentParser(description="Train RF detector using CIC-IDS2017 benign + CIC-DDoS2019 attack")
    parser.add_argument("--benign-parquet", required=True)
    parser.add_argument("--train-attack-path", required=True)
    parser.add_argument("--test-attack-path", required=True)
    parser.add_argument("--attack-cache-path", default="Attack_2019_ALL_FEATURES.parquet")
    parser.add_argument("--output-dir", default="artifacts")
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)

    model_path = os.path.join(args.output_dir, "ddos_final_model.pkl")
    scaler_path = os.path.join(args.output_dir, "final_scaler.pkl")
    meta_path = os.path.join(args.output_dir, "model_meta.json")

    print("[1/4] 加载正常流量 (CIC-IDS-2017)")
    benign_df = pd.read_parquet(args.benign_parquet)
    benign_df = standardize_columns(benign_df)
    benign_df = ensure_base_features(benign_df)
    benign_df["Label"] = 0

    print("[2/4] 加载攻击流量 (CIC-DDoS2019)")
    attack_df = get_attack_data(
        train_attack_path=args.train_attack_path,
        test_attack_path=args.test_attack_path,
        cache_path=args.attack_cache_path,
        target_samples=len(benign_df),
    )
    attack_df = standardize_columns(attack_df)
    attack_df = ensure_base_features(attack_df)
    attack_df["Label"] = 1

    print("[3/4] 特征工程")
    benign_df = benign_df[BASE_FEATURES + ["Label"]].replace([np.inf, -np.inf], np.nan).dropna()
    attack_df = attack_df[BASE_FEATURES + ["Label"]].replace([np.inf, -np.inf], np.nan).dropna()

    full_df = pd.concat([benign_df, attack_df], ignore_index=True).sample(frac=1, random_state=42)
    full_df = add_engineered_features(full_df)

    X = full_df[FINAL_FEATURES]
    y = full_df["Label"].astype(int)

    X_train, X_temp, y_train, y_temp = train_test_split(X, y, test_size=0.30, random_state=42, stratify=y)
    X_val, X_test, y_val, y_test = train_test_split(X_temp, y_temp, test_size=0.50, random_state=42, stratify=y_temp)

    print(f"Train={len(X_train)}, Val={len(X_val)}, Test={len(X_test)}")

    print("[4/4] 训练模型")
    scaler = RobustScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_val_scaled = scaler.transform(X_val)
    X_test_scaled = scaler.transform(X_test)

    model = RandomForestClassifier(
        n_estimators=400,
        max_depth=18,
        min_samples_split=8,
        min_samples_leaf=2,
        max_features="sqrt",
        class_weight="balanced_subsample",
        n_jobs=-1,
        random_state=42,
    )
    model.fit(X_train_scaled, y_train)

    val_score = model.predict_proba(X_val_scaled)[:, 1]
    best_threshold = pick_best_threshold(y_val.values, val_score)
    print(f"[+] 最佳阈值: {best_threshold:.4f}")

    test_score = model.predict_proba(X_test_scaled)[:, 1]
    test_pred = (test_score >= best_threshold).astype(int)

    evaluate_and_plot(y_test.values, test_pred, test_score, model, FINAL_FEATURES, args.output_dir)

    joblib.dump(model, model_path)
    joblib.dump(scaler, scaler_path)

    meta = {
        "base_features": BASE_FEATURES,
        "final_features": FINAL_FEATURES,
        "threshold": best_threshold,
        "flow_duration_unit": "microseconds",
        "model_type": "RandomForestClassifier",
        "notes": "Use the same engineered features online before inference.",
    }
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(meta, f, ensure_ascii=False, indent=2)

    print(f"🎉 模型保存: {model_path}")
    print(f"🎉 标准化器保存: {scaler_path}")
    print(f"🎉 元数据保存: {meta_path}")


if __name__ == "__main__":
    main()
