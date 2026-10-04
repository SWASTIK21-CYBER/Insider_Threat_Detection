"""Step 2 - Train the anomaly detector, score every user-day, raise alerts, make charts."""
from pathlib import Path
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from sklearn.ensemble import IsolationForest
from sklearn.metrics import classification_report, confusion_matrix

from features import RAW_FEATURES, add_baseline_zscores, build_features

ROOT = Path(__file__).parent
OUT = ROOT / "output"
OUT.mkdir(exist_ok=True)

BASELINE_DAYS = 30      # first 30 days define each user's "normal"
TRAIN_DAYS = 45         # model is trained on days 0-44 (assumed clean)
ALERT_QUANTILE = 0.995  # alert threshold = 99.5th percentile of training scores

events = pd.read_csv(ROOT / "data" / "events.csv")
labels = pd.read_csv(ROOT / "data" / "labels.csv", parse_dates=["date"])

feats = build_features(events)
start = feats["date"].min()
feats = add_baseline_zscores(feats, start + pd.Timedelta(days=BASELINE_DAYS))
feats = feats.merge(labels, on=["user", "date"], how="left")

Z_COLS = [f"z_{c}" for c in RAW_FEATURES]
MODEL_COLS = Z_COLS + ["is_weekend"]
train_mask = feats["date"] < start + pd.Timedelta(days=TRAIN_DAYS)

model = IsolationForest(n_estimators=300, random_state=42, n_jobs=-1)
model.fit(feats.loc[train_mask, MODEL_COLS])

feats["anomaly_score"] = -model.score_samples(feats[MODEL_COLS])   # higher = weirder
threshold = np.quantile(feats.loc[train_mask, "anomaly_score"], ALERT_QUANTILE)
lo, hi = feats["anomaly_score"].min(), feats["anomaly_score"].max()
feats["risk_score"] = (100 * (feats["anomaly_score"] - lo) / (hi - lo)).round(1)
feats["alert"] = (feats["anomaly_score"] > threshold).astype(int)


def explain(row):
    z = row[Z_COLS].astype(float)
    top = z[z.abs() > 3].abs().sort_values(ascending=False).head(3).index
    return "; ".join(f"{c[2:]} ({z[c]:+.1f} sd)" for c in top) or "overall unusual pattern"


feats["reason"] = ""
alerts_idx = feats.index[feats["alert"] == 1]
feats.loc[alerts_idx, "reason"] = feats.loc[alerts_idx].apply(explain, axis=1)

feats.to_csv(OUT / "scored_user_days.csv", index=False)
alerts = feats[feats["alert"] == 1].sort_values("risk_score", ascending=False)
alerts[["user", "date", "risk_score", "reason", "is_malicious"]].to_csv(OUT / "alerts.csv", index=False)

# ---------------- evaluation (test period only = days the model never saw) -------------
test = feats[~train_mask]
print("\n=== Evaluation on unseen days (days 45-59) ===")
print(classification_report(test["is_malicious"], test["alert"],
                            target_names=["normal", "malicious"], zero_division=0))
print("Confusion matrix [[TN FP],[FN TP]]:\n", confusion_matrix(test["is_malicious"], test["alert"]))
false_alarms_train = int(feats.loc[train_mask, "alert"].sum())
print(f"Alerts inside the clean training window (sanity check): {false_alarms_train}")

print("\n=== Top alerts ===")
print(alerts[["user", "date", "risk_score", "reason"]].head(12).to_string(index=False))

by_user = alerts.groupby("user").size().sort_values(ascending=False)
print("\n=== Users ranked by number of alerts ===")
print(by_user.head(8).to_string())

# ---------------- charts ----------------
top = by_user.head(10)
plt.figure(figsize=(8, 4))
plt.bar(top.index, top.values, color="#c0392b")
plt.title("Users with most insider-threat alerts")
plt.ylabel("Number of alerts")
plt.xticks(rotation=45)
plt.tight_layout()
plt.savefig(OUT / "top_users.png", dpi=130)
plt.close()

plt.figure(figsize=(10, 4.5))
avg = feats.groupby("date")["risk_score"].mean()
plt.plot(avg.index, avg.values, color="grey", lw=2, label="average of all users")
for u in by_user.head(4).index:
    s = feats[feats["user"] == u].set_index("date")["risk_score"]
    plt.plot(s.index, s.values, marker="o", ms=3, lw=1, label=u)
plt.axvline(start + pd.Timedelta(days=TRAIN_DAYS), ls="--", color="k", alpha=.5)
plt.text(start + pd.Timedelta(days=TRAIN_DAYS + .3), plt.ylim()[1] * .9, "unseen period", fontsize=8)
plt.title("Daily risk score - flagged users vs. everyone else")
plt.ylabel("Risk score (0-100)")
plt.legend(fontsize=8)
plt.tight_layout()
plt.savefig(OUT / "risk_timeline.png", dpi=130)
plt.close()
print(f"\nSaved: {OUT/'alerts.csv'}, scored_user_days.csv, top_users.png, risk_timeline.png")
