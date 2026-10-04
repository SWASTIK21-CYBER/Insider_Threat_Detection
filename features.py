"""Feature engineering + per-user behavioural baselines (the 'UBA' part)."""
import numpy as np
import pandas as pd

RAW_FEATURES = [
    "n_events", "n_files", "file_mb", "n_usb", "usb_mb",
    "n_ext_emails", "ext_email_mb", "n_uploads", "upload_mb",
    "after_hours_events", "first_hour", "last_hour", "n_pcs",
]


def build_features(events: pd.DataFrame) -> pd.DataFrame:
    """Aggregate raw log events into one row per (user, day)."""
    df = events.copy()
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df["date"] = df["timestamp"].dt.normalize()
    df["hour"] = df["timestamp"].dt.hour + df["timestamp"].dt.minute / 60
    et = df["event_type"]

    df["is_file"] = (et == "file_access").astype(int)
    df["is_usb"] = (et == "usb_connect").astype(int)
    df["is_upload"] = (et == "http_upload").astype(int)
    df["is_ext_email"] = ((et == "email") & (df["external"] == 1)).astype(int)
    df["after_hours"] = (((df["hour"] < 7) | (df["hour"] >= 19)) & (et != "logoff")).astype(int)
    df["file_mb"] = df["size_mb"] * df["is_file"]
    df["usb_mb"] = df["size_mb"] * df["is_usb"]
    df["ext_email_mb"] = df["size_mb"] * df["is_ext_email"]
    df["upload_mb"] = df["size_mb"] * df["is_upload"]

    feats = df.groupby(["user", "date"]).agg(
        n_events=("event_type", "size"),
        n_files=("is_file", "sum"),
        file_mb=("file_mb", "sum"),
        n_usb=("is_usb", "sum"),
        usb_mb=("usb_mb", "sum"),
        n_ext_emails=("is_ext_email", "sum"),
        ext_email_mb=("ext_email_mb", "sum"),
        n_uploads=("is_upload", "sum"),
        upload_mb=("upload_mb", "sum"),
        after_hours_events=("after_hours", "sum"),
        first_hour=("hour", "min"),
        last_hour=("hour", "max"),
        n_pcs=("pc", "nunique"),
    ).reset_index()
    feats["is_weekend"] = (feats["date"].dt.dayofweek >= 5).astype(int)
    return feats


def add_baseline_zscores(feats: pd.DataFrame, baseline_end: pd.Timestamp) -> pd.DataFrame:
    """z-score every feature against THAT USER's own behaviour before `baseline_end`.

    A file download of 500 MB is normal for one person and a red flag for another -
    comparing each user with their own history is the core idea of UBA.
    """
    base = feats[feats["date"] < baseline_end]
    mu = base.groupby("user")[RAW_FEATURES].mean()
    sd = base.groupby("user")[RAW_FEATURES].std().fillna(0)
    sd = np.maximum(sd, 0.25 * mu.abs() + 1.0)          # floor avoids divide-by-~0 blow-ups
    z = (feats[RAW_FEATURES].values - mu.loc[feats["user"]].values) / sd.loc[feats["user"]].values
    z = np.clip(z, -50, 50)
    zdf = pd.DataFrame(z, columns=[f"z_{c}" for c in RAW_FEATURES], index=feats.index)
    return pd.concat([feats, zdf], axis=1)
