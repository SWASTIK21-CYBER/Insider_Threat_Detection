"""Step 1 - Generate synthetic enterprise activity logs with injected insider threats.

Creates:
  data/events.csv  - raw logs (logon, logoff, file_access, email, usb_connect, http_upload)
  data/labels.csv  - ground truth per user-day (ONLY used to evaluate the model)
"""
from pathlib import Path
import numpy as np
import pandas as pd

SEED = 42
N_USERS = 50
N_DAYS = 60
START = pd.Timestamp("2026-07-06")   # a Monday
ATTACK_START_DAY = 45                # insiders turn malicious from this day on

INSIDERS = {
    "user07": "mass_download_usb",   # night logon + mass file access + USB copy
    "user19": "external_exfil",      # big attachments to external mail + uploads
    "user33": "night_usb",           # night logon + USB copy
    "user42": "weekend_hoarder",     # weekend work + mass file access + external mail
}

rng = np.random.default_rng(SEED)
events = []


def add(ts, user, etype, pc, size_mb=0.0, external=0):
    events.append((ts, user, etype, pc, round(float(size_mb), 3), int(external)))


def at(day, hour):
    return day + pd.Timedelta(hours=float(hour))


def normal_day(user, pc, day, start_h):
    end_h = min(start_h + rng.normal(8, 0.7), 20.0)
    add(at(day, start_h), user, "logon", pc)
    for _ in range(rng.poisson(12)):
        add(at(day, rng.uniform(start_h, end_h)), user, "file_access", pc, rng.lognormal(-1, 0.8))
    for _ in range(rng.poisson(15)):
        ext = rng.random() < 0.08
        add(at(day, rng.uniform(start_h, end_h)), user, "email", pc, rng.exponential(0.3), ext)
    for _ in range(rng.poisson(0.5)):
        add(at(day, rng.uniform(start_h, end_h)), user, "http_upload", pc, rng.exponential(0.5))
    if rng.random() < 0.01:
        add(at(day, rng.uniform(start_h, end_h)), user, "usb_connect", pc, rng.uniform(1, 20))
    add(at(day, end_h), user, "logoff", pc)


def attack_events(user, pc, day, scenario):
    if scenario == "mass_download_usb":
        h0 = rng.uniform(21, 22.5)
        add(at(day, h0), user, "logon", pc)
        for _ in range(rng.poisson(150)):
            add(at(day, rng.uniform(h0, 23.9)), user, "file_access", pc, rng.lognormal(1.0, 0.7))
        for _ in range(rng.integers(1, 4)):
            add(at(day, rng.uniform(h0, 23.9)), user, "usb_connect", pc, rng.uniform(200, 800))
    elif scenario == "external_exfil":
        for _ in range(rng.integers(8, 16)):
            add(at(day, rng.uniform(10, 17)), user, "email", pc, rng.uniform(15, 40), 1)
        for _ in range(rng.integers(5, 11)):
            add(at(day, rng.uniform(10, 17)), user, "http_upload", pc, rng.uniform(30, 100))
    elif scenario == "night_usb":
        h0 = rng.uniform(21.5, 22.5)
        add(at(day, h0), user, "logon", pc)
        for _ in range(rng.poisson(40)):
            add(at(day, rng.uniform(h0, 23.9)), user, "file_access", pc, rng.lognormal(0, 0.8))
        for _ in range(2):
            add(at(day, rng.uniform(h0, 23.9)), user, "usb_connect", pc, rng.uniform(100, 500))
    elif scenario == "weekend_hoarder":
        h0 = rng.uniform(10, 12)
        add(at(day, h0), user, "logon", pc)
        for _ in range(rng.poisson(200)):
            add(at(day, rng.uniform(h0, 17)), user, "file_access", pc, rng.lognormal(0.8, 0.6))
        for _ in range(5):
            add(at(day, rng.uniform(h0, 17)), user, "email", pc, rng.uniform(5, 15), 1)


labels = []
for u in range(1, N_USERS + 1):
    user, pc = f"user{u:02d}", f"PC-{u:03d}"
    start_pref = float(np.clip(rng.normal(9, 0.6), 7.5, 10.5))
    for d in range(N_DAYS):
        day = START + pd.Timedelta(days=d)
        weekend = day.dayofweek >= 5
        insider = user in INSIDERS and d >= ATTACK_START_DAY
        attack = insider and (rng.random() < 0.7)
        if user == "user42" and weekend:
            attack = insider                       # always hoards on weekends
        working = (not weekend and rng.random() < 0.97) or (weekend and rng.random() < 0.03)

        if attack and not weekend:
            normal_day(user, pc, day, start_pref + rng.normal(0, 0.3))
        elif working and not attack:
            normal_day(user, pc, day, start_pref + rng.normal(0, 0.3))
        if attack:
            attack_events(user, pc, day, INSIDERS[user])
        labels.append((user, day, int(attack)))

out = Path(__file__).parent / "data"
out.mkdir(exist_ok=True)
ev = pd.DataFrame(events, columns=["timestamp", "user", "event_type", "pc", "size_mb", "external"])
ev = ev.sort_values("timestamp").reset_index(drop=True)
ev.to_csv(out / "events.csv", index=False)
pd.DataFrame(labels, columns=["user", "date", "is_malicious"]).to_csv(out / "labels.csv", index=False)
print(f"Wrote {len(ev):,} events for {N_USERS} users over {N_DAYS} days -> {out}")
print("Injected insiders:", ", ".join(f"{k} ({v})" for k, v in INSIDERS.items()))
