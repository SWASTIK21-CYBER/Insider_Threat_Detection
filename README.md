# Insider Threat Detection System

A Python project that detects suspicious behaviour by internal users (for example
after-hours access, mass file access, USB copying and data exfiltration) using
**User Behavior Analytics (UBA)**, **Machine Learning**, and the **ELK Stack** for
visualisation.

| | |
|---|---|
| **Objective** | Detect suspicious insider activity from user logs |
| **Tools** | Python, scikit-learn (Isolation Forest), pandas, matplotlib, Elasticsearch, Kibana, Docker |
| **Skills** | Insider threat modeling, anomaly detection, behavioural analytics |

---

## 1. How it works

```
 Raw logs ──► Feature engineering ──► Per-user baseline (UBA) ──► Isolation Forest ──► Risk score + Alerts
 (events.csv)   (one row per           (z-score vs the user's        (ML anomaly          │
                 user per day)           own normal behaviour)         detection)           ▼
                                                                              CSV reports + charts
                                                                              Elasticsearch ──► Kibana dashboard
```

1. **Data generation** (`generate_data.py`): 50 users over 60 days with logon, logoff,
   file access, email, USB and upload events. Four insiders turn malicious in the last
   15 days. The ground-truth labels are used only for evaluation, never for training.
2. **Feature engineering** (`features.py`): events are aggregated into one row per user
   per day, such as after-hours events, MB copied to USB, external email volume, and
   files accessed.
3. **UBA baseline**: each feature is z-scored against that user's own first 30 days.
   500 MB copied might be normal for one person and a red flag for another.
4. **ML detection** (`train_detect.py`): an Isolation Forest is trained on days 0-44
   (assumed clean). Every user-day gets a risk score from 0 to 100, and scores above
   the 99.5th percentile of the training scores raise an alert.
5. **Explainability**: each alert states why it fired, for example
   `usb_mb (+50.0 sd); after_hours_events (+50.0 sd)`.
6. **ELK integration** (`elk_export.py`): events and scored data are loaded into
   Elasticsearch and visualised in Kibana.

### Injected insider scenarios

| User | Scenario |
|---|---|
| user07 | Night logon, mass file access, USB copy |
| user19 | Large attachments to external email, big uploads |
| user33 | Night logon, USB copy |
| user42 | Weekend work, mass file access, external email |

---

## 2. Project structure

```
insider_threat_detection/
├── generate_data.py      # synthetic logs + injected insiders
├── features.py           # feature engineering + per-user baselines
├── train_detect.py       # model, risk scores, alerts, charts
├── elk_export.py         # load data into Elasticsearch
├── docker-compose.yml    # Elasticsearch + Kibana 8.13.4
├── requirements.txt
├── README.md
├── data/                 # events.csv, labels.csv (generated)
└── output/               # alerts.csv, scored_user_days.csv, charts (generated)
```

---

## 3. Setup and run (Python only, no Docker needed)

Requires Python 3.9 or newer.

```
python -m venv venv
venv\Scripts\activate            # Windows   (macOS/Linux: source venv/bin/activate)
pip install -r requirements.txt  # can take a few minutes; the last step looks frozen but is not
python generate_data.py          # creates data/events.csv and data/labels.csv
python train_detect.py           # prints the report and writes output/
```

### Output files

| File | Contents |
|---|---|
| `output/alerts.csv` | Flagged user-days with risk score and reason |
| `output/scored_user_days.csv` | Every user-day with features, z-scores and risk score |
| `output/top_users.png` | Users ranked by number of alerts |
| `output/risk_timeline.png` | Daily risk score of flagged users vs the average |

---

## 4. Results

Evaluated on days 45-59, which the model never saw during training:

| | Predicted normal | Predicted malicious |
|---|---|---|
| **Actually normal** | 504 | 1 |
| **Actually malicious** | 0 | 44 |

- All four injected insiders (user07, user19, user33, user42) rank at the top of the alert list.
- Recall is 100% and precision is about 98%, with 1 false alarm among 505 normal user-days.
- About 9 alerts fall inside the clean training window. This is expected because the
  threshold flags the top 0.5% of scores. Normal users such as user08 occasionally
  produce a false positive, which is worth discussing in a report.

---

## 5. Optional: ELK Stack dashboard

Elasticsearch stores and indexes the data, and Kibana provides the dashboards.
Docker is only the delivery method, so no manual installation is needed.

**Requirements:** Docker Desktop (WSL 2) and about 4 GB of free RAM. Virtualization
must be enabled in the BIOS.

```
docker compose up -d       # wait 1-2 minutes
python elk_export.py       # loads data into Elasticsearch
```

1. Check http://localhost:9200 shows JSON (`"You Know, for Search"`).
2. Open Kibana at http://localhost:5601.
3. Go to **Stack Management, Data Views, Create data view**, and create two views:
   - `insider-scored` with timestamp field `@timestamp`
   - `insider-events` with timestamp field `@timestamp`
4. In Discover, set the time range to **Last 1 year** (the data is from 2026, and Kibana
   defaults to the last 15 minutes).
5. Build the dashboard (Dashboard, Create, Lens):
   - **Alerts per user:** bar chart, filter `alert : 1`, x-axis `user.keyword`, y-axis Count
   - **Risk over time:** line chart, x-axis `@timestamp`, y-axis Max of `risk_score`, break down by `user.keyword`
   - **USB data copied:** horizontal bar, Sum of `usb_mb` by `user.keyword`
6. When finished:

```
docker compose down
```

Data and dashboards are not persisted, so repeat `up -d` and `elk_export.py` to restore them.

---

## 6. Troubleshooting

| Problem | Fix |
|---|---|
| `pip install` seems stuck at "Installing collected packages" | Wait 5-10 minutes; it is unpacking large libraries. If still stuck, Ctrl+C and run `pip install --no-cache-dir -r requirements.txt` |
| Docker: "Virtualization support not detected" | Enable VT-x / SVM in the BIOS, and enable *Virtual Machine Platform* and *WSL* in Windows Features |
| Kibana: "index pattern doesn't match any indices" | Run `python elk_export.py` first, then refresh Kibana |
| `elk_export.py` cannot reach Elasticsearch | Wait 1-2 minutes after `docker compose up -d`, and check http://localhost:9200 |
| Kibana charts are empty | Set the time range to Last 1 year |
| Elasticsearch exits with code 137 | Out of memory; close other apps or give Docker more RAM |
| PowerShell blocks `venv\Scripts\activate` | Use Command Prompt (`cmd`) instead |

---

## 7. Limitations

- The data is synthetic and the attacks are blatant, so the near-perfect score will not
  carry over to real organisations where insiders are subtler.
- The model assumes the training period contains no malicious activity.
- Behaviour is modelled per day only. There is no sequence modelling or peer-group comparison.
- The threshold is a fixed percentile, not tuned to a business risk appetite.

## 8. Future improvements

- Use the real **CERT Insider Threat dataset** (r4.2) instead of synthetic logs.
- Compare other models: Autoencoder, One-Class SVM, Local Outlier Factor.
- Add peer-group baselines (compare against the same department) and hourly features.
- Add rule-based alerts, for example USB use after hours, alongside the ML score.
- Add real-time ingestion with Filebeat or Logstash and Kibana alerting rules.
- Add a persistent Docker volume so Elasticsearch data survives restarts.
