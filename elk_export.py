"""Step 3 (optional) - Push events and alerts into Elasticsearch so Kibana can visualise them.

Needs the ELK containers running:  docker compose up -d
"""
import json
import sys
from pathlib import Path

import pandas as pd
from elasticsearch import Elasticsearch, helpers

ES_URL = "http://localhost:9200"
ROOT = Path(__file__).parent


def to_actions(df: pd.DataFrame, index: str, ts_col: str):
    for rec in json.loads(df.to_json(orient="records", date_format="iso")):
        rec["@timestamp"] = rec[ts_col]
        yield {"_index": index, "_source": rec}


es = Elasticsearch(ES_URL)
try:
    es.info()
except Exception as e:                                   # noqa: BLE001
    sys.exit(f"Cannot reach Elasticsearch at {ES_URL}. Run 'docker compose up -d' first.\n{e}")

events = pd.read_csv(ROOT / "data" / "events.csv")
scored = pd.read_csv(ROOT / "output" / "scored_user_days.csv")

for index in ("insider-events", "insider-scored"):
    if es.indices.exists(index=index):
        es.indices.delete(index=index)

n1, _ = helpers.bulk(es, to_actions(events, "insider-events", "timestamp"), chunk_size=2000)
n2, _ = helpers.bulk(es, to_actions(scored, "insider-scored", "date"), chunk_size=2000)
print(f"Indexed {n1:,} raw events -> 'insider-events' and {n2:,} scored user-days -> 'insider-scored'")
print("Open Kibana at http://localhost:5601 and create data views for 'insider-*'.")
