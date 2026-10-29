#!/bin/bash
# Latency hop `es_ingest`: stamp every telemetry document with the box ES's own receive time.
# An ingest pipeline sets arena.ingest_ts = _ingest.timestamp (box clock); an index template makes it
# the default pipeline for the sensor indices created from now on, and any index that already exists
# is switched to it in place. The sensor's own @timestamp stays the event time (host clock), so the
# scorer gets host-emit -> box-ingest per document without touching the sensors.
set -e
ES=${ES_URL:-http://localhost:9200}
for i in $(seq 1 30); do
  curl -s -m 5 -o /dev/null -w '%{http_code}' "$ES" | grep -q 200 && break
  sleep 2
done
curl -s -m 10 -X PUT "$ES/_ingest/pipeline/arena_ingest_stamp" -H 'Content-Type: application/json' -d '{
  "description": "arena latency hop es_ingest: stamp the box receive time on every document",
  "processors": [ { "set": { "field": "arena.ingest_ts", "value": "{{_ingest.timestamp}}" } } ]
}'
echo
curl -s -m 10 -X PUT "$ES/_index_template/arena_ingest_stamp" -H 'Content-Type: application/json' -d '{
  "index_patterns": ["sysflow*", "falco*"],
  "priority": 500,
  "template": { "settings": { "index.default_pipeline": "arena_ingest_stamp" } }
}'
echo
# Indices that already exist (a sensor may have shipped before this ran): switch them in place.
for idx in $(curl -s -m 10 "$ES/_cat/indices/sysflow*,falco*?h=index" 2>/dev/null); do
  curl -s -m 10 -X PUT "$ES/$idx/_settings" -H 'Content-Type: application/json' \
       -d '{"index.default_pipeline": "arena_ingest_stamp"}'
  echo
done
echo "ingest stamp installed"
