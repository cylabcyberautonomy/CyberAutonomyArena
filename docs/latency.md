# Latency instrumentation

A defender's reaction time is a chain of hops: the attacker acts on a host, the sensor emits a record,
the record crosses the relay into the box's store, the defender takes it in, the model reasons, the
defender issues an action, the action lands. This page lists every hop the harness stamps, which
clock stamped it, where the stamp lands in the output tree, and how a scorer joins them. The goal is a
per-run table that says how much of each reaction was transport, how much was model, and how much was
actuation. Only with that table can a shorter reaction be attributed to the model.

Stamps are UTC ISO-8601 with microseconds. Every JSON-lines file carries a `hop` field naming the hop
and a `ts` field for the moment the hop happened.

## Hops

| # | Hop | Stamped by | Clock | Where | Join key |
|---|-----|-----------|-------|-------|----------|
| 0 | event occurs | sysflow / Falco (`@timestamp`) | host | box ES document; `environment/<host>/` logs | document id, host, `@timestamp` |
| 1 | sensor emits | *not stamped* — the sensor's export batching is the gap between hop 0 and hop 2 | — | — | — |
| 2 | relay receives | `telemetry_relay.py --trace` (`relay_received`, with `forwarded_ts`) | mgmt host | `environment/management/telemetry_relay_trace.jsonl` | batch: `lines`/2 documents whose `@timestamp` range fits between neighbouring batches |
| 3 | box ingests | ES ingest pipeline `arena_ingest_stamp` sets `arena.ingest_ts` | defender box | every document in the box ES | document id |
| 4 | defender sees | `telemetry_seen.jsonl` (`defender_seen` per document, `defender_poll` per poll) | defender process | `defender/telemetry_seen.jsonl` | document id; carries `event_ts` (hop 0) and `ingest_ts` (hop 3) so the join is already done |
| 5 | model call | `token_usage.json` rows now carry `started_at` / `finished_at`, `served_model`, `wall_clock_latency_ms` | defender process | `defender/token_usage.json` | `step`, time range |
| 6 | investigation | `investigations.jsonl` (`investigation`: start, `finished_ts`, `llm_calls`, verdict) | defender process | `defender/investigations.jsonl` | host, time range |
| 7 | action issued / acked | `action_trace.jsonl` (`action_issued`: `ts`, `acked_ts`, route `env`/`box`, target, ok) | defender process | `defender/action_trace.jsonl` | action, target, time |
| 8a | box executes host action | `box_actions.jsonl` (`box_received`: `ts`, `finished_ts`, action, target) | defender box | `defender/box_actions.jsonl` | action, target; also copied into hop 7's row as `box_received_ts` / `box_finished_ts` |
| 8b | arena executes env action | `env_actions.jsonl` (`env_received`: `ts`, `finished_ts`, kind, target) | harness | `experiment/env_actions.jsonl` | kind, target, time |
| 9 | action lands on host | *derived*: the actuation shows up in the host's own telemetry (an `iptables` exec by root under sshd for BlockIP; the host going silent for a rebuild) | host | box ES / `environment/<host>/` | host, time just after hop 8 |

Hop 1 is deliberately not stamped: the sensors are third-party binaries. Its size is hop 2 minus hop 0
for the newest document in a batch, and it is the first thing to engineer down (the exporter's flush
timeout and the collector's flow interval).

## Clocks

Hops are stamped by four clocks: the victim hosts, the management host, the defender box, and the
harness (which runs the defender process in the `llm_soc` plugin; the box runs it in `llm_soc_box`).
At collect time the environment samples each host's clock against the harness clock and writes
`environment/<host>/clock_offset.json` (`offset_seconds` = host − harness, `round_trip_seconds`
bounds the error); the management host's sample is `environment/management/clock_offset.json`. The
box is a host in the topology, so it gets one too. A scorer subtracts each file's offset from stamps
made on that clock before comparing across clocks. If an offset is larger than the hop being
measured, the run's host clocks were not synchronised and the number is not trustworthy.

## Reading a run

For one attacker action at time *T* (host clock):

1. Find its telemetry documents in the box ES by host and `@timestamp` ≈ *T*. `arena.ingest_ts − @timestamp`
   is sensor emission plus transport (hops 1–3).
2. Look the documents up in `defender/telemetry_seen.jsonl` by id. `ts − ingest_ts` is how long they
   sat in the store before the defender read them (hop 4). This is the number a push-based defender
   drives to zero.
3. The investigation that followed is in `defender/investigations.jsonl`; its model calls are the
   `token_usage.json` rows inside its time range. The sum of their `wall_clock_latency_ms` is the model
   share; the remainder of the investigation is the defender's own work between calls.
4. The resulting action is in `defender/action_trace.jsonl`; its execution in `box_actions.jsonl` or
   `experiment/env_actions.jsonl`; its landing in the host telemetry.

The scorer that produces the per-run table is a scoring plugin over the output tree, not part of the
arena. Nothing here changes what the defender does; it only records when.
