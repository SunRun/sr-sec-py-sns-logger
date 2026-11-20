# Benchmarks

Measured 2026-11-19 in AWS account `687126124183` (SoftSec Dev), region `us-west-2`.

## What was tested

| Item | Value |
|---|---|
| Function | `secbench-py`, `python3.12`, 512 MB, timeout 30 s |
| Package under test | `sr-sec-py-sns-logger` 2.3.0 (this repo, working tree) |
| Event logged | one `record_access`, `id_list` of 1 |
| Primary topic | `arn:aws:sns:us-west-2:687126124183:sr-sec-logging-log-topic-dev` |
| Failover topic | `arn:aws:sns:us-east-2:687126124183:sr-sec-logging-log-topic-failover-dev` |
| Failover override | explicitly set — see the safety note below |

One event per invocation, so these are per-log-call costs, not per-batch.

## Results

### Cold — first invocation in a fresh container

| Measurement | ms |
|---|---|
| Lambda `Init Duration` (Python runtime + our import) | 573 |
| Library init only (`init_lambda_security_logging`) | 444 |
| First `log_record_access` (boto3 client build + DNS/TLS + publish) | 166 |

### Warm — subsequent invocations, same container

`log_record_access` per call: 16, 18, 18 ms.

Each call is exactly one synchronous SNS publish and returns a status map. It does not raise on failure, which is deliberate: logging must never break the request it is recording.

### Failure path — SNS endpoint unreachable

`AWS_ENDPOINT_URL=http://192.0.2.1:1`, cold container, so both the primary and the failover region are unreachable:

| Measurement | Result |
|---|---|
| `log_record_access` wall time | 20,626 ms |
| Whole invocation (`REPORT` Duration) | 20,628 ms |
| Returned value | `{"status": "failure", "message": "1/1 messages failed to publish"}` |
| Raised exception | none |

**Why it is ~20 s, and why failover does not help here.** The call tries the primary region, fails, then tries the failover region, which also fails. Both attempts are bounded by the configured `connect_timeout=2` / `read_timeout=2` plus retries, so the total is roughly two timeout budgets rather than one. Failover protects against a *single-region* outage — it is not a latency reduction, and in a full egress blackhole both endpoints are dead.

Both regions being unreachable simultaneously is the unlikely case, not the normal one. Under normal operation the failover path is never entered.

**Tuning note.** Roughly 19 of the 20.6 s is the log call; everything else in the handler is ~2 ms. There is no `apiCallTimeout` equivalent tuning knob in use here beyond the explicit boto3 timeouts already set, so the failure cost is a known, bounded number rather than an infinite hang.

## Method

1. Staged the package modules alongside a minimal handler, deployed as `secbench-py` with the dev topic and dev failover topic in the environment.
2. Cold was the first invoke after creating the function; warm were later invokes in the same container. `Init Duration` came from the Lambda `REPORT` line; in-function timers covered our own init and the log call.
3. Re-ran with `AWS_ENDPOINT_URL` pointing at a non-routable address for the failure path, and captured the library's **actual return value** rather than a handler-assumed one.
4. Deleted the function, its IAM role, and its log group; verified with `list-functions` and `describe-log-groups` that nothing remained.

## Safety note — the failover default is production

`init_security_logging` falls back to the **prod** failover topic in account `000576341507` whenever failover is enabled and no override is set. Any benchmark run outside production must set `SECURITY_LOGS_FAILOVER_TOPIC_ARN` explicitly, or a dev test can publish into production.

## A field trap worth knowing

`build_lambda_context()` returns `user_agent` and `user_role`. `log_record_access()` rejects both as unexpected keyword arguments. Because the documented calling pattern wraps the call in `ignore_log_error`, the resulting `TypeError` is swallowed and **the event is dropped with no error surfaced** — the caller sees a successful request and no log.

Strip them before calling, or pass fields explicitly:

```python
fields = build_lambda_context(event, actor_type=ActorType.SYSTEM_SELF)
fields.pop("user_role", None)
fields.pop("user_agent", None)
log_record_access(event_type=..., endpoint_path=..., **fields)
```

This bench asserts `status == "success"` on every call for exactly this reason — a silent drop looks identical to a successful publish from the handler's point of view.
