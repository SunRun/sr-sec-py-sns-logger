# Benchmarks

Measured 2026-11-19 in AWS account `687126124183` (SoftSec Dev), region `us-west-2`.

| Item | Value |
|---|---|
| Function | `secbench-py`, `python3.12`, 512 MB, timeout 30 s |
| Package under test | `sr-sec-py-sns-logger` 2.3.0 (this repo, working tree) |
| Topic | `arn:aws:sns:us-west-2:687126124183:sr-sec-logging-log-topic-dev` |
| Failover | dev failover topic, explicitly set (never the prod default) |
| Event | one `record_access`, `id_list` of 1 |

## Results

### Cold (first invocation in a fresh container)

| Measurement | ms |
|---|---|
| `Init Duration` from Lambda `REPORT` (Python runtime + our import) | 573 |
| Library init only (`init_lambda_security_logging`) | 444 |
| First `log_record_access` (includes boto3 client build + DNS/TLS) | 166 |

### Warm (subsequent invocations, same container)

`log_record_access` per call: 16, 18, 18 ms. Includes one full synchronous SNS publish.

### Failure path (SNS endpoint blackholed)

`AWS_ENDPOINT_URL=http://192.0.2.1:1`, cold container:

| Measurement | Result |
|---|---|
| `log_record_access` wall time | 20,626 ms |
| Returned value | `{"status": "failure", "message": "1/1 messages failed to publish"}` |
| Raised exception | none |

The 20.6 s is the retry budget: 2 s connect / 2 s read timeouts across 2 primary attempts plus 3 failover attempts. The call always returns rather than raising, so a wedged network costs time but not correctness. Account for this in Lambda timeouts.

## Method

1. Deployed `secbench-py` with `SECURITY_LOGS_TOPIC_ARN` and `SECURITY_LOGS_FAILOVER_TOPIC_ARN` pointing at the dev topics, so no default ARN (the prod one) is ever used.
2. Invoked with `aws lambda invoke --log-type Tail`; cold was forced by creating the function fresh, warm by repeated invokes in the same container.
3. Read `Init Duration` from the Lambda `REPORT` line for platform-level cost, and in-function timers for our own init and the log call.
4. Re-ran with `AWS_ENDPOINT_URL` set to a non-routable address to measure the failure path.
5. Deleted the function, its IAM role, and its log group; verified with `list-functions` that nothing remained.

One trap worth recording: `build_lambda_context()` returns `user_agent` and `user_role`, which `log_record_access()` rejects as unexpected keyword arguments. Because callers wrap the call in `ignore_log_error`, the resulting `TypeError` is swallowed and the event is dropped with no error surfaced. The bench asserts `status == "success"` on every call for exactly this reason.
