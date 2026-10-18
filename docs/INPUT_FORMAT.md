# Input format

Use UTF-8 JSON Lines (one complete object per line), sorted by timestamp.
The GUI accepts an optional local JSONL file; otherwise it loads bundled examples.

```json
{"timestamp":"2026-10-01T00:00:00+00:00","service_id":"demo-app","actor_id":"server-side-pseudonym","method":"GET","path":"/api/v1/items/123","status":200,"bytes_sent":420,"authenticated":true}
```

| Field | Requirement |
|---|---|
| timestamp or ts | UNIX seconds, or ISO-8601 with timezone; not milliseconds |
| actor_id | Preferred trusted server-side grouping identifier; do not pass raw session cookies |
| client_ip or remote_addr | Required as fallback when actor_id is absent; trust your proxy chain first |
| service_id | Application scope; defaults to default |
| method | Standard HTTP method; unknown methods become OTHER |
| path or uri | Request target; query strings are removed before analysis |
| status | Integer 100-599 |
| bytes_sent | Optional nonnegative integer, defaults to zero; missing is not proof of no data transfer |
| authenticated | Optional boolean from trusted application context |
| waf_alerts | Optional nonnegative alert count; defaults to zero |

Labels, scenario names, headers, User-Agent and arbitrary extra fields are not input features. Missing fields are not inferred from HTTP outcomes.

## ModSecurity subset

A JSONL object with transaction.request.method, transaction.request.uri,
transaction.response.http_code and transaction.client_ip is supported.
transaction.messages is counted. Supply a top-level timestamp in UTC/offset-aware
ISO format when transaction.time_stamp is timezone-free. The code refuses to guess
a timezone. Arrays, pretty-printed multi-line JSON, ModSecurity native multipart
logs and all historical JSON variants are not supported by this first adapter.

A fixture is in examples/modsecurity_v3_sample.jsonl. It is a schema illustration,
not evidence of a tested WAF deployment. Normalize production logs upstream and
check field mapping against your actual version. Combine complete web access
metadata with optional WAF alerts; RelevantOnly audit logs can leave gaps.
Do not assume absent WAF alerts imply benign traffic.
