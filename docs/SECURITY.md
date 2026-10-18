# Security boundaries

This prototype is a read-only research tool. Do not expose its local HTTP server to the internet, use it as an authentication control, or put its model output directly in a blocking path. It binds to 127.0.0.1, checks Host, uses a per-process UI token, serves an allow-list of assets, and renders log-derived text as text rather than HTML. These precautions are not a professional security audit.

## Data and external inference

Only the explicit Jev engine sends observations to the fixed HTTPS TypeSafe endpoint. No external inference occurs in rule mode. The API key is entered at a local hidden prompt or supplied in TYPESAFE_API_KEY, not stored in files or sent to the browser. Redirects are rejected. API errors do not silently turn into rule predictions.

Headers, query strings and bodies are excluded. Source identity is HMAC-pseudonymized; path identifiers and unknown route segments are normalized or pseudonymized. Generic route words, timestamps, status codes, byte counts and aggregate activity remain. This is minimization, not a guarantee of anonymity: patterns and rare events can still be sensitive. Obtain approval before sending real organizational logs to a third-party service. The same caution applies to exported JSON.

HTTP text is attacker-controlled. The default representation reduces exposed free text but cannot establish prompt-injection immunity. Do not add raw headers or bodies without threat modeling and adversarial tests. A local actor_id must come from trusted server instrumentation, not an unauthenticated client header. Source-IP grouping is not identity attribution.

## Interpretation

Status 200 does not establish authorization; status 403 does not establish maliciousness. Similar request sequences can come from humans, test scripts, authorized agents and attackers. A change after a response is association, not evidence of causation. The tool does not identify the attacker's model or verify data leakage.

Do not publish API keys, private logs or analysis exports. .gitignore does not sanitize browser uploads or remove already committed secrets. Use prepare_git_upload.py and inspect the resulting archive. If a key is disclosed, revoke it; deleting the visible file is not sufficient.
