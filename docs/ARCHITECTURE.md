# Architecture and scope

```text
Normalized web/API metadata    ModSecurity JSON subset
             |                         |
             +----- field allow-list --+
                          |
                 identity and route minimization
                          |
               per-entity ordered history
                          |
           short window + bounded history summary
                          |
                decision-backend interface
                    /              \
             offline rules       Jev HTTPS API
                    \              /
              timeline + observed evidence + JSON
```

Python computes statistics. Only the Jev backend performs model inference.
The displayed evidence table comes from logged observations; it is not a generated
explanation or access to the model's reasoning. Findings are hypotheses for review.

The initial release is a **read-only log replay tool**, not a streaming collector,
inline WAF, complete SIEM, ASN enrichment service or autonomous incident-response
agent. It can analyze prepared logs but does not capture traffic itself. The source
contains no attack engine. The long-term goal is to investigate captured authorized
agent runs using the same input and output contracts.
