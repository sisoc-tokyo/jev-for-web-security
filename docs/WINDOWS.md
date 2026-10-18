# Exact window semantics

For an entity's event at time t, keep the last N records whose timestamps are within [t - short_horizon, t]. Retain up to max_history records within [t - horizon, t] for the history summary. Thus a window is bounded by both time and count; it is not a fixed-size batch. Defaults: N=20, S=5, short=300s, history=1800s, max_history=10000, max_actors=1000.

Evaluate at the first observation, at entity episode counts S, 2S, 3S, and when a new observation arrives at least short_horizon seconds after the last evaluation. An inactive entity expires after the history horizon. There is no background timer: silence does not cause a verdict, and the final incomplete stride is not automatically flushed. High-speed replay does not simulate real-time inference capacity.

Early windows are allowed and marked cold_start. N=20 and S=5 produce window counts 1, 5, 10, 15, 20 on the first 20 regularly spaced observations. Increasing N does not necessarily delay the first verdict because windows need not fill. The history summary includes the short window, not only the earlier disjoint period.

Records must be in timestamp order. Nothing after the as_of time is used. Grouping uses a trusted actor_id scoped by service_id, falling back to client_ip. User-Agent and ASN are not identity keys. NAT and proxy rotation remain limitations. Unknown identity is rejected, not merged into one global entity.

History caps can remove relevant context. The history_truncated flag stays true while a discarded event would still be inside the current time horizon. Defaults are engineering choices, not empirically optimized settings.

In experiments, vary N independently from stride and time horizon. Freeze the inference schedule when measuring the effect of context alone. Do not split overlapping windows randomly between training and test sets. Report false alerts per session/entity-hour and time-to-first-detection, not just window-level F1. Preserve complete independent sessions for splitting and confidence intervals.

Pseudonyms remain stable across reruns in one dashboard server process. For controlled CLI comparisons, supply a locally protected JEVWEB_PSEUDONYM_SALT environment value consistently; do not publish it. By default each CLI run gets fresh pseudonyms. Exact exported states can be retained privately for later backend comparisons.
