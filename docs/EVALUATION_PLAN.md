# Evaluation plan (not results)

The research question is whether a short ordered request sequence plus longer historical context helps identify persistent or changing suspicious behavior at an acceptable false-alert rate, compared with the same inputs supplied to simpler baselines.

Collect authorized traffic from held-out web applications: ordinary users, legitimate automation/agents, conventional scanners, human testing and agent-driven testing. Label execution provenance independently from maliciousness and from success. Establish success with application-side evidence, not HTTP 200 alone. Keep agent traces and experimental labels outside detector inputs.

Compare request-level and temporal rules, a trained conventional model, a suitable sequence baseline, a general LLM, and Jev. Control the available information and split whole runs/applications before generating overlapping windows. Hold out agent implementations or task families to test generalization. Avoid an unfair baseline that sees only one request while Jev receives long history.

Window ablations: N=1/5/10/20/50/100; ordered sequence alone versus sequence plus aggregate history; fixed stride versus call-budget matched schedules. Include shuffling or order-removal ablations to separate useful sequence order from simple counts. Include benign failure/retry and high-volume API cases. Assess evasion and prompt injection separately.

Primary outcomes: session recall at fixed false-alert rate, false alerts per entity-hour or per legitimate session, detection delay, API calls and input tokens, and wall time/throughput under controlled load. Thresholds are selected on validation data only. Report uncertainty using independent runs, not overlapping windows as independent samples.

The bundled 4 x 80 generated records are functional fixtures, not a benchmark. They cannot substantiate precision, recall, calibrated probabilities, superiority over a WAF, AI attribution or real-world robustness. A public dataset release should include provenance, authorization, generator/agent configuration, labels, splits, event timestamps, schema, licenses and limitations.
