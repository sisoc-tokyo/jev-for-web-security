# Verification status - 2026-10-18

Implemented: normalized JSONL input; per-entity count/time windows; bounded historical features; a transparent rule backend; an official-schema Jev HTTP client; a local browser dashboard; JSON export; a documented ModSecurity v3 subset adapter; generated fixtures; automated tests.

Verified in the preparation environment: 28 Python tests, JavaScript syntax, browser UI interactions using local assets bridged to the Python pipeline, and a separate actual local HTTP GET/POST smoke test. The browser environment disallowed local navigation, so these are two complementary checks rather than a full browser-to-server end-to-end test.

Not yet verified: a credentialed Jev API call; Windows/macOS launcher execution; a live ModSecurity deployment; detection on captured agent traffic; comparative accuracy, latency under operational load, or production safety. Synthetic examples demonstrate mechanics, not effectiveness. These distinctions must remain visible in the submission.
