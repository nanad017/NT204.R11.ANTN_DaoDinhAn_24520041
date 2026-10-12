# Result: DNS Response

Source: Wireshark Sample Captures, `dns.cap`.
https://wiki.wireshark.org/SampleCaptures

Expected: DNS responses contain query data and at least one answer record.

Actual: `actual.jsonl` contains 19 DNS response events with parsed answer
records.

Result: PASS
