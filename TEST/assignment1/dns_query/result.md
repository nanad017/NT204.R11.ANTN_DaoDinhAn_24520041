# Result: DNS Query

Source: Wireshark Sample Captures, `dns.cap`.
https://wiki.wireshark.org/SampleCaptures

Expected: DNS query name and query type are parsed.

Actual: `actual.jsonl` contains 19 DNS query events. The first query is for
`google.com` with type `TXT`.

Result: PASS
