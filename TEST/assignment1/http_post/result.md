# Result: HTTP POST

Source: Wireshark Sample Captures, `tcp-ethereal-file1.trace`.
https://wiki.wireshark.org/SampleCaptures

Expected: an HTTP POST request with a body is parsed.

Actual: `actual.jsonl` contains an HTTP POST event with
`multipart/form-data` content type and content length 152372.

Result: PASS
