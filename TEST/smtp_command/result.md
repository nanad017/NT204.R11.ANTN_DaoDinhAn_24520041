# Result: SMTP Command

Source: Wireshark Sample Captures, `smtp.pcap`.
https://wiki.wireshark.org/SampleCaptures

Expected: SMTP HELO/EHLO, MAIL FROM, or RCPT TO command data is parsed.

Actual: `actual.jsonl` contains SMTP command events with HELO, MAIL FROM,
and RCPT TO fields.

Result: PASS
