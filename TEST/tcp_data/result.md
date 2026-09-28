# Result: TCP Data

Source: live traffic captured from `wlan0` with `tcpdump`.

Expected: a TCP packet with a payload is parsed without errors.

Actual: `actual.jsonl` contains 11 TCP events, including three packets with
`PSH, ACK` flags and a non-zero payload length.

Result: PASS
