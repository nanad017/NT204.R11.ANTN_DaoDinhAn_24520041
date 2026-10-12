# Result: TCP Handshake

Source: live traffic captured from `wlan0` with `tcpdump`.

Expected: SYN, SYN-ACK, and ACK are parsed without errors.

Actual: `actual.jsonl` contains 11 TCP events, including `SYN`, `SYN, ACK`,
and `ACK`. The parser status is `success` for all events.

Result: PASS
