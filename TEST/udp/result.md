# Result: UDP

Source: Wireshark Sample Captures, `iperf3-udp.pcapng.gz`.
https://wiki.wireshark.org/SampleCaptures

Expected: UDP packets are parsed without errors.

Actual: the input contains 282 UDP packets. The parser completed 314 capture
events with no handler errors; UDP events include length, checksum, and
payload length.

Result: PASS
