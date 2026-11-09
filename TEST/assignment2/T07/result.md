# T07 – TCP handshake

## Test dùng

- Pytest: `tests/test_assignment2.py::test_t07_tcp_handshake_reaches_established_in_one_flow`
- Lệnh chạy trực tiếp:

```bash
uv run --with scapy==2.7.0 --with pytest python -m pytest -q tests/test_assignment2.py::test_t07_tcp_handshake_reaches_established_in_one_flow
```

## Input

```json
{
  "packets": [
    {
      "flags": [
        "SYN"
      ],
      "timestamp": "2026-01-01T00:00:00+00:00"
    },
    {
      "endpoints": {
        "dest_ip": "192.0.2.1",
        "dest_port": 50000,
        "src_ip": "198.51.100.1",
        "src_port": 80
      },
      "flags": [
        "SYN",
        "ACK"
      ],
      "timestamp": "2026-01-01T00:00:01+00:00"
    },
    {
      "flags": [
        "ACK"
      ],
      "timestamp": "2026-01-01T00:00:02+00:00"
    }
  ]
}
```

## Mong đợi

```json
{
  "active_flow_count": 1,
  "directions": [
    "forward",
    "backward",
    "forward"
  ],
  "flow_ids": [
    1,
    1,
    1
  ],
  "state": "ESTABLISHED"
}
```

## Output thực tế

```json
{
  "active_flow_count": 1,
  "directions": [
    "forward",
    "backward",
    "forward"
  ],
  "flow_ids": [
    1,
    1,
    1
  ],
  "state": "ESTABLISHED"
}
```

## Phân tích

SYN, SYN/ACK và ACK cùng flow ID; packet ACK cuối đưa TCP flow sang ESTABLISHED. Output thực tế trùng khớp hoàn toàn với expected.

## Kết luận

**PASS**, exit code `0`. Bằng chứng: [`run.log`](run.log), [`actual.json`](actual.json), [`exit_code.txt`](exit_code.txt).
