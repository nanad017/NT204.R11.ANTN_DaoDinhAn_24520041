# T13 – Flow statistics

## Test dùng

- Pytest: `tests/test_assignment2.py::test_t13_statistics_count_full_packet_bytes_and_duration`
- Lệnh chạy trực tiếp:

```bash
uv run --with scapy==2.7.0 --with pytest python -m pytest -q tests/test_assignment2.py::test_t13_statistics_count_full_packet_bytes_and_duration
```

## Input

```json
{
  "packets": [
    {
      "flags": [
        "SYN"
      ],
      "packet_length": 60,
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
      "packet_length": 60,
      "timestamp": "2026-01-01T00:00:01+00:00"
    },
    {
      "flags": [
        "ACK"
      ],
      "packet_length": 52,
      "timestamp": "2026-01-01T00:00:02+00:00"
    },
    {
      "flags": [
        "ACK",
        "PSH"
      ],
      "packet_length": 100,
      "timestamp": "2026-01-01T00:00:03+00:00"
    },
    {
      "endpoints": {
        "dest_ip": "192.0.2.1",
        "dest_port": 50000,
        "src_ip": "198.51.100.1",
        "src_port": 80
      },
      "flags": [
        "FIN",
        "ACK"
      ],
      "packet_length": 60,
      "timestamp": "2026-01-01T00:00:05+00:00"
    }
  ]
}
```

## Mong đợi

```json
{
  "ack_count": 4,
  "backward_byte_count": 120,
  "backward_packet_count": 2,
  "byte_count": 332,
  "duration": 5.0,
  "established": true,
  "fin_count": 1,
  "forward_byte_count": 212,
  "forward_packet_count": 3,
  "packet_count": 5,
  "rst_count": 0,
  "state": "CLOSING",
  "syn_count": 2
}
```

## Output thực tế

```json
{
  "ack_count": 4,
  "backward_byte_count": 120,
  "backward_packet_count": 2,
  "byte_count": 332,
  "duration": 5.0,
  "established": true,
  "fin_count": 1,
  "forward_byte_count": 212,
  "forward_packet_count": 3,
  "packet_count": 5,
  "rst_count": 0,
  "state": "CLOSING",
  "syn_count": 2
}
```

## Phân tích

Packet/byte counter hai chiều, SYN/ACK/FIN/RST counter và duration đều phản ánh đúng chuỗi TCP. Output thực tế trùng khớp hoàn toàn với expected.

## Kết luận

**PASS**, exit code `0`. Bằng chứng: [`run.log`](run.log), [`actual.json`](actual.json), [`exit_code.txt`](exit_code.txt).
