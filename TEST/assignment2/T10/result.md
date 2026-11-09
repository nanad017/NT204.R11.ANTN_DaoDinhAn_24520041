# T10 – UDP query/response

## Test dùng

- Pytest: `tests/test_assignment2.py::test_t10_udp_query_response_is_one_bidirectional_flow`
- Lệnh chạy trực tiếp:

```bash
uv run --with scapy==2.7.0 --with pytest python -m pytest -q tests/test_assignment2.py::test_t10_udp_query_response_is_one_bidirectional_flow
```

## Input

```json
{
  "query": {
    "event": {
      "dest_port": 53,
      "packet_length": 60,
      "proto": "UDP",
      "src_port": 53000
    },
    "udp": {
      "length": 40,
      "payload_length": 32
    }
  },
  "response": {
    "event": {
      "dest_ip": "192.0.2.1",
      "dest_port": 53000,
      "packet_length": 100,
      "proto": "UDP",
      "src_ip": "198.51.100.1",
      "src_port": 53
    },
    "udp": {
      "length": 80,
      "payload_length": 72
    }
  }
}
```

## Mong đợi

```json
{
  "backward_byte_count": 100,
  "backward_packet_count": 1,
  "byte_count": 160,
  "duration": 0.0,
  "flow_id": 1,
  "forward_byte_count": 60,
  "forward_packet_count": 1,
  "packet_count": 2,
  "protocol": "UDP",
  "state": "NEW"
}
```

## Output thực tế

```json
{
  "backward_byte_count": 100,
  "backward_packet_count": 1,
  "byte_count": 160,
  "duration": 0.0,
  "flow_id": 1,
  "forward_byte_count": 60,
  "forward_packet_count": 1,
  "packet_count": 2,
  "protocol": "UDP",
  "state": "NEW"
}
```

## Phân tích

DNS-like UDP query/response cùng flow; packet và byte counter được tách đúng hai chiều. Output thực tế trùng khớp hoàn toàn với expected.

## Kết luận

**PASS**, exit code `0`. Bằng chứng: [`run.log`](run.log), [`actual.json`](actual.json), [`exit_code.txt`](exit_code.txt).
