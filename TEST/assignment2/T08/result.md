# T08 – Bidirectional flow

## Test dùng

- Pytest: `tests/test_assignment2.py::test_t08_bidirectional_packets_share_id_and_direction_is_stable`
- Lệnh chạy trực tiếp:

```bash
uv run --with scapy==2.7.0 --with pytest python -m pytest -q tests/test_assignment2.py::test_t08_bidirectional_packets_share_id_and_direction_is_stable
```

## Input

```json
{
  "backward": {
    "dest_ip": "192.0.2.1",
    "dest_port": 50000,
    "src_ip": "198.51.100.1",
    "src_port": 80
  },
  "forward": {
    "dest_ip": "198.51.100.1",
    "dest_port": 80,
    "src_ip": "192.0.2.1",
    "src_port": 50000
  }
}
```

## Mong đợi

```json
{
  "active_flow_count": 1,
  "backward_direction": "backward",
  "backward_flow_id": 1,
  "forward_direction": "forward",
  "forward_flow_id": 1
}
```

## Output thực tế

```json
{
  "active_flow_count": 1,
  "backward_direction": "backward",
  "backward_flow_id": 1,
  "forward_direction": "forward",
  "forward_flow_id": 1
}
```

## Phân tích

Five-tuple đảo chiều được chuẩn hóa về cùng flow key và hướng backward được gắn đúng. Output thực tế trùng khớp hoàn toàn với expected.

## Kết luận

**PASS**, exit code `0`. Bằng chứng: [`run.log`](run.log), [`actual.json`](actual.json), [`exit_code.txt`](exit_code.txt).
