# T09 – TCP close và reset

## Test dùng

- Pytest: `tests/test_assignment2.py::test_t09_fin_close_and_rst_are_terminal_states`
- Lệnh chạy trực tiếp:

```bash
uv run --with scapy==2.7.0 --with pytest python -m pytest -q tests/test_assignment2.py::test_t09_fin_close_and_rst_are_terminal_states
```

## Input

```json
{
  "normal_close": [
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
    },
    {
      "flags": [
        "FIN"
      ],
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
      "timestamp": "2026-01-01T00:00:04+00:00"
    }
  ],
  "reset": {
    "flags": [
      "RST"
    ],
    "timestamp": "2026-01-01T00:00:05+00:00"
  }
}
```

## Mong đợi

```json
{
  "active_after_close": 0,
  "active_after_reset": 0,
  "closed_flow_id": 1,
  "closed_state": "CLOSED",
  "reset_flow_id": 2,
  "reset_state": "RESET"
}
```

## Output thực tế

```json
{
  "active_after_close": 0,
  "active_after_reset": 0,
  "closed_flow_id": 1,
  "closed_state": "CLOSED",
  "reset_flow_id": 2,
  "reset_state": "RESET"
}
```

## Phân tích

FIN từ hai hướng tạo CLOSED; RST tạo RESET; cả hai flow terminal được loại khỏi active table. Output thực tế trùng khớp hoàn toàn với expected.

## Kết luận

**PASS**, exit code `0`. Bằng chứng: [`run.log`](run.log), [`actual.json`](actual.json), [`exit_code.txt`](exit_code.txt).
