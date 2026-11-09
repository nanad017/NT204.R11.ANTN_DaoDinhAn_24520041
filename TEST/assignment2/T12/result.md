# T12 – Idle timeout

## Test dùng

- Pytest: `tests/test_assignment2.py::test_t12_idle_timeout_removes_flow_and_keeps_final_summary`
- Lệnh chạy trực tiếp:

```bash
uv run --with scapy==2.7.0 --with pytest python -m pytest -q tests/test_assignment2.py::test_t12_idle_timeout_removes_flow_and_keeps_final_summary
```

## Input

```json
{
  "expire_time": "2026-01-01T00:00:05+00:00",
  "packet_time": "2026-01-01T00:00:00+00:00",
  "tcp_idle_timeout": 5,
  "udp_idle_timeout": 5
}
```

## Mong đợi

```json
{
  "active_flow_count": 0,
  "completed_packet_count": 1,
  "expired_count": 1
}
```

## Output thực tế

```json
{
  "active_flow_count": 0,
  "completed_packet_count": 1,
  "expired_count": 1
}
```

## Phân tích

Flow hết hạn chính xác tại idle timeout, rời active table nhưng summary cuối vẫn được giữ. Output thực tế trùng khớp hoàn toàn với expected.

## Kết luận

**PASS**, exit code `0`. Bằng chứng: [`run.log`](run.log), [`actual.json`](actual.json), [`exit_code.txt`](exit_code.txt).
