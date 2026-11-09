# T11 – Concurrent flows

## Test dùng

- Pytest: `tests/test_assignment2.py::test_t11_concurrent_five_tuples_remain_separate`
- Lệnh chạy trực tiếp:

```bash
uv run --with scapy==2.7.0 --with pytest python -m pytest -q tests/test_assignment2.py::test_t11_concurrent_five_tuples_remain_separate
```

## Input

```json
{
  "flow_1": {
    "dest_port": 80
  },
  "flow_2": {
    "dest_port": 443
  }
}
```

## Mong đợi

```json
{
  "active_flow_count": 2,
  "flow_1_id": 1,
  "flow_2_id": 2,
  "separate_flows": true
}
```

## Output thực tế

```json
{
  "active_flow_count": 2,
  "flow_1_id": 1,
  "flow_2_id": 2,
  "separate_flows": true
}
```

## Phân tích

Hai destination port khác nhau tạo hai flow ID riêng, không bị gộp nhầm. Output thực tế trùng khớp hoàn toàn với expected.

## Kết luận

**PASS**, exit code `0`. Bằng chứng: [`run.log`](run.log), [`actual.json`](actual.json), [`exit_code.txt`](exit_code.txt).
