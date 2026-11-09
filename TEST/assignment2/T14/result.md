# T14 – Malformed event

## Test dùng

- Pytest: `tests/test_assignment2.py::test_t14_malformed_event_is_safe_and_meaningful`
- Lệnh chạy trực tiếp:

```bash
uv run --with scapy==2.7.0 --with pytest python -m pytest -q tests/test_assignment2.py::test_t14_malformed_event_is_safe_and_meaningful
```

## Input

```json
{
  "event": {
    "dest_ip": "198.51.100.1",
    "dest_port": 80,
    "proto": "TCP",
    "src_ip": "not-an-ip",
    "src_port": 70000,
    "timestamp": "not-a-timestamp"
  },
  "invalid_event_policy": "retain"
}
```

## Mong đợi

```json
{
  "flow_result": null,
  "preprocess_errors": [
    "timestamp is not ISO-8601",
    "src_ip is invalid",
    "src_port must be an integer in range 0..65535"
  ],
  "preprocess_status": "invalid",
  "processing_action": "retain",
  "reason": "timestamp is not ISO-8601; src_ip is invalid; src_port must be an integer in range 0..65535"
}
```

## Output thực tế

```json
{
  "flow_result": null,
  "preprocess_errors": [
    "timestamp is not ISO-8601",
    "src_ip is invalid",
    "src_port must be an integer in range 0..65535"
  ],
  "preprocess_status": "invalid",
  "processing_action": "retain",
  "reason": "timestamp is not ISO-8601; src_ip is invalid; src_port must be an integer in range 0..65535"
}
```

## Phân tích

Event malformed được đánh dấu invalid với lý do đầy đủ; FlowTracker từ chối tạo flow và không crash. Output thực tế trùng khớp hoàn toàn với expected.

## Kết luận

**PASS**, exit code `0`. Bằng chứng: [`run.log`](run.log), [`actual.json`](actual.json), [`exit_code.txt`](exit_code.txt).
