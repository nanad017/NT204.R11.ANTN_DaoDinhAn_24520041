# T05 – Normalization

## Test dùng

- Pytest: `tests/test_assignment2.py::test_t05_normalization_is_consistent_and_does_not_lower_uri`
- Lệnh chạy trực tiếp:

```bash
uv run --with scapy==2.7.0 --with pytest python -m pytest -q tests/test_assignment2.py::test_t05_normalization_is_consistent_and_does_not_lower_uri
```

## Input

```json
{
  "app_proto": "HTTP",
  "header_name": "Host",
  "hostname": "Example.TEST.",
  "proto": "tcp",
  "timestamp": "2026-01-01T00:00:00Z",
  "url": "/CaseSensitive/Path"
}
```

## Mong đợi

```json
{
  "app_proto": "http",
  "header_name": "host",
  "hostname": "example.test",
  "normalized_url": "/CaseSensitive/Path",
  "original_header_name": "Host",
  "original_values": {
    "app_proto": "HTTP",
    "http.header:Host": "Host",
    "http.hostname": "Example.TEST.",
    "proto": "tcp",
    "timestamp": "2026-01-01T00:00:00Z"
  },
  "preprocess_status": "valid",
  "proto": "TCP",
  "timestamp": "2026-01-01T00:00:00+00:00",
  "url": "/CaseSensitive/Path"
}
```

## Output thực tế

```json
{
  "app_proto": "http",
  "header_name": "host",
  "hostname": "example.test",
  "normalized_url": "/CaseSensitive/Path",
  "original_header_name": "Host",
  "original_values": {
    "app_proto": "HTTP",
    "http.header:Host": "Host",
    "http.hostname": "Example.TEST.",
    "proto": "tcp",
    "timestamp": "2026-01-01T00:00:00Z"
  },
  "preprocess_status": "valid",
  "proto": "TCP",
  "timestamp": "2026-01-01T00:00:00+00:00",
  "url": "/CaseSensitive/Path"
}
```

## Phân tích

Protocol, app protocol, domain, header và timestamp được chuẩn hóa; URL phân biệt hoa thường vẫn giữ nguyên. Output thực tế trùng khớp hoàn toàn với expected.

## Kết luận

**PASS**, exit code `0`. Bằng chứng: [`run.log`](run.log), [`actual.json`](actual.json), [`exit_code.txt`](exit_code.txt).
