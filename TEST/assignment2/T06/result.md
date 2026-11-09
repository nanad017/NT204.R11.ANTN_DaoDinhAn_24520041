# T06 – Missing fields

## Test dùng

- Pytest: `tests/test_assignment2.py::test_t06_missing_fields_have_invalid_status_without_exception`
- Lệnh chạy trực tiếp:

```bash
uv run --with scapy==2.7.0 --with pytest python -m pytest -q tests/test_assignment2.py::test_t06_missing_fields_have_invalid_status_without_exception
```

## Input

```json
{
  "optional_missing": {},
  "required_missing": {
    "timestamp": "2026-01-01T00:00:00+00:00"
  }
}
```

## Mong đợi

```json
{
  "optional_missing": {
    "dns": null,
    "email": null,
    "http": null,
    "parser_errors": [],
    "preprocess_status": "valid",
    "smtp": null
  },
  "required_missing": {
    "errors": [
      "src_ip is required",
      "dest_ip is required",
      "transport protocol is missing"
    ],
    "processing_action": "retain",
    "reason": "src_ip is required; dest_ip is required; transport protocol is missing",
    "status": "invalid"
  }
}
```

## Output thực tế

```json
{
  "optional_missing": {
    "dns": null,
    "email": null,
    "http": null,
    "parser_errors": [],
    "preprocess_status": "valid",
    "smtp": null
  },
  "required_missing": {
    "errors": [
      "src_ip is required",
      "dest_ip is required",
      "transport protocol is missing"
    ],
    "processing_action": "retain",
    "reason": "src_ip is required; dest_ip is required; transport protocol is missing",
    "status": "invalid"
  }
}
```

## Phân tích

Field tùy chọn thiếu giữ giá trị `null`/`[]`; field bắt buộc thiếu được gom lỗi và xử lý theo policy retain. Output thực tế trùng khớp hoàn toàn với expected.

## Kết luận

**PASS**, exit code `0`. Bằng chứng: [`run.log`](run.log), [`actual.json`](actual.json), [`exit_code.txt`](exit_code.txt).
