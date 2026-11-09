# T02 – HTML entity

## Test dùng

- Pytest: `tests/test_assignment2.py::test_t02_html_entity_decoding_is_separate_from_raw_body`
- Lệnh chạy trực tiếp:

```bash
uv run --with scapy==2.7.0 --with pytest python -m pytest -q tests/test_assignment2.py::test_t02_html_entity_decoding_is_separate_from_raw_body
```

## Input

```json
{
  "body": "&lt;script&gt;alert(1)&lt;/script&gt;",
  "content_type": "text/html"
}
```

## Mong đợi

```json
{
  "decoder_status": "success",
  "html_decoded_body": "<script>alert(1)</script>",
  "raw_body": "&lt;script&gt;alert(1)&lt;/script&gt;"
}
```

## Output thực tế

```json
{
  "decoder_status": "success",
  "html_decoded_body": "<script>alert(1)</script>",
  "raw_body": "&lt;script&gt;alert(1)&lt;/script&gt;"
}
```

## Phân tích

HTML entity được decode vào field riêng, raw body không bị thay đổi và decoder không phát sinh lỗi. Output thực tế trùng khớp hoàn toàn với expected.

## Kết luận

**PASS**, exit code `0`. Bằng chứng: [`run.log`](run.log), [`actual.json`](actual.json), [`exit_code.txt`](exit_code.txt).
