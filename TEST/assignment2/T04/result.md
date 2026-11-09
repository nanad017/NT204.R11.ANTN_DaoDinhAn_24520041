# T04 – Invalid UTF-8 bytes

## Test dùng

- Pytest: `tests/test_assignment2.py::test_t04_invalid_utf8_is_partial_and_does_not_raise`
- Lệnh chạy trực tiếp:

```bash
uv run --with scapy==2.7.0 --with pytest python -m pytest -q tests/test_assignment2.py::test_t04_invalid_utf8_is_partial_and_does_not_raise
```

## Input

```json
{
  "mime_payload": "Content-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n\r\n//4="
}
```

## Mong đợi

```json
{
  "decoded_body": "��",
  "decoder_errors": [
    "MIME character decoding: invalid character sequence"
  ],
  "decoder_status": "partial",
  "email_decode_status": "partial"
}
```

## Output thực tế

```json
{
  "decoded_body": "��",
  "decoder_errors": [
    "MIME character decoding: invalid character sequence"
  ],
  "decoder_status": "partial",
  "email_decode_status": "partial"
}
```

## Phân tích

Chuỗi UTF-8 lỗi được thay thế an toàn, ghi lỗi và trạng thái partial thay vì làm dừng chương trình. Output thực tế trùng khớp hoàn toàn với expected.

## Kết luận

**PASS**, exit code `0`. Bằng chứng: [`run.log`](run.log), [`actual.json`](actual.json), [`exit_code.txt`](exit_code.txt).
