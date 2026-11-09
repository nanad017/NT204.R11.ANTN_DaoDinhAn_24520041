# T03 – SMTP Base64 và Quoted-Printable

## Test dùng

- Pytest: `tests/test_assignment2.py::test_t03_smtp_base64_and_quoted_printable_decode_when_header_identifies_it`
- Lệnh chạy trực tiếp:

```bash
uv run --with scapy==2.7.0 --with pytest python -m pytest -q tests/test_assignment2.py::test_t03_smtp_base64_and_quoted_printable_decode_when_header_identifies_it
```

## Input

```json
{
  "base64": {
    "mime_payload": "Content-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n\r\nSGVsbG8gV29ybGQh"
  },
  "quoted_printable": {
    "mime_payload": "Content-Type: text/plain\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\nHello=20world!"
  }
}
```

## Mong đợi

```json
{
  "base64": {
    "decode_status": "success",
    "decoded_body": "Hello World!",
    "encoding": "base64"
  },
  "quoted_printable": {
    "decode_status": "success",
    "decoded_body": "Hello world!",
    "encoding": "quoted-printable"
  }
}
```

## Output thực tế

```json
{
  "base64": {
    "decode_status": "success",
    "decoded_body": "Hello World!",
    "encoding": "base64"
  },
  "quoted_printable": {
    "decode_status": "success",
    "decoded_body": "Hello world!",
    "encoding": "quoted-printable"
  }
}
```

## Phân tích

Decoder chỉ chọn Base64/Quoted-Printable khi MIME header chỉ ra encoding và ghi trạng thái thành công. Output thực tế trùng khớp hoàn toàn với expected.

## Kết luận

**PASS**, exit code `0`. Bằng chứng: [`run.log`](run.log), [`actual.json`](actual.json), [`exit_code.txt`](exit_code.txt).
