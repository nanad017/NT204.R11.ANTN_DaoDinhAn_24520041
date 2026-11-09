# T01 – HTTP URL decode

## Test dùng

- Pytest: `tests/test_assignment2.py::test_t01_http_url_decoding_preserves_raw_uri`
- Lệnh chạy trực tiếp:

```bash
uv run --with scapy==2.7.0 --with pytest python -m pytest -q tests/test_assignment2.py::test_t01_http_url_decoding_preserves_raw_uri
```

## Input

```json
{
  "url": "/search?q=%27%20OR%201%3D1+literal"
}
```

## Mong đợi

```json
{
  "decoded_query": "q=' OR 1=1+literal",
  "decoded_url": "/search?q=' OR 1=1+literal",
  "decoder_status": "success",
  "raw_url": "/search?q=%27%20OR%201%3D1+literal"
}
```

## Output thực tế

```json
{
  "decoded_query": "q=' OR 1=1+literal",
  "decoded_url": "/search?q=' OR 1=1+literal",
  "decoder_status": "success",
  "raw_url": "/search?q=%27%20OR%201%3D1+literal"
}
```

## Phân tích

Percent-encoding được giải mã nhưng raw URI vẫn được bảo toàn; dấu `+` trong URI không bị đổi sai thành khoảng trắng. Output thực tế trùng khớp hoàn toàn với expected.

## Kết luận

**PASS**, exit code `0`. Bằng chứng: [`run.log`](run.log), [`actual.json`](actual.json), [`exit_code.txt`](exit_code.txt).
