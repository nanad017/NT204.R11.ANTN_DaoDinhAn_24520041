# Báo cáo kiểm thử Assignment 2

## 1. Cấu trúc bằng chứng

```text
TEST/assignment2/
├── result.md
├── T01/
│   ├── input.json
│   ├── expected.json
│   ├── actual.json
│   ├── command.txt
│   ├── run.log
│   ├── exit_code.txt
│   └── result.md
├── ...
└── T14/
    └── các file bằng chứng giống T01
```

Mỗi test case có input, expected, actual, lệnh chạy, log, exit code và báo cáo PASS/FAIL, cùng cách trình bày với các assignment còn lại.

## 2. Cách chạy

```bash
uv run --with scapy==2.7.0 --with pytest python -m pytest -q tests/test_assignment2.py
```

Chạy riêng một case:

```bash
uv run --with scapy==2.7.0 --with pytest python -m pytest -q tests/test_assignment2.py::test_t01_http_url_decoding_preserves_raw_uri
```

Môi trường: `Linux-7.3.1-1-cachyos-x86_64-with-glibc2.44`, Python `3.12.13`, Scapy `2.7.0`, pytest `9.2.0`.

## 3. Kết quả tổng hợp

- T01–T14: **14/14 PASS**, 0 FAIL.
- PCAP integration: **PASS** (12/12 scenario).
- `tests/test_assignment2.py`: **PASS** — `21 passed in 0.04s`.
- Toàn project: **PASS** — `149 passed in 0.16s`.

| Test | Nội dung theo PDF | Trạng thái | Bằng chứng |
|---|---|---|---|
| T01 | HTTP URL decode | PASS | [T01/result.md](T01/result.md) |
| T02 | HTML entity | PASS | [T02/result.md](T02/result.md) |
| T03 | SMTP Base64 và Quoted-Printable | PASS | [T03/result.md](T03/result.md) |
| T04 | Invalid UTF-8 bytes | PASS | [T04/result.md](T04/result.md) |
| T05 | Normalization | PASS | [T05/result.md](T05/result.md) |
| T06 | Missing fields | PASS | [T06/result.md](T06/result.md) |
| T07 | TCP handshake | PASS | [T07/result.md](T07/result.md) |
| T08 | Bidirectional flow | PASS | [T08/result.md](T08/result.md) |
| T09 | TCP close và reset | PASS | [T09/result.md](T09/result.md) |
| T10 | UDP query/response | PASS | [T10/result.md](T10/result.md) |
| T11 | Concurrent flows | PASS | [T11/result.md](T11/result.md) |
| T12 | Idle timeout | PASS | [T12/result.md](T12/result.md) |
| T13 | Flow statistics | PASS | [T13/result.md](T13/result.md) |
| T14 | Malformed event | PASS | [T14/result.md](T14/result.md) |

---

## 4. Chi tiết T01–T14

## T01 – HTTP URL decode

### Test dùng

- Pytest: `tests/test_assignment2.py::test_t01_http_url_decoding_preserves_raw_uri`
- Lệnh chạy trực tiếp:

```bash
uv run --with scapy==2.7.0 --with pytest python -m pytest -q tests/test_assignment2.py::test_t01_http_url_decoding_preserves_raw_uri
```

### Input

```json
{
  "url": "/search?q=%27%20OR%201%3D1+literal"
}
```

### Mong đợi

```json
{
  "decoded_query": "q=' OR 1=1+literal",
  "decoded_url": "/search?q=' OR 1=1+literal",
  "decoder_status": "success",
  "raw_url": "/search?q=%27%20OR%201%3D1+literal"
}
```

### Output thực tế

```json
{
  "decoded_query": "q=' OR 1=1+literal",
  "decoded_url": "/search?q=' OR 1=1+literal",
  "decoder_status": "success",
  "raw_url": "/search?q=%27%20OR%201%3D1+literal"
}
```

### Phân tích

Percent-encoding được giải mã nhưng raw URI vẫn được bảo toàn; dấu `+` trong URI không bị đổi sai thành khoảng trắng. Output thực tế trùng khớp hoàn toàn với expected.

### Kết luận

**PASS**, exit code `0`. Bằng chứng: [`run.log`](T01/run.log), [`actual.json`](T01/actual.json), [`exit_code.txt`](T01/exit_code.txt).


---

## T02 – HTML entity

### Test dùng

- Pytest: `tests/test_assignment2.py::test_t02_html_entity_decoding_is_separate_from_raw_body`
- Lệnh chạy trực tiếp:

```bash
uv run --with scapy==2.7.0 --with pytest python -m pytest -q tests/test_assignment2.py::test_t02_html_entity_decoding_is_separate_from_raw_body
```

### Input

```json
{
  "body": "&lt;script&gt;alert(1)&lt;/script&gt;",
  "content_type": "text/html"
}
```

### Mong đợi

```json
{
  "decoder_status": "success",
  "html_decoded_body": "<script>alert(1)</script>",
  "raw_body": "&lt;script&gt;alert(1)&lt;/script&gt;"
}
```

### Output thực tế

```json
{
  "decoder_status": "success",
  "html_decoded_body": "<script>alert(1)</script>",
  "raw_body": "&lt;script&gt;alert(1)&lt;/script&gt;"
}
```

### Phân tích

HTML entity được decode vào field riêng, raw body không bị thay đổi và decoder không phát sinh lỗi. Output thực tế trùng khớp hoàn toàn với expected.

### Kết luận

**PASS**, exit code `0`. Bằng chứng: [`run.log`](T02/run.log), [`actual.json`](T02/actual.json), [`exit_code.txt`](T02/exit_code.txt).


---

## T03 – SMTP Base64 và Quoted-Printable

### Test dùng

- Pytest: `tests/test_assignment2.py::test_t03_smtp_base64_and_quoted_printable_decode_when_header_identifies_it`
- Lệnh chạy trực tiếp:

```bash
uv run --with scapy==2.7.0 --with pytest python -m pytest -q tests/test_assignment2.py::test_t03_smtp_base64_and_quoted_printable_decode_when_header_identifies_it
```

### Input

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

### Mong đợi

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

### Output thực tế

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

### Phân tích

Decoder chỉ chọn Base64/Quoted-Printable khi MIME header chỉ ra encoding và ghi trạng thái thành công. Output thực tế trùng khớp hoàn toàn với expected.

### Kết luận

**PASS**, exit code `0`. Bằng chứng: [`run.log`](T03/run.log), [`actual.json`](T03/actual.json), [`exit_code.txt`](T03/exit_code.txt).


---

## T04 – Invalid UTF-8 bytes

### Test dùng

- Pytest: `tests/test_assignment2.py::test_t04_invalid_utf8_is_partial_and_does_not_raise`
- Lệnh chạy trực tiếp:

```bash
uv run --with scapy==2.7.0 --with pytest python -m pytest -q tests/test_assignment2.py::test_t04_invalid_utf8_is_partial_and_does_not_raise
```

### Input

```json
{
  "mime_payload": "Content-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n\r\n//4="
}
```

### Mong đợi

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

### Output thực tế

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

### Phân tích

Chuỗi UTF-8 lỗi được thay thế an toàn, ghi lỗi và trạng thái partial thay vì làm dừng chương trình. Output thực tế trùng khớp hoàn toàn với expected.

### Kết luận

**PASS**, exit code `0`. Bằng chứng: [`run.log`](T04/run.log), [`actual.json`](T04/actual.json), [`exit_code.txt`](T04/exit_code.txt).


---

## T05 – Normalization

### Test dùng

- Pytest: `tests/test_assignment2.py::test_t05_normalization_is_consistent_and_does_not_lower_uri`
- Lệnh chạy trực tiếp:

```bash
uv run --with scapy==2.7.0 --with pytest python -m pytest -q tests/test_assignment2.py::test_t05_normalization_is_consistent_and_does_not_lower_uri
```

### Input

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

### Mong đợi

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

### Output thực tế

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

### Phân tích

Protocol, app protocol, domain, header và timestamp được chuẩn hóa; URL phân biệt hoa thường vẫn giữ nguyên. Output thực tế trùng khớp hoàn toàn với expected.

### Kết luận

**PASS**, exit code `0`. Bằng chứng: [`run.log`](T05/run.log), [`actual.json`](T05/actual.json), [`exit_code.txt`](T05/exit_code.txt).


---

## T06 – Missing fields

### Test dùng

- Pytest: `tests/test_assignment2.py::test_t06_missing_fields_have_invalid_status_without_exception`
- Lệnh chạy trực tiếp:

```bash
uv run --with scapy==2.7.0 --with pytest python -m pytest -q tests/test_assignment2.py::test_t06_missing_fields_have_invalid_status_without_exception
```

### Input

```json
{
  "optional_missing": {},
  "required_missing": {
    "timestamp": "2026-01-01T00:00:00+00:00"
  }
}
```

### Mong đợi

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

### Output thực tế

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

### Phân tích

Field tùy chọn thiếu giữ giá trị `null`/`[]`; field bắt buộc thiếu được gom lỗi và xử lý theo policy retain. Output thực tế trùng khớp hoàn toàn với expected.

### Kết luận

**PASS**, exit code `0`. Bằng chứng: [`run.log`](T06/run.log), [`actual.json`](T06/actual.json), [`exit_code.txt`](T06/exit_code.txt).


---

## T07 – TCP handshake

### Test dùng

- Pytest: `tests/test_assignment2.py::test_t07_tcp_handshake_reaches_established_in_one_flow`
- Lệnh chạy trực tiếp:

```bash
uv run --with scapy==2.7.0 --with pytest python -m pytest -q tests/test_assignment2.py::test_t07_tcp_handshake_reaches_established_in_one_flow
```

### Input

```json
{
  "packets": [
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
    }
  ]
}
```

### Mong đợi

```json
{
  "active_flow_count": 1,
  "directions": [
    "forward",
    "backward",
    "forward"
  ],
  "flow_ids": [
    1,
    1,
    1
  ],
  "state": "ESTABLISHED"
}
```

### Output thực tế

```json
{
  "active_flow_count": 1,
  "directions": [
    "forward",
    "backward",
    "forward"
  ],
  "flow_ids": [
    1,
    1,
    1
  ],
  "state": "ESTABLISHED"
}
```

### Phân tích

SYN, SYN/ACK và ACK cùng flow ID; packet ACK cuối đưa TCP flow sang ESTABLISHED. Output thực tế trùng khớp hoàn toàn với expected.

### Kết luận

**PASS**, exit code `0`. Bằng chứng: [`run.log`](T07/run.log), [`actual.json`](T07/actual.json), [`exit_code.txt`](T07/exit_code.txt).


---

## T08 – Bidirectional flow

### Test dùng

- Pytest: `tests/test_assignment2.py::test_t08_bidirectional_packets_share_id_and_direction_is_stable`
- Lệnh chạy trực tiếp:

```bash
uv run --with scapy==2.7.0 --with pytest python -m pytest -q tests/test_assignment2.py::test_t08_bidirectional_packets_share_id_and_direction_is_stable
```

### Input

```json
{
  "backward": {
    "dest_ip": "192.0.2.1",
    "dest_port": 50000,
    "src_ip": "198.51.100.1",
    "src_port": 80
  },
  "forward": {
    "dest_ip": "198.51.100.1",
    "dest_port": 80,
    "src_ip": "192.0.2.1",
    "src_port": 50000
  }
}
```

### Mong đợi

```json
{
  "active_flow_count": 1,
  "backward_direction": "backward",
  "backward_flow_id": 1,
  "forward_direction": "forward",
  "forward_flow_id": 1
}
```

### Output thực tế

```json
{
  "active_flow_count": 1,
  "backward_direction": "backward",
  "backward_flow_id": 1,
  "forward_direction": "forward",
  "forward_flow_id": 1
}
```

### Phân tích

Five-tuple đảo chiều được chuẩn hóa về cùng flow key và hướng backward được gắn đúng. Output thực tế trùng khớp hoàn toàn với expected.

### Kết luận

**PASS**, exit code `0`. Bằng chứng: [`run.log`](T08/run.log), [`actual.json`](T08/actual.json), [`exit_code.txt`](T08/exit_code.txt).


---

## T09 – TCP close và reset

### Test dùng

- Pytest: `tests/test_assignment2.py::test_t09_fin_close_and_rst_are_terminal_states`
- Lệnh chạy trực tiếp:

```bash
uv run --with scapy==2.7.0 --with pytest python -m pytest -q tests/test_assignment2.py::test_t09_fin_close_and_rst_are_terminal_states
```

### Input

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

### Mong đợi

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

### Output thực tế

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

### Phân tích

FIN từ hai hướng tạo CLOSED; RST tạo RESET; cả hai flow terminal được loại khỏi active table. Output thực tế trùng khớp hoàn toàn với expected.

### Kết luận

**PASS**, exit code `0`. Bằng chứng: [`run.log`](T09/run.log), [`actual.json`](T09/actual.json), [`exit_code.txt`](T09/exit_code.txt).


---

## T10 – UDP query/response

### Test dùng

- Pytest: `tests/test_assignment2.py::test_t10_udp_query_response_is_one_bidirectional_flow`
- Lệnh chạy trực tiếp:

```bash
uv run --with scapy==2.7.0 --with pytest python -m pytest -q tests/test_assignment2.py::test_t10_udp_query_response_is_one_bidirectional_flow
```

### Input

```json
{
  "query": {
    "event": {
      "dest_port": 53,
      "packet_length": 60,
      "proto": "UDP",
      "src_port": 53000
    },
    "udp": {
      "length": 40,
      "payload_length": 32
    }
  },
  "response": {
    "event": {
      "dest_ip": "192.0.2.1",
      "dest_port": 53000,
      "packet_length": 100,
      "proto": "UDP",
      "src_ip": "198.51.100.1",
      "src_port": 53
    },
    "udp": {
      "length": 80,
      "payload_length": 72
    }
  }
}
```

### Mong đợi

```json
{
  "backward_byte_count": 100,
  "backward_packet_count": 1,
  "byte_count": 160,
  "duration": 0.0,
  "flow_id": 1,
  "forward_byte_count": 60,
  "forward_packet_count": 1,
  "packet_count": 2,
  "protocol": "UDP",
  "state": "NEW"
}
```

### Output thực tế

```json
{
  "backward_byte_count": 100,
  "backward_packet_count": 1,
  "byte_count": 160,
  "duration": 0.0,
  "flow_id": 1,
  "forward_byte_count": 60,
  "forward_packet_count": 1,
  "packet_count": 2,
  "protocol": "UDP",
  "state": "NEW"
}
```

### Phân tích

DNS-like UDP query/response cùng flow; packet và byte counter được tách đúng hai chiều. Output thực tế trùng khớp hoàn toàn với expected.

### Kết luận

**PASS**, exit code `0`. Bằng chứng: [`run.log`](T10/run.log), [`actual.json`](T10/actual.json), [`exit_code.txt`](T10/exit_code.txt).


---

## T11 – Concurrent flows

### Test dùng

- Pytest: `tests/test_assignment2.py::test_t11_concurrent_five_tuples_remain_separate`
- Lệnh chạy trực tiếp:

```bash
uv run --with scapy==2.7.0 --with pytest python -m pytest -q tests/test_assignment2.py::test_t11_concurrent_five_tuples_remain_separate
```

### Input

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

### Mong đợi

```json
{
  "active_flow_count": 2,
  "flow_1_id": 1,
  "flow_2_id": 2,
  "separate_flows": true
}
```

### Output thực tế

```json
{
  "active_flow_count": 2,
  "flow_1_id": 1,
  "flow_2_id": 2,
  "separate_flows": true
}
```

### Phân tích

Hai destination port khác nhau tạo hai flow ID riêng, không bị gộp nhầm. Output thực tế trùng khớp hoàn toàn với expected.

### Kết luận

**PASS**, exit code `0`. Bằng chứng: [`run.log`](T11/run.log), [`actual.json`](T11/actual.json), [`exit_code.txt`](T11/exit_code.txt).


---

## T12 – Idle timeout

### Test dùng

- Pytest: `tests/test_assignment2.py::test_t12_idle_timeout_removes_flow_and_keeps_final_summary`
- Lệnh chạy trực tiếp:

```bash
uv run --with scapy==2.7.0 --with pytest python -m pytest -q tests/test_assignment2.py::test_t12_idle_timeout_removes_flow_and_keeps_final_summary
```

### Input

```json
{
  "expire_time": "2026-01-01T00:00:05+00:00",
  "packet_time": "2026-01-01T00:00:00+00:00",
  "tcp_idle_timeout": 5,
  "udp_idle_timeout": 5
}
```

### Mong đợi

```json
{
  "active_flow_count": 0,
  "completed_packet_count": 1,
  "expired_count": 1
}
```

### Output thực tế

```json
{
  "active_flow_count": 0,
  "completed_packet_count": 1,
  "expired_count": 1
}
```

### Phân tích

Flow hết hạn chính xác tại idle timeout, rời active table nhưng summary cuối vẫn được giữ. Output thực tế trùng khớp hoàn toàn với expected.

### Kết luận

**PASS**, exit code `0`. Bằng chứng: [`run.log`](T12/run.log), [`actual.json`](T12/actual.json), [`exit_code.txt`](T12/exit_code.txt).


---

## T13 – Flow statistics

### Test dùng

- Pytest: `tests/test_assignment2.py::test_t13_statistics_count_full_packet_bytes_and_duration`
- Lệnh chạy trực tiếp:

```bash
uv run --with scapy==2.7.0 --with pytest python -m pytest -q tests/test_assignment2.py::test_t13_statistics_count_full_packet_bytes_and_duration
```

### Input

```json
{
  "packets": [
    {
      "flags": [
        "SYN"
      ],
      "packet_length": 60,
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
      "packet_length": 60,
      "timestamp": "2026-01-01T00:00:01+00:00"
    },
    {
      "flags": [
        "ACK"
      ],
      "packet_length": 52,
      "timestamp": "2026-01-01T00:00:02+00:00"
    },
    {
      "flags": [
        "ACK",
        "PSH"
      ],
      "packet_length": 100,
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
      "packet_length": 60,
      "timestamp": "2026-01-01T00:00:05+00:00"
    }
  ]
}
```

### Mong đợi

```json
{
  "ack_count": 4,
  "backward_byte_count": 120,
  "backward_packet_count": 2,
  "byte_count": 332,
  "duration": 5.0,
  "established": true,
  "fin_count": 1,
  "forward_byte_count": 212,
  "forward_packet_count": 3,
  "packet_count": 5,
  "rst_count": 0,
  "state": "CLOSING",
  "syn_count": 2
}
```

### Output thực tế

```json
{
  "ack_count": 4,
  "backward_byte_count": 120,
  "backward_packet_count": 2,
  "byte_count": 332,
  "duration": 5.0,
  "established": true,
  "fin_count": 1,
  "forward_byte_count": 212,
  "forward_packet_count": 3,
  "packet_count": 5,
  "rst_count": 0,
  "state": "CLOSING",
  "syn_count": 2
}
```

### Phân tích

Packet/byte counter hai chiều, SYN/ACK/FIN/RST counter và duration đều phản ánh đúng chuỗi TCP. Output thực tế trùng khớp hoàn toàn với expected.

### Kết luận

**PASS**, exit code `0`. Bằng chứng: [`run.log`](T13/run.log), [`actual.json`](T13/actual.json), [`exit_code.txt`](T13/exit_code.txt).


---

## T14 – Malformed event

### Test dùng

- Pytest: `tests/test_assignment2.py::test_t14_malformed_event_is_safe_and_meaningful`
- Lệnh chạy trực tiếp:

```bash
uv run --with scapy==2.7.0 --with pytest python -m pytest -q tests/test_assignment2.py::test_t14_malformed_event_is_safe_and_meaningful
```

### Input

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

### Mong đợi

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

### Output thực tế

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

### Phân tích

Event malformed được đánh dấu invalid với lý do đầy đủ; FlowTracker từ chối tạo flow và không crash. Output thực tế trùng khớp hoàn toàn với expected.

### Kết luận

**PASS**, exit code `0`. Bằng chứng: [`run.log`](T14/run.log), [`actual.json`](T14/actual.json), [`exit_code.txt`](T14/exit_code.txt).


---

## 5. Kiểm thử integration với PCAP

Các capture của Assignment 1 được chạy lại qua pipeline Parser → Decoder → Preprocessor → FlowTracker. Không lưu bản sao PCAP hoặc JSONL mới trong Assignment 2 để tránh dữ liệu dư.

| Input | Packet events | Flow summaries | Exit code | Kết quả |
|---|---:|---:|---:|---|
| `dns_query` | 38 | 9 | 0 | PASS |
| `dns_response` | 38 | 9 | 0 | PASS |
| `http_get` | 43 | 4 | 0 | PASS |
| `http_post` | 220 | 1 | 0 | PASS |
| `http_response` | 43 | 4 | 0 | PASS |
| `smtp_command` | 60 | 4 | 0 | PASS |
| `smtp_response` | 60 | 4 | 0 | PASS |
| `tcp_data` | 11 | 2 | 0 | PASS |
| `tcp_handshake` | 11 | 2 | 0 | PASS |
| `udp` | 314 | 5 | 0 | PASS |
| `unknown` | 1 | 0 | 0 | PASS |
| `malformed` | 0 | 0 | 1 | PASS (lỗi input có kiểm soát) |

## 6. Test bổ sung

Ngoài T01–T14, `tests/test_assignment2.py` còn kiểm tra thứ tự pipeline, flush cuối capture, tái sử dụng five-tuple sau reset, timestamp không theo thứ tự, TCP capture không đầy đủ, port lỗi, MIME encoding không hỗ trợ và giới hạn kích thước decode.

## 7. Kết luận

Decoder, Preprocessor và Flow/Connection Tracker đáp ứng toàn bộ T01–T14 của PDF. Lỗi decode/normalize/track được cô lập; timeout, size limit và policy đều cấu hình được. Bộ test có thể chạy lại tự động và toàn bộ output dùng để kết luận đều được lưu trong `TEST/assignment2`.
