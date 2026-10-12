# Báo cáo kiểm thử Assignment 2

## 1. Thông tin chạy test

File test:

    tests/test_assignment2.py

Lệnh chạy:

    .venv/bin/python -m pytest -q tests/test_assignment2.py

Kết quả:

    21 passed

Trong đó có 14 test bắt buộc T01–T14 và các test bổ sung về pipeline, flush,
timestamp, five-tuple reuse, MIME không hỗ trợ và giới hạn kích thước.

Kiểm tra toàn bộ project:

    .venv/bin/python -m pytest -q

Kết quả:

    49 passed

Các input dưới đây là input trực tiếp của từng test. Output là giá trị thực tế
được lấy lại khi chạy code hiện tại.

---

## T01 – HTTP URL decoding

### Test dùng

    test_t01_http_url_decoding_preserves_raw_uri()

### Input

    HTTPInfo(
        url="/search?q=%27%20OR%201%3D1+literal"
    )

### Mong đợi

- Giải mã các mã percent như %27, %20 và %3D.
- Giữ nguyên URL gốc.
- Dấu + trong URI thông thường không tự đổi thành khoảng trắng.

### Output thực tế

    {
      "raw_url": "/search?q=%27%20OR%201%3D1+literal",
      "decoded_url": "/search?q=' OR 1=1+literal",
      "decoded_query": "q=' OR 1=1+literal",
      "status": "success"
    }

### Phân tích

Kết quả đạt yêu cầu. raw_url vẫn giữ nguyên để phục vụ phân tích bảo mật,
còn decoded_url và decoded_query được lưu riêng sau khi giải mã.

---

## T02 – HTML entity decoding

### Test dùng

    test_t02_html_entity_decoding_is_separate_from_raw_body()

### Input

    HTTPInfo(
        body="&lt;script&gt;alert(1)&lt;/script&gt;",
        http_content_type="text/html"
    )

### Mong đợi

- Giải mã &lt; thành < và &gt; thành >.
- Giữ nguyên body gốc.
- Không làm chương trình dừng.

### Output thực tế

    {
      "raw_body": "&lt;script&gt;alert(1)&lt;/script&gt;",
      "html_decoded_body": "<script>alert(1)</script>",
      "status": "success"
    }

### Phân tích

Kết quả đạt yêu cầu. Dữ liệu gốc và dữ liệu HTML đã decode nằm ở hai field
khác nhau, nên không làm mất thông tin ban đầu.

---

## T03 – SMTP Base64 và Quoted-Printable

### Test dùng

    test_t03_smtp_base64_and_quoted_printable_decode_when_header_identifies_it()

### Input

Base64:

    Content-Type: text/plain; charset=utf-8
    Content-Transfer-Encoding: base64

    SGVsbG8gV29ybGQh

Quoted-Printable:

    Content-Type: text/plain
    Content-Transfer-Encoding: quoted-printable

    Hello=20world!

### Mong đợi

- Chỉ decode khi header xác định encoding.
- Base64 cho ra Hello World!.
- Quoted-Printable cho ra Hello world!.
- Trạng thái decode là success.

### Output thực tế

    {
      "base64": {
        "decoded_body": "Hello World!",
        "decode_status": "success",
        "encoding": "base64"
      },
      "quoted_printable": {
        "decoded_body": "Hello world!",
        "decode_status": "success",
        "encoding": "quoted-printable"
      }
    }

### Phân tích

Kết quả đạt yêu cầu. Decoder không decode mù payload SMTP mà đọc
Content-Transfer-Encoding trước rồi mới chọn cách giải mã.

---

## T04 – Invalid UTF-8

### Test dùng

    test_t04_invalid_utf8_is_partial_and_does_not_raise()

### Input

    Content-Type: text/plain; charset=utf-8
    Content-Transfer-Encoding: base64

    //4=

Sau Base64 decode, dữ liệu là byte không hợp lệ với UTF-8.

### Mong đợi

- Không phát sinh exception làm dừng xử lý.
- Trạng thái là partial.
- Có thông tin lỗi character decoding.

### Output thực tế

    {
      "decoder_status": "partial",
      "email_decode_status": "partial",
      "decoded_body": "��",
      "errors": [
        "MIME character decoding: invalid character sequence"
      ]
    }

### Phân tích

Kết quả đạt yêu cầu. Byte lỗi được thay bằng ký tự thay thế �, đồng thời
Decoder ghi trạng thái partial và tiếp tục xử lý.

---

## T05 – Normalization

### Test dùng

    test_t05_normalization_is_consistent_and_does_not_lower_uri()

### Input

    {
      "proto": "tcp",
      "app_proto": "HTTP",
      "timestamp": "2026-01-01T00:00:00Z",
      "hostname": "Example.TEST.",
      "header_name": "Host",
      "url": "/CaseSensitive/Path"
    }

### Mong đợi

- Protocol được chuẩn hóa thành chữ hoa.
- Application protocol được chuẩn hóa thành chữ thường.
- Domain được chuẩn hóa thành chữ thường và bỏ dấu chấm cuối.
- HTTP header name được chuẩn hóa nhưng giữ original_name.
- Không chuyển path URL thành chữ thường.
- Timestamp được đưa về dạng UTC ISO-8601.

### Output thực tế

    {
      "proto": "TCP",
      "app_proto": "http",
      "hostname": "example.test",
      "header_name": "host",
      "original_header_name": "Host",
      "url": "/CaseSensitive/Path",
      "normalized_url": "/CaseSensitive/Path",
      "timestamp": "2026-01-01T00:00:00+00:00",
      "status": "valid",
      "original_values": {
        "proto": "tcp",
        "app_proto": "HTTP",
        "timestamp": "2026-01-01T00:00:00Z",
        "http.hostname": "Example.TEST.",
        "http.header:Host": "Host"
      }
    }

### Phân tích

Kết quả đạt yêu cầu. Các giá trị an toàn để chuẩn hóa được thay đổi, còn
giá trị gốc vẫn được lưu trong original_values hoặc original_name.

---

## T06 – Missing fields

### Test dùng

    test_t06_missing_fields_have_invalid_status_without_exception()

### Input

    {
      "timestamp": "2026-01-01T00:00:00+00:00",
      "src_ip": null,
      "dest_ip": null,
      "proto": null
    }

### Mong đợi

- Không phát sinh exception.
- Event được đánh dấu invalid.
- Chính sách mặc định retain được áp dụng.
- Có reason mô tả các field bị thiếu.

### Output thực tế

    {
      "status": "invalid",
      "processing_action": "retain",
      "reason": "src_ip is required; dest_ip is required; transport protocol is missing",
      "errors": [
        "src_ip is required",
        "dest_ip is required",
        "transport protocol is missing"
      ]
    }

### Phân tích

Kết quả đạt yêu cầu. Preprocessor gom nhiều lỗi trong cùng một event thay vì
dừng ngay ở lỗi đầu tiên.

---

## T07 – TCP handshake

### Test dùng

    test_t07_tcp_handshake_reaches_established_in_one_flow()

### Input

    Packet 1: SYN       A:50000 -> B:80
    Packet 2: SYN/ACK   B:80    -> A:50000
    Packet 3: ACK       A:50000 -> B:80

### Mong đợi

- Ba packet dùng chung một flow_id.
- Flow chuyển sang ESTABLISHED.
- Chỉ có một flow active.
- Hướng packet được nhận diện đúng.

### Output thực tế

    {
      "flow_ids": [1, 1, 1],
      "state": "ESTABLISHED",
      "active_flow_count": 1,
      "directions": ["forward", "backward", "forward"]
    }

### Phân tích

Kết quả đạt yêu cầu. Flow được tạo từ SYN đầu tiên, SYN/ACK được xác định là
hướng ngược lại và ACK cuối hoàn tất handshake.

---

## T08 – Bidirectional flow

### Test dùng

    test_t08_bidirectional_packets_share_id_and_direction_is_stable()

### Input

    Forward:  192.0.2.1:50000 -> 198.51.100.1:80
    Backward: 198.51.100.1:80 -> 192.0.2.1:50000

### Mong đợi

- Hai chiều có cùng flow_id.
- Packet thứ hai có hướng backward.
- Không tạo flow thứ hai.

### Output thực tế

    {
      "forward_flow_id": 1,
      "backward_flow_id": 1,
      "backward_direction": "backward",
      "active_flow_count": 1
    }

### Phân tích

Kết quả đạt yêu cầu. _flow_key() sắp xếp hai endpoint để key không phụ thuộc
chiều truyền packet.

---

## T09 – TCP close và reset

### Test dùng

    test_t09_fin_close_and_rst_are_terminal_states()

### Input

Đóng bình thường:

    SYN -> SYN/ACK -> ACK -> FIN -> FIN/ACK

Đóng bất thường:

    RST

### Mong đợi

- FIN từ hai hướng đưa flow sang CLOSED.
- RST đưa flow sang RESET.
- Flow terminal bị xóa khỏi active table.
- Five-tuple sau đó có thể tạo flow instance mới.

### Output thực tế

    {
      "closed_state": "CLOSED",
      "active_after_close": 0,
      "reset_state": "RESET",
      "active_after_reset": 0,
      "flow_ids": [1, 2]
    }

### Phân tích

Kết quả đạt yêu cầu. Flow đóng bằng FIN và flow bị reset bằng RST đều được
finalize, xóa khỏi bảng active và giữ lại summary.

---

## T10 – UDP query/response

### Test dùng

    test_t10_udp_query_response_is_one_bidirectional_flow()

### Input

    Query:    192.0.2.1:53000 -> 198.51.100.1:53, 60 bytes
    Response: 198.51.100.1:53 -> 192.0.2.1:53000, 100 bytes

### Mong đợi

- Hai packet thuộc cùng một UDP flow.
- Tổng packet là 2.
- Tổng byte là 160.
- Mỗi hướng có 1 packet.
- UDP không cần TCP handshake.

### Output thực tế

    {
      "flow_id": 1,
      "state": "NEW",
      "protocol": "UDP",
      "packet_count": 2,
      "byte_count": 160,
      "forward_packet_count": 1,
      "forward_byte_count": 60,
      "backward_packet_count": 1,
      "backward_byte_count": 100,
      "duration": 0.0
    }

### Phân tích

Kết quả đạt yêu cầu. UDP dùng cùng cơ chế five-tuple hai chiều nhưng không có
state handshake; trạng thái mặc định vẫn là NEW.

---

## T11 – Concurrent flows

### Test dùng

    test_t11_concurrent_five_tuples_remain_separate()

### Input

    Flow 1: 192.0.2.1:50000 -> 198.51.100.1:80
    Flow 2: 192.0.2.1:50000 -> 198.51.100.1:443

### Mong đợi

- Hai five-tuple khác nhau phải có flow khác nhau.
- Không gộp port 80 và port 443 vào cùng flow.

### Output thực tế

    {
      "flow_1_id": 1,
      "flow_2_id": 2,
      "active_flow_count": 2
    }

### Phân tích

Kết quả đạt yêu cầu. Destination port là một phần của five-tuple nên hai
connection được tách biệt.

---

## T12 – Idle timeout

### Test dùng

    test_t12_idle_timeout_removes_flow_and_keeps_final_summary()

### Input

    {
      "protocol": "UDP",
      "packet_time": "2026-01-01T00:00:00+00:00",
      "idle_timeout": 5,
      "expire_time": "2026-01-01T00:00:05+00:00"
    }

### Mong đợi

- Flow hết hạn đúng tại mốc 5 giây.
- Flow bị xóa khỏi active table.
- Summary cuối vẫn được giữ lại.

### Output thực tế

    {
      "expired_count": 1,
      "active_flow_count": 0,
      "completed_packet_count": 1
    }

### Phân tích

Kết quả đạt yêu cầu. Test dùng timestamp truyền trực tiếp vào expire() nên
không phụ thuộc việc sleep hoặc wall-clock.

---

## T13 – Flow statistics

### Test dùng

    test_t13_statistics_count_full_packet_bytes_and_duration()

### Input

    Packet 1: length=70, time=00:00:00
    Packet 2: length=90, time=00:00:05

### Mong đợi

- Packet count là 2.
- Byte count là 70 + 90 = 160.
- Cả hai packet cùng hướng forward.
- Duration là 5 giây.

### Output thực tế

    {
      "flow_id": 1,
      "state": "NEW",
      "protocol": "UDP",
      "packet_count": 2,
      "byte_count": 160,
      "forward_packet_count": 2,
      "forward_byte_count": 160,
      "backward_packet_count": 0,
      "backward_byte_count": 0,
      "duration": 5.0
    }

### Phân tích

Kết quả đạt yêu cầu. Flow Tracker ưu tiên event.packet_length, vì vậy
byte_count là kích thước packet được cung cấp, không phải chỉ payload.

---

## T14 – Malformed event

### Test dùng

    test_t14_malformed_event_is_safe_and_meaningful()

### Input

    {
      "timestamp": "not-a-timestamp",
      "src_ip": "not-an-ip",
      "dest_ip": "198.51.100.1",
      "src_port": 70000,
      "dest_port": 80,
      "proto": "TCP"
    }

### Mong đợi

- Không crash.
- Preprocessor đánh dấu event là invalid.
- Ghi rõ lý do lỗi.
- Flow Tracker không tạo flow từ event không hợp lệ.

### Output thực tế

    {
      "preprocess_status": "invalid",
      "processing_action": "retain",
      "reason": "timestamp is not ISO-8601; src_ip is invalid; src_port must be an integer in range 0..65535",
      "flow_result": null
    }

### Phân tích

Kết quả đạt yêu cầu. Event được giữ lại để log theo policy retain, nhưng
không được đưa vào Flow Tracker vì endpoint không hợp lệ.

---

## 3. Kiểm thử integration với PCAP

Assignment 2 yêu cầu kiểm tra các module mới trong pipeline thật, không chỉ
gọi từng class riêng lẻ. Các PCAP dưới đây được chạy qua main.py bằng chế độ
offline capture.

Lệnh mẫu:

    .venv/bin/python main.py \
        --pcap TEST/assignment1/http_get/input.pcap \
        --output /tmp/http_get.jsonl \
        --flow-output /tmp/http_get.flows.jsonl \
        --overwrite

Trong bảng:

- event output là số dòng trong JSONL packet event.
- flow output là số dòng trong JSONL flow summary.
- exit code 0 là chạy thành công.
- malformed có exit code 1 vì input cố ý không phải capture hợp lệ; đây là
  kết quả mong đợi.

| PCAP input | Input dùng | Output thực tế | Phân tích | Kết quả |
|---|---|---|---|---|
| TEST/assignment1/dns_query/input.pcap | 38 packet DNS query | 38 event, 9 flow, exit 0 | Parser, Decoder không làm hỏng DNS; Flow Tracker gom được UDP flow | PASS |
| TEST/assignment1/dns_response/input.pcap | 38 packet DNS response | 38 event, 9 flow, exit 0 | DNS response đi qua pipeline và được xuất flow summary | PASS |
| TEST/assignment1/http_get/input.pcap | HTTP GET capture | 43 event, 4 flow, exit 0 | HTTP parser tạo event; Decoder và Preprocessor chạy trong pipeline | PASS |
| TEST/assignment1/http_post/input.pcap | HTTP POST capture có body | 220 event, 1 flow, exit 0 | HTTP body được đưa qua Decoder; flow output được tạo | PASS |
| TEST/assignment1/http_response/input.pcap | HTTP response capture | 43 event, 4 flow, exit 0 | HTTP response vẫn tương thích với pipeline mới | PASS |
| TEST/assignment1/smtp_command/input.pcap | SMTP command capture | 60 event, 4 flow, exit 0 | SMTP command được giữ nguyên; Decoder không decode mù command | PASS |
| TEST/assignment1/smtp_response/input.pcap | SMTP response capture | 60 event, 4 flow, exit 0 | SMTP response chạy qua parser và flow tracker không lỗi | PASS |
| TEST/assignment1/tcp_data/input.pcap | TCP có payload | 11 event, 2 flow, exit 0 | TCP packet có payload được đếm và gắn flow | PASS |
| TEST/assignment1/tcp_handshake/input.pcap | TCP handshake/data capture | 11 event, 2 flow, exit 0 | Pipeline xử lý được SYN, SYN/ACK, ACK và packet tiếp theo | PASS |
| TEST/assignment1/udp/input.pcapng | UDP capture | 314 event, 5 flow, exit 0 | UDP packet được parse, gom flow hai chiều và flush cuối PCAP | PASS |
| TEST/assignment1/unknown/input.pcap | IPv4 protocol không hỗ trợ | 1 event, 0 flow, exit 0 | Event được giữ lại nhưng không tạo flow TCP/UDP | PASS |
| TEST/assignment1/malformed/input.pcap | File capture cố ý không hợp lệ | 0 event, 0 flow, exit 1 | Chương trình báo lỗi có kiểm soát, không có unhandled traceback | PASS |

Output packet và flow của mỗi lần chạy có dạng:

    --output       JSONL chứa PacketEvent sau Parser, Decoder, Preprocessor và FlowTracker
    --flow-output  JSONL chứa FlowInfo sau khi flow được đóng hoặc flush

Kết quả cho thấy các stage Assignment 2 đã được gọi trong pipeline offline
thật, không chỉ được kiểm thử bằng event giả lập.

## 4. Kết luận

| Nhóm | Kết quả |
|---|---|
| Decoder HTTP | Đạt |
| Decoder SMTP/MIME | Đạt |
| Character decoding và lỗi malformed | Đạt |
| Preprocessor validation | Đạt |
| Preprocessor normalization | Đạt |
| TCP flow tracking | Đạt |
| UDP flow tracking | Đạt |
| Timeout và finalize | Đạt |
| Flow statistics | Đạt |
| T01–T14 | 14/14 PASS |
| PCAP integration | 12/12 PASS |
| Toàn bộ test project | 49 passed |

Các test bổ sung trong tests/test_assignment2.py cũng chạy thành công, gồm
integration pipeline, end-of-capture flush, five-tuple reuse, timestamp không
theo thứ tự, TCP capture không đầy đủ, MIME encoding không hỗ trợ và decoder
size limit.
