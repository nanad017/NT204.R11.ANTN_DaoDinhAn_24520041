# NT204.R11.ANTN_DaoDinhAn_24520041

## Kiến trúc hệ thống

Luồng xử lý của chương trình:

    Live interface hoặc PCAP
        -> Capture callback
        -> PacketPipeline
        -> IPv4 parser
        -> TCP hoặc UDP parser
        -> Application protocol detector
        -> HTTP, DNS, SMTP parser
        -> PacketEvent JSON Lines output

Cả live capture và PCAP đều được đưa vào cùng một pipeline xử lý.

## Cài đặt môi trường

Tạo virtual environment:

    python -m venv .venv

Kích hoạt môi trường:

    source .venv/bin/activate

Cài đặt các thư viện cần thiết:

    pip install -r requirement.txt

## Chạy chương trình

### Đọc packet từ file PCAP

    python main.py --pcap pcaps/sample.pcap

### Capture packet trực tiếp từ network interface

    sudo python main.py --interface eth0

### Thay đổi đường dẫn output

    python main.py --pcap pcaps/sample.pcap --output output/events.jsonl

### Ghi tiếp vào file JSON Lines hiện có

    python main.py --pcap pcaps/sample.pcap --append

Mặc định, các event sau khi parse được ghi vào:

    output/events.jsonl

Các log kỹ thuật của chương trình được ghi vào:

    logs/app.log

## Kiểm thử

Chạy toàn bộ automated test:

    python -m pytest -q

Bộ test tự động bao gồm các phần:

- Capture từ live interface và PCAP
- Schema serialization
- IPv4
- TCP
- UDP
- Application protocol detection
- HTTP
- DNS
- SMTP
- JSON Lines output
- CLI
- Khả năng cô lập lỗi trong pipeline

Các test case thủ công và kết quả kiểm thử được lưu trong các thư mục:

    TEST/assignment1/
    TEST/assignment2/

Report kiểm thử Assignment 1:

    TEST/assignment1/BAO_CAO_KIEM_THU.md

## Schema

Thiết kế cấu trúc dữ liệu output của project có tham khảo cách tổ chức event của Suricata.

Mỗi packet sau khi đi qua pipeline sẽ được chuyển thành một `PacketEvent` chuẩn hóa và có thể được xuất dưới dạng JSON Lines.

## AI Declaration

Trong quá trình thực hiện bài tập, em có sử dụng ChatGPT như một công cụ hỗ trợ lập trình.

ChatGPT được sử dụng để hỗ trợ:

- Gợi ý hướng triển khai và cấu trúc project.
- Hỗ trợ viết và chỉnh sửa code.
- Debug và phân tích lỗi.
- Kiểm tra một số trường hợp biên.
- Hỗ trợ xây dựng test case.
- Giải thích một số kiến thức liên quan đến mạng máy tính và Python.

AI được sử dụng trong phần lớn các thành phần của project, bao gồm packet capture, IPv4/TCP/UDP parser, HTTP/DNS/SMTP parser, application protocol detection, logging, pipeline xử lý, CLI và các test case.

Toàn bộ code có sự hỗ trợ của AI đều được em đọc lại, review, chỉnh sửa khi cần thiết, chạy kiểm thử và kiểm tra kết quả. Em hiểu cấu trúc project, luồng xử lý, logic và cách hoạt động của các thành phần trong chương trình.

## Bài tập 2: Decoder, Preprocessor và Flow Tracker

Bài tập 2 mở rộng pipeline của Bài tập 1 theo thứ tự:

    Capture
        -> Packet Parser
        -> Application Parser
        -> Decoder
        -> Preprocessor
        -> Flow/Connection Tracker
        -> JSON Lines và flow summary

### Decoder

Decoder xử lý:

- HTTP percent decoding cho URI, path và query.
- HTTP form data `application/x-www-form-urlencoded`.
- HTML entity như `&lt;` và `&gt;`.
- SMTP/MIME Base64 và Quoted-Printable.
- Character decoding cho UTF-8 và ASCII.
- Dữ liệu raw được giữ riêng với dữ liệu decoded.
- Dữ liệu lỗi hoặc quá lớn được đánh dấu `partial` thay vì làm dừng pipeline.

### Preprocessor

Preprocessor thực hiện:

- Kiểm tra timestamp, IP, port và transport protocol.
- Chuẩn hóa protocol, domain, HTTP header và timestamp.
- Giữ lại giá trị gốc khi chuẩn hóa.
- Ghi `preprocess_status`, `processing_action`, `reason`, warning và error.
- Xử lý event thiếu hoặc không hợp lệ theo policy `retain` hoặc `skip`.

### Flow/Connection Tracker

Flow Tracker sử dụng five-tuple hai chiều:

    src_ip, dst_ip, src_port, dst_port, protocol

Các chức năng chính:

- Gộp packet hai chiều vào cùng một flow.
- Gắn `flow_id` và `flow_direction`.
- Theo dõi TCP state: `NEW`, `HANDSHAKE`, `ESTABLISHED`,
  `CLOSING`, `CLOSED`, `RESET`.
- Theo dõi UDP query/response theo flow.
- Đếm packet, byte và counter theo từng hướng.
- Xử lý FIN, RST, idle timeout, flow capacity và flush cuối PCAP.

### Cấu hình Assignment 2

Các tùy chọn có thể truyền qua CLI:

    --tcp-idle-timeout
    --udp-idle-timeout
    --max-active-flows
    --max-decoded-content-size
    --invalid-event-policy {retain,skip}
    --unsupported-data-policy {retain,skip}

Ví dụ:

    python main.py \
      --pcap TEST/assignment1/http_get/input.pcap \
      --output output/events.jsonl \
      --flow-output output/flows.jsonl \
      --max-decoded-content-size 1048576 \
      --overwrite

### Kiểm thử Assignment 2

Test bắt buộc T01–T14 nằm trong:

    tests/test_assignment2.py

Chạy riêng test Assignment 2:

    python -m pytest -q tests/test_assignment2.py

Báo cáo chi tiết input, output, kết quả mong đợi và phân tích nằm tại:

    TEST/assignment2/result.md

Các PCAP của Bài tập 1 được gom tại:

    TEST/assignment1/

Assignment 2 dùng lại các PCAP này để kiểm tra integration trong pipeline.

