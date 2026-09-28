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

Các test case thủ công và kết quả kiểm thử được lưu trong thư mục:

    TEST/

Thông tin chi tiết được mô tả trong:

    TEST/README.md

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