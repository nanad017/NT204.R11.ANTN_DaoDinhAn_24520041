# Bao Cao Kiem Thu

## Tong quan

File nay giai thich nguon du lieu va cach chay cac test case bat buoc cua bai
Packet Capture & Parser IDS.

Moi test case trong `TEST/<case>/` co cac file sau:

```text
input.pcap hoac input.pcapng  PCAP dung lam dau vao
actual.jsonl                  JSON Lines do chuong trinh tao ra
run.log                       log cua lenh chay
exit_code.txt                 ma thoat cua chuong trinh
result.md                     ket qua doi chieu PASS/FAIL
```

Tat ca cac case duoc chay lai bang `main.py`. Khong commit hay push Git trong
qua trinh tao ket qua nay.

## Nguon PCAP cong khai

Nam file cong khai duoc tai tu Wireshark Sample Captures:

<https://wiki.wireshark.org/SampleCaptures>

```text
data/dns.cap                       DNS query va DNS response
data/smtp.pcap                     SMTP command va SMTP response
data/http.cap                      HTTP GET va HTTP response
data/tcp-ethereal-file1.trace      HTTP POST co body
data/iperf3-udp.pcapng.gz          UDP traffic
```

Ban sao cua cac file phu hop da duoc dat trong tung thu muc
`TEST/assignment1/` de moi case co the chay doc lap. Rieng file UDP duoc
giai nen thanh `TEST/assignment1/udp/input.pcapng`.

## Test case va cach tao input

| Test case | Nguon input | Da kiem tra gi |
| --- | --- | --- |
| `tcp_handshake` | Traffic bat truc tiep tu `wlan0` bang tcpdump | SYN, SYN-ACK, ACK |
| `tcp_data` | Traffic bat truc tiep tu `wlan0` bang tcpdump | TCP co payload |
| `udp` | `iperf3-udp.pcapng.gz` cua Wireshark | UDP length, checksum, payload length |
| `http_get` | `http.cap` cua Wireshark | GET, URL, Host, headers |
| `http_post` | `tcp-ethereal-file1.trace` cua Wireshark | POST, Content-Type, Content-Length |
| `http_response` | `http.cap` cua Wireshark | status 200 va response headers |
| `dns_query` | `dns.cap` cua Wireshark | domain va query type |
| `dns_response` | `dns.cap` cua Wireshark | query va answer records |
| `smtp_command` | `smtp.pcap` cua Wireshark | HELO, MAIL FROM, RCPT TO |
| `smtp_response` | `smtp.pcap` cua Wireshark | SMTP status code va response |
| `unknown` | PCAP tu tao bang Scapy | IPv4 protocol 99 khong duoc ho tro |
| `malformed` | File capture co chu y khong hop le | Chuong trinh bao loi co kiem soat, khong crash |

PCAP tu tao bang Scapy chi duoc dung cho `unknown`, vi can protocol IPv4 99
khong duoc ho tro. Case `malformed` dung file capture khong hop le co chu y.
Hai case TCP dung traffic bat truc tiep tu `wlan0`; cac case con lai dung PCAP
cong khai co the chay lai duoc.

## Cach chay

Voi file `.pcap`, lenh mau la:

```bash
.venv/bin/python main.py \
  --pcap TEST/assignment1/dns_query/input.pcap \
  --output TEST/assignment1/dns_query/actual.jsonl \
  --overwrite
```

Voi UDP, dau vao la `.pcapng`:

```bash
.venv/bin/python main.py \
  --pcap TEST/assignment1/udp/input.pcapng \
  --output TEST/assignment1/udp/actual.jsonl \
  --overwrite
```

Sau khi chay, mo `actual.jsonl` de doi chieu cac field can thiet voi yeu cau
cua case. `timestamp` va `checksum` co the thay doi, nen khong dung hai field
do lam dieu kien PASS/FAIL.

## Ket qua

Tat ca 12 test case deu PASS.

- TCP handshake co du SYN, SYN-ACK, ACK.
- TCP data co ba packet voi payload khac 0.
- HTTP GET, POST va response deu duoc parser nhan dien.
- DNS query/response va SMTP command/response deu co field yeu cau.
- UDP packet duoc parser doc cac field UDP.
- Unknown protocol tao warning `Unsupported IPv4 transport protocol` va chuong
  trinh van chay xong voi exit code 0.
- Malformed input bao `Not a supported capture file`, exit code 1, khong co
  unhandled traceback. Day la ket qua mong doi cho input khong hop le.

## Live capture da thu

Traffic TCP da duoc bat truc tiep tu `wlan0` bang `tcpdump` va luu vao
`TEST/assignment1/tcp_handshake/input.pcap`. Cung file nay duoc dung cho
`tcp_data` vi no co ca TCP handshake va TCP payload. Parser tao 11 event,
trong do co du
SYN/SYN-ACK/ACK va ba packet co payload.

Mot lan live capture khac bang `main.py --interface wlan0` da duoc dung nhu
smoke test. Lan do bat duoc UDP, DNS query/response, HTTP GET/response va
unknown traffic. Cac case nay van dung PCAP cong khai trong `TEST/assignment1/` de co the
chay lai va doi chieu ket qua on dinh.
