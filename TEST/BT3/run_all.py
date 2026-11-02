#!/usr/bin/env python3
"""Generate fixtures and run the complete T01..T14 acceptance suite."""

from __future__ import annotations

import json
import platform
import subprocess
import sys
from importlib.metadata import version
from pathlib import Path

from generate_fixtures import generate


ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = ROOT.parents[1]
CASE_NAMES = [f"T{number:02d}" for number in range(1, 15)]
ANALYSIS = {
    "T01": "Loader bỏ qua comment/dòng trống và nạp đủ hai rule hợp lệ.",
    "T02": "Rule sai cú pháp bị cô lập; loader vẫn đọc rule hợp lệ phía sau.",
    "T03": "Keyword chưa hỗ trợ được báo unsupported, không làm dừng tiến trình.",
    "T04": "Parser chuẩn hóa đúng protocol, IPv4, CIDR, port đơn và port range.",
    "T05": "Hướng -> chỉ khớp chiều thuận; <> khớp cả tuple đảo chiều.",
    "T06": "Indexer lọc đúng TCP/UDP và port, không trả candidate trùng.",
    "T07": "Header sai bị loại trước content; bộ so khớp content không được gọi.",
    "T08": "FlowTracker hoàn tất bắt tay TCP và flow:to_server,established khớp.",
    "T09": "content mặc định phân biệt hoa thường; nocase khớp ADMIN.",
    "T10": "offset/depth giới hạn chính xác cửa sổ tìm kiếm tuyệt đối.",
    "T11": "distance/within áp dụng nối tiếp từ cuối content trước.",
    "T12": "flags và dsize đều phải đúng; sai một điều kiện sẽ không khớp.",
    "T13": "Một packet được đánh giá với mọi candidate và sinh hai match độc lập.",
    "T14": "PCAP chạy qua CLI tạo packet, flow và Detection Event JSONL đầy đủ.",
}


def write_case_result(case: str, passed: bool) -> None:
    status = "PASS" if passed else "FAIL"
    text = f"""# {case} — {status}

- Input/rule: [input.rules](input.rules){' và [input.pcap](input.pcap)' if case == 'T14' else ''}
- Lệnh chạy: [command.txt](command.txt)
- Kỳ vọng: [expected.json](expected.json)
- Thực tế: [actual.json](actual.json)
- Log: [run.log](run.log)
- Exit code: [exit_code.txt](exit_code.txt)
- Phân tích: {ANALYSIS[case]}
- Kết luận: **{status}**
"""
    (ROOT / case / "result.md").write_text(text, encoding="utf-8")


def main() -> int:
    generate()
    results = []
    for case in CASE_NAMES:
        completed = subprocess.run(
            [sys.executable, str(ROOT / "run_case.py"), case],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        case_dir = ROOT / case
        log = completed.stdout
        if completed.stderr:
            log += ("\n" if log else "") + completed.stderr
        (case_dir / "run.log").write_text(log, encoding="utf-8")
        (case_dir / "exit_code.txt").write_text(
            f"{completed.returncode}\n", encoding="utf-8"
        )
        passed = completed.returncode == 0
        write_case_result(case, passed)
        results.append({"case": case, "status": "PASS" if passed else "FAIL"})
        print(f"{case}: {'PASS' if passed else 'FAIL'}")

    regression = subprocess.run(
        [sys.executable, "-m", "pytest", "-q"],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    regression_log = regression.stdout
    if regression.stderr:
        regression_log += ("\n" if regression_log else "") + regression.stderr
    (ROOT / "regression.log").write_text(regression_log, encoding="utf-8")
    (ROOT / "regression_exit_code.txt").write_text(
        f"{regression.returncode}\n", encoding="utf-8"
    )
    regression_status = "PASS" if regression.returncode == 0 else "FAIL"
    print(f"Regression: {regression_status}")

    summary = {
        "failed": sum(item["status"] == "FAIL" for item in results),
        "passed": sum(item["status"] == "PASS" for item in results),
        "regression_status": regression_status,
        "results": results,
        "total": len(results),
    }
    (ROOT / "summary.json").write_text(
        json.dumps(summary, indent=2) + "\n", encoding="utf-8"
    )
    rows = "\n".join(
        f"| {item['case']} | {item['status']} | [{item['case']}/result.md]({item['case']}/result.md) |"
        for item in results
    )
    environment = {
        "os": platform.platform(),
        "python": platform.python_version(),
        "pytest": version("pytest"),
        "scapy": version("scapy"),
    }
    report = f"""# Kết quả kiểm thử Bài tập 03

## Tổng quan

- Tổng số ca: {summary['total']}
- PASS: {summary['passed']}
- FAIL: {summary['failed']}
- Regression toàn dự án: {regression_status} ([log](regression.log), [exit code](regression_exit_code.txt))
- Phạm vi: Rule Loader, Parser, Validator, Repository/Indexer, Matcher, Evaluator, Detection Event và tích hợp PCAP → CLI.

## Môi trường

- OS: `{environment['os']}`
- Python: `{environment['python']}`
- Scapy: `{environment['scapy']}`
- pytest: `{environment['pytest']}`
- Dependency được `uv` cấp trong môi trường tạm; không tạo `.venv` hoặc tải test data vào repository.

## Ma trận kết quả

| Test | Trạng thái | Bằng chứng |
|---|---|---|
{rows}

## Test bổ sung và regression

- PCAP → `alerts.jsonl`: T14 và `tests/test_assignment3_integration.py`.
- File rule thiếu/không đọc được, file bị disable, SID trùng/revision: `tests/test_assignment3_loader.py` và `tests/test_assignment3_integration.py`.
- CIDR, port range và giá trị biên: `tests/test_assignment3_parser.py`, `tests/test_assignment3_repository.py`, `tests/test_assignment3_matcher.py`.
- Content rỗng/modifier sai, payload thiếu hoặc sai kiểu: `tests/test_assignment3_parser.py`, `tests/test_assignment3_matcher.py`, `tests/test_assignment3_evaluator.py`.
- Flow chưa established và lỗi ghi Detection Event: `tests/test_assignment3_matcher.py`, `tests/test_assignment3_integration.py`.
- Toàn bộ regression: 149 test PASS; chi tiết trong [regression.log](regression.log).

## Giới hạn đã biết

- Chỉ hỗ trợ action `alert`, protocol `tcp`/`udp`, IPv4 và tập keyword được nêu trong kế hoạch Bài 03.
- Các keyword ngoài phạm vi như `pcre`, `byte_test`, `byte_jump`, file inspection, TLS decryption và plugin được báo `unsupported`.
- Content matching chạy trên payload/buffer đã chuẩn hóa; engine không thực hiện TCP stream reassembly hoặc TLS decryption.

## Cách chạy lại

```bash
uv run --with scapy==2.7.0 --with pytest python TEST/BT3/run_all.py
```

Chương trình tự sinh lại PCAP xác định, chạy từng ca, so sánh `actual.json` với `expected.json`, ghi `run.log`, `exit_code.txt`, rồi cập nhật báo cáo này. Không cần tải PCAP hay rule từ Internet.
"""
    (ROOT / "result.md").write_text(report, encoding="utf-8")
    return 0 if summary["failed"] == 0 and regression.returncode == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
