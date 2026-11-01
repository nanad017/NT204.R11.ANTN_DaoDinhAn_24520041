import re

import pytest

from src.core_engine.loader import RuleLoader, RuleLoaderConfig
from src.core_engine.models import (
    DiagnosticKind,
    IPAddressSpec,
    InternalRule,
    PortSpec,
    RuleDiagnostic,
    RuleHeader,
    RuleStatus,
)


class StubParser:
    def __init__(self):
        self.calls = []

    def parse(self, rule_text, *, source_file=None, source_line=None):
        self.calls.append((rule_text, source_file, source_line))
        if "explode" in rule_text:
            raise ValueError("deliberate parser failure")

        sid_match = re.search(r"sid:(\d+)", rule_text)
        sid = int(sid_match.group(1)) if sid_match else None
        if "unsupported" in rule_text:
            return InternalRule(
                raw_text=rule_text,
                status=RuleStatus.UNSUPPORTED,
                sid=sid,
                diagnostics=[
                    RuleDiagnostic(
                        kind=DiagnosticKind.UNSUPPORTED,
                        reason="unsupported keyword",
                        keyword="pcre",
                    )
                ],
            )
        if "invalid" in rule_text:
            return InternalRule(
                raw_text=rule_text,
                status=RuleStatus.INVALID,
                sid=sid,
                diagnostics=[
                    RuleDiagnostic(
                        kind=DiagnosticKind.INVALID,
                        reason="invalid rule syntax",
                        position=0,
                    )
                ],
            )

        return InternalRule(
            raw_text=rule_text,
            status=RuleStatus.VALID,
            header=RuleHeader(
                action="alert",
                protocol="tcp",
                source_ip=IPAddressSpec.match_any(),
                source_port=PortSpec.match_any(),
                direction="->",
                destination_ip=IPAddressSpec.match_any(),
                destination_port=PortSpec.single(80),
            ),
            msg="test rule",
            sid=sid,
            rev=1,
        )


def test_loader_skips_blank_and_comment_lines(tmp_path):
    rule_file = tmp_path / "main.rules"
    rule_file.write_text(
        "\n# full line comment\n"
        'alert tcp any any -> any 80 (msg:"one"; sid:1001; rev:1;)\n'
        "   # indented comment\n"
        'alert tcp any any -> any 80 (msg:"two"; sid:1002; rev:1;)\n',
        encoding="utf-8",
    )
    parser = StubParser()

    result = RuleLoader(parser).load_file(rule_file)

    assert [rule.sid for rule in result.rules] == [1001, 1002]
    assert len(parser.calls) == 2
    assert result.files_seen == 1
    assert result.files_loaded == 1
    assert result.rule_lines_seen == 2
    assert result.valid_count == 2


def test_loader_continues_after_parser_error(tmp_path):
    rule_file = tmp_path / "parser-error.rules"
    rule_file.write_text(
        "explode sid:1101;\n"
        'alert tcp any any -> any 80 (msg:"still loaded"; sid:1102; rev:1;)\n',
        encoding="utf-8",
    )

    result = RuleLoader(StubParser()).load_file(rule_file)

    assert len(result.rules) == 2
    assert result.rules[0].status == RuleStatus.INVALID
    assert "deliberate parser failure" in result.rules[0].diagnostics[0].reason
    assert result.rules[1].status == RuleStatus.VALID
    assert result.invalid_count == 1
    assert result.valid_count == 1


def test_loader_collects_invalid_and_unsupported_diagnostics(tmp_path):
    rule_file = tmp_path / "diagnostics.rules"
    rule_file.write_text(
        "invalid sid:1201;\nunsupported sid:1202;\n",
        encoding="utf-8",
    )

    result = RuleLoader(StubParser()).load_file(rule_file)

    assert result.invalid_count == 1
    assert result.unsupported_count == 1
    assert [item.kind for item in result.diagnostics] == [
        DiagnosticKind.INVALID,
        DiagnosticKind.UNSUPPORTED,
    ]
    assert result.diagnostics[0].source_line == 1
    assert result.diagnostics[1].keyword == "pcre"


def test_loader_reads_multiple_files_and_survives_missing_file(tmp_path):
    first = tmp_path / "first.rules"
    second = tmp_path / "second.rules"
    missing = tmp_path / "missing.rules"
    first.write_text("valid sid:1301;\n", encoding="utf-8")
    second.write_text("valid sid:1302;\n", encoding="utf-8")

    result = RuleLoader(StubParser()).load_files([first, missing, second])

    assert [rule.sid for rule in result.rules] == [1301, 1302]
    assert result.files_seen == 3
    assert result.files_loaded == 2
    assert len(result.diagnostics) == 1
    assert "could not read rule file" in result.diagnostics[0].reason


def test_disabled_file_is_not_read_or_sent_to_parser(tmp_path):
    enabled = tmp_path / "enabled.rules"
    disabled = tmp_path / "disabled.rules"
    enabled.write_text("valid sid:1401;\n", encoding="utf-8")
    disabled.write_text("valid sid:1402;\n", encoding="utf-8")
    parser = StubParser()
    config = RuleLoaderConfig(disabled_files=frozenset({str(disabled)}))

    result = RuleLoader(parser, config).load_files([disabled, enabled])

    assert [rule.sid for rule in result.rules] == [1401]
    assert len(parser.calls) == 1
    assert result.files_seen == 2
    assert result.files_loaded == 1
    assert result.files_skipped == 1
    assert result.diagnostics[0].kind == DiagnosticKind.WARNING


def test_disabled_sid_is_retained_but_not_active(tmp_path):
    rule_file = tmp_path / "disabled-sid.rules"
    rule_file.write_text(
        "valid sid:1501;\nvalid sid:1502;\n",
        encoding="utf-8",
    )
    config = RuleLoaderConfig(disabled_sids=frozenset({1502}))

    result = RuleLoader(StubParser(), config).load_file(rule_file)

    assert result.valid_count == 2
    assert result.disabled_count == 1
    assert [rule.sid for rule in result.active_rules] == [1501]
    assert result.rules[1].enabled is False
    assert "SID 1502 disabled" in result.diagnostics[0].reason


def test_loader_joins_backslash_continuation_and_keeps_start_line(tmp_path):
    rule_file = tmp_path / "multiline.rules"
    rule_file.write_text(
        "# comment\n"
        "alert tcp any any -> any 80 \\\n"
        '    (msg:"continued"; sid:1601; rev:1;)\n',
        encoding="utf-8",
    )
    parser = StubParser()

    result = RuleLoader(parser).load_file(rule_file)

    assert result.rule_lines_seen == 1
    assert result.rules[0].sid == 1601
    assert result.rules[0].source_line == 2
    assert "\\" not in parser.calls[0][0]
    assert parser.calls[0][2] == 2


def test_loader_rejects_invalid_configuration_and_parser():
    with pytest.raises(ValueError):
        RuleLoaderConfig(disabled_sids=frozenset({0}))
    with pytest.raises(TypeError):
        RuleLoader(object())


def test_loader_converts_wrong_parser_return_type_to_invalid_rule(tmp_path):
    class WrongReturnParser:
        def parse(self, rule_text, *, source_file=None, source_line=None):
            return None

    rule_file = tmp_path / "wrong-return.rules"
    rule_file.write_text("some rule text\n", encoding="utf-8")

    result = RuleLoader(WrongReturnParser()).load_file(rule_file)

    assert result.invalid_count == 1
    assert "did not return InternalRule" in result.rules[0].diagnostics[0].reason


def test_loader_continues_after_file_with_invalid_utf8(tmp_path):
    invalid_utf8 = tmp_path / "invalid-utf8.rules"
    valid = tmp_path / "valid.rules"
    invalid_utf8.write_bytes(b"\xff\xfe\x00")
    valid.write_text("valid sid:1701;\n", encoding="utf-8")

    result = RuleLoader(StubParser()).load_files([invalid_utf8, valid])

    assert result.files_seen == 2
    assert result.files_loaded == 1
    assert [rule.sid for rule in result.rules] == [1701]
    assert "could not read rule file" in result.diagnostics[0].reason
