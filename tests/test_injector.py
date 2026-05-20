import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from injector import _parse_inject_output


class TestParseInjectOutput:
    def test_empty_input(self):
        errors, logs = _parse_inject_output("", "")
        assert errors == []
        assert logs == []

    def test_none_input(self):
        errors, logs = _parse_inject_output(None, None)
        assert errors == []
        assert logs == []

    def test_error_prefix(self):
        stdout = "__ERROR__:ReferenceError: xyz is not defined"
        errors, logs = _parse_inject_output(stdout, "")
        assert len(errors) == 1
        assert "xyz is not defined" in errors[0]

    def test_inline_error_detection(self):
        stdout = "TypeError: cannot read property 'x' of null"
        errors, logs = _parse_inject_output(stdout, "")
        assert len(errors) == 1
        assert "TypeError" in errors[0]

    def test_reference_error_detection(self):
        stdout = "ReferenceError: Java is not defined"
        errors, logs = _parse_inject_output(stdout, "")
        assert len(errors) == 1

    def test_generic_error_detection(self):
        stdout = "Error: frida crashed"
        errors, logs = _parse_inject_output(stdout, "")
        assert len(errors) == 1

    def test_normal_log_lines(self):
        stdout = "[HOOK] TrustManager hooked\n[HOOK] SSL bypass active"
        errors, logs = _parse_inject_output(stdout, "")
        assert len(logs) == 2
        assert errors == []

    def test_stderr_included(self):
        errors, logs = _parse_inject_output("", "Fatal error occurred")
        assert len(errors) == 1
        assert "[stderr]" in errors[0]

    def test_stderr_warnings_filtered(self):
        errors, logs = _parse_inject_output("", "Warning: deprecated feature")
        assert errors == []

    def test_mixed_output(self):
        stdout = "[HOOK] ok\n__ERROR__:bad thing\nnormal log"
        stderr = "Warning: ignore this\nActual error here"
        errors, logs = _parse_inject_output(stdout, stderr)
        assert len(errors) == 2  # __ERROR__ + stderr line
        assert len(logs) == 2    # [HOOK] ok + normal log

    def test_blank_lines_skipped(self):
        stdout = "\n\n  \n[HOOK] active\n\n"
        errors, logs = _parse_inject_output(stdout, "")
        assert len(logs) == 1
        assert logs[0] == "[HOOK] active"
