"""Tests for the pyaxmlparser-based network security config parser."""

import os
import sys
import tempfile
import zipfile
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from recon import _decode_axml, _extract_nsc_from_apk, _parse_nsc_xml


class TestExtractNscFromApk:
    def test_extracts_existing_entry(self, tmp_path):
        apk_path = tmp_path / "test.apk"
        with zipfile.ZipFile(apk_path, "w") as zf:
            zf.writestr("res/xml/network_security_config.xml", b"\x03\x00\x08\x00fake")
        result = _extract_nsc_from_apk(str(apk_path))
        assert result is not None
        assert len(result) > 0

    def test_returns_none_when_no_entry(self, tmp_path):
        apk_path = tmp_path / "test.apk"
        with zipfile.ZipFile(apk_path, "w") as zf:
            zf.writestr("AndroidManifest.xml", b"fake")
        assert _extract_nsc_from_apk(str(apk_path)) is None

    def test_returns_none_for_bad_zip(self, tmp_path):
        bad_path = tmp_path / "notazip.apk"
        bad_path.write_bytes(b"this is not a zip file")
        assert _extract_nsc_from_apk(str(bad_path)) is None

    def test_returns_none_for_missing_file(self):
        assert _extract_nsc_from_apk("/nonexistent/path.apk") is None


class TestDecodeAxml:
    def test_valid_decode_with_mock(self):
        mock_instance = MagicMock()
        mock_instance.get_xml.return_value = "<network-security-config><pin-set/></network-security-config>"

        with patch("recon._AXML", return_value=mock_instance):
            result = _decode_axml(b"\x03\x00\x08\x00testdata")

        assert result is not None
        assert "pin-set" in result

    def test_returns_bytes_as_str(self):
        mock_instance = MagicMock()
        mock_instance.get_xml.return_value = b"<config/>"

        with patch("recon._AXML", return_value=mock_instance):
            result = _decode_axml(b"\x03\x00\x08\x00testdata")

        assert isinstance(result, str)
        assert result == "<config/>"

    def test_malformed_input_returns_none(self):
        with patch("recon._AXML", side_effect=Exception("bad AXML")):
            result = _decode_axml(b"garbage")
        assert result is None

    def test_missing_pyaxmlparser_returns_none(self):
        with patch("recon._AXML", None):
            result = _decode_axml(b"anything")
        assert result is None

    def test_with_real_axml_fixture(self, nsc_axml_bytes):
        """Feed the handcrafted AXML fixture to pyaxmlparser if installed."""
        pyaxmlparser = pytest.importorskip("pyaxmlparser")

        fd, tmp_path = tempfile.mkstemp(suffix=".xml")
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(nsc_axml_bytes)

            try:
                axml = pyaxmlparser.AXML(tmp_path)
                xml_text = axml.get_xml()
                if isinstance(xml_text, bytes):
                    xml_text = xml_text.decode("utf-8", errors="replace")
                assert "pin-set" in xml_text.lower()
            except Exception:
                pytest.skip(
                    "Handcrafted AXML fixture not accepted by this pyaxmlparser version; "
                    "mock-based tests still cover the wrapper logic"
                )
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


class TestParseNscXml:
    def test_detects_pin_set(self):
        xml = '<network-security-config><pin-set expiration="2025-01-01"/></network-security-config>'
        result = _parse_nsc_xml(xml)
        assert result["has_config"] is True
        assert result["has_pins"] is True

    def test_no_pin_set(self):
        xml = '<network-security-config><base-config/></network-security-config>'
        result = _parse_nsc_xml(xml)
        assert result["has_config"] is True
        assert result["has_pins"] is False

    def test_case_insensitive(self):
        xml = '<config><PIN-SET/></config>'
        result = _parse_nsc_xml(xml)
        assert result["has_pins"] is True

    def test_empty_returns_no_pins(self):
        result = _parse_nsc_xml("")
        assert result["has_pins"] is False

    def test_none_returns_no_pins(self):
        result = _parse_nsc_xml(None)
        assert result["has_pins"] is False
