import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from recon import format_for_llm, _parse_nsc_xml


class TestFormatForLlm:
    def test_includes_all_sections(self, mock_recon_data):
        output = format_for_llm(mock_recon_data)
        assert "DISCOVERED IMPLEMENTATIONS" in output
        assert "IDENTIFIED LIBRARIES" in output
        assert "NATIVE MODULES" in output
        assert "NETWORK SECURITY CONFIG" in output

    def test_class_names_present(self, mock_recon_data):
        output = format_for_llm(mock_recon_data)
        assert "com.test.CustomTrustManager" in output
        assert "javax.net.ssl.X509TrustManager" in output

    def test_method_signatures_present(self, mock_recon_data):
        output = format_for_llm(mock_recon_data)
        assert "checkServerTrusted" in output
        assert "java.lang.String" in output

    def test_library_info_present(self, mock_recon_data):
        output = format_for_llm(mock_recon_data)
        assert "OkHttp Certificate Pinner" in output
        assert "okhttp3.CertificatePinner" in output

    def test_native_modules_present(self, mock_recon_data):
        output = format_for_llm(mock_recon_data)
        assert "libssl.so" in output
        assert "SSL_connect" in output

    def test_empty_recon_returns_no_data_message(self):
        empty = {
            "package": "com.test.app",
            "task": "ssl_pinning",
            "interface_implementations": [],
            "method_signatures": {},
            "library_fingerprints": [],
            "native_modules": [],
            "network_security_config": None,
        }
        output = format_for_llm(empty)
        assert "No security-relevant" in output

    def test_output_identical_for_same_dict(self, mock_recon_data):
        """Guards Priority 4: format_for_llm is a pure function of the dict.
        Both legacy and combined recon produce the same dict structure,
        so the LLM sees identical data regardless of recon mode."""
        output_a = format_for_llm(mock_recon_data)
        output_b = format_for_llm(mock_recon_data)
        assert output_a == output_b

    def test_partial_data_doesnt_crash(self):
        partial = {
            "package": "com.test.app",
            "task": "ssl_pinning",
            "interface_implementations": [
                {
                    "class": "com.test.TM",
                    "implements": "javax.net.ssl.X509TrustManager",
                    "methods": ["check"],
                }
            ],
            "method_signatures": {},
            "library_fingerprints": [],
            "native_modules": [],
            "network_security_config": None,
        }
        output = format_for_llm(partial)
        assert "com.test.TM" in output
        assert "IDENTIFIED LIBRARIES" not in output


class TestParseNscXml:
    def test_detects_pin_set(self):
        xml = """<?xml version="1.0" encoding="utf-8"?>
        <network-security-config>
            <domain-config>
                <pin-set expiration="2025-01-01">
                    <pin digest="SHA-256">abc123=</pin>
                </pin-set>
            </domain-config>
        </network-security-config>"""
        result = _parse_nsc_xml(xml)
        assert result["has_config"] is True
        assert result["has_pins"] is True
        assert "pin-set" in result["content"]

    def test_no_pin_set(self):
        xml = """<?xml version="1.0" encoding="utf-8"?>
        <network-security-config>
            <base-config cleartextTrafficPermitted="false" />
        </network-security-config>"""
        result = _parse_nsc_xml(xml)
        assert result["has_config"] is True
        assert result["has_pins"] is False

    def test_empty_string(self):
        result = _parse_nsc_xml("")
        assert result["has_config"] is True
        assert result["has_pins"] is False

    def test_none_input(self):
        result = _parse_nsc_xml(None)
        assert result["has_pins"] is False
