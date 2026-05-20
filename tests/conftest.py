import struct
import pytest


@pytest.fixture
def mock_recon_data():
    """Recon data dict matching the contract both legacy and combined modes produce."""
    return {
        "package": "com.test.app",
        "task": "ssl_pinning",
        "interface_implementations": [
            {
                "class": "com.test.CustomTrustManager",
                "implements": "javax.net.ssl.X509TrustManager",
                "methods": ["checkServerTrusted", "checkClientTrusted", "getAcceptedIssuers"],
            }
        ],
        "method_signatures": {
            "com.test.CustomTrustManager": [
                {
                    "name": "checkServerTrusted",
                    "returns": "void",
                    "params": [
                        "[Ljava.security.cert.X509Certificate;",
                        "java.lang.String",
                    ],
                    "modifiers": 1,
                },
                {
                    "name": "getAcceptedIssuers",
                    "returns": "[Ljava.security.cert.X509Certificate;",
                    "params": [],
                    "modifiers": 1,
                },
            ]
        },
        "library_fingerprints": [
            {
                "class": "okhttp3.CertificatePinner",
                "description": "OkHttp Certificate Pinner",
                "matched_methods": [{"method": "check", "params": ""}],
                "confidence": 0.5,
            }
        ],
        "native_modules": [
            {
                "module": "libssl.so",
                "path": "/system/lib64/libssl.so",
                "exports": [
                    {"name": "SSL_connect", "address": "0x7f12345678"}
                ],
            }
        ],
        "network_security_config": {
            "has_config": True,
            "content": "<network-security-config><domain-config><pin-set/></domain-config></network-security-config>",
            "has_pins": True,
        },
    }


@pytest.fixture
def nsc_axml_bytes():
    """Build a minimal binary AXML representing a network-security-config with pin-set."""
    strings = [
        b"",
        b"network-security-config",
        b"domain-config",
        b"pin-set",
    ]

    string_offsets = []
    string_bytes = b""
    for s in strings:
        string_offsets.append(len(string_bytes))
        string_bytes += struct.pack("B", len(s))
        string_bytes += struct.pack("B", len(s))
        string_bytes += s
        string_bytes += b"\x00"

    while len(string_bytes) % 4:
        string_bytes += b"\x00"

    num_strings = len(strings)
    sp_header_size = 28
    offsets_data = struct.pack(f"<{num_strings}I", *string_offsets)
    strings_start = sp_header_size + len(offsets_data)
    sp_size = strings_start + len(string_bytes)

    string_pool = struct.pack(
        "<HHIIIIII",
        0x0001, sp_header_size, sp_size,
        num_strings, 0, 0x00000100,
        strings_start, 0,
    )
    string_pool += offsets_data
    string_pool += string_bytes

    def _start_elem(name_idx, line):
        node = struct.pack("<HHIII", 0x0102, 16, 36, line, 0xFFFFFFFF)
        ext = struct.pack("<II", 0xFFFFFFFF, name_idx)
        ext += struct.pack("<HHHHHH", 20, 20, 0, 0, 0, 0)
        return node + ext

    def _end_elem(name_idx, line):
        node = struct.pack("<HHIII", 0x0103, 16, 24, line, 0xFFFFFFFF)
        ext = struct.pack("<II", 0xFFFFFFFF, name_idx)
        return node + ext

    xml_chunks = (
        _start_elem(1, 1)
        + _start_elem(2, 2)
        + _start_elem(3, 3)
        + _end_elem(3, 3)
        + _end_elem(2, 4)
        + _end_elem(1, 5)
    )

    body = string_pool + xml_chunks
    file_header = struct.pack("<HHI", 0x0003, 8, 8 + len(body))
    return file_header + body
