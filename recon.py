"""
Phase 1: Deep Reconnaissance Engine (subprocess-based)

Uses FridaRunner (subprocess frida CLI) instead of Frida Python API
to avoid the 'Java is not defined' bug in frida-python 17.x.

Goes far beyond basic class enumeration:
  Layer 1 — Interface/Superclass Discovery (obfuscation-proof)
  Layer 2 — Method Signature Analysis (gives LLM the data it needs)
  Layer 3 — Known Library Fingerprinting (catches renamed classes)
  Layer 4 — Native Module Scanning (catches C/C++ implementations)
  Layer 5 — Network Security Config Parsing (catches XML-defined pins)
"""

import json
import os
import subprocess
import tempfile
import zipfile

from frida_runner import FridaRunner, wrap_java_script, wrap_plain_script

try:
    from pyaxmlparser import AXML as _AXML
except ImportError:
    _AXML = None


# ═══════════════════════════════════════════════════════════
#  INTERFACE TARGETS PER TASK
# ═══════════════════════════════════════════════════════════

INTERFACE_TARGETS = {
    "ssl_pinning": [
        "javax.net.ssl.X509TrustManager",
        "javax.net.ssl.HostnameVerifier",
        "javax.net.ssl.SSLSocketFactory",
        "javax.net.ssl.X509ExtendedTrustManager",
        "okhttp3.CertificatePinner",
        "okhttp3.internal.tls.CertificateChainCleaner",
        "com.datatheorem.android.trustkit.TrustKit",
        "org.conscrypt.TrustManagerImpl",
    ],
    "root_detection": [
        "com.scottyab.rootbeer.RootBeer",
        "com.google.android.gms.safetynet.SafetyNetApi",
        "com.google.android.play.core.integrity.IntegrityManager",
    ],
    "crypto": [
        "javax.crypto.Cipher",
        "javax.crypto.KeyGenerator",
        "javax.crypto.Mac",
        "java.security.KeyStore",
        "javax.crypto.spec.SecretKeySpec",
        "javax.crypto.spec.IvParameterSpec",
    ],
    "auth": [
        "android.accounts.AccountManager",
        "android.webkit.CookieManager",
    ],
}

# ═══════════════════════════════════════════════════════════
#  KNOWN LIBRARY FINGERPRINTS
# ═══════════════════════════════════════════════════════════

LIBRARY_FINGERPRINTS = {
    "ssl_pinning": {
        "okhttp3.CertificatePinner": {
            "description": "OkHttp Certificate Pinner",
            "methods": ["check", "check$okhttp"],
        },
        "com.android.org.conscrypt.TrustManagerImpl": {
            "description": "Android Conscrypt TrustManager",
            "methods": ["checkTrustedRecursive", "checkServerTrusted"],
        },
        "com.squareup.okhttp.CertificatePinner": {
            "description": "OkHttp2 Certificate Pinner (legacy)",
            "methods": ["check"],
        },
        "com.datatheorem.android.trustkit.pinning.OkHostnameVerifier": {
            "description": "TrustKit Hostname Verifier",
            "methods": ["verify"],
        },
        "org.chromium.net.impl.CronetUrlRequestContext": {
            "description": "Cronet (Chromium-based networking)",
            "methods": ["startNetLogToDisk", "initNetworkThread"],
        },
    },
    "root_detection": {
        "com.scottyab.rootbeer.RootBeer": {
            "description": "RootBeer Detection Library",
            "methods": ["isRooted", "isRootedWithoutBusyBoxCheck", "detectRootManagementApps"],
        },
    },
    "crypto": {
        "javax.crypto.Cipher": {
            "description": "JCA Cipher (core crypto)",
            "methods": ["getInstance", "init", "doFinal", "update"],
        },
    },
    "auth": {
        "android.webkit.CookieManager": {
            "description": "WebView Cookie Manager",
            "methods": ["getCookie", "setCookie"],
        },
    },
}

# ═══════════════════════════════════════════════════════════
#  NATIVE LIBRARY PATTERNS
# ═══════════════════════════════════════════════════════════

NATIVE_PATTERNS = {
    "ssl_pinning": ["ssl", "tls", "cert", "pin", "conscrypt", "boring"],
    "root_detection": ["root", "magisk", "su", "integrity"],
    "crypto": ["crypto", "cipher", "aes", "openssl", "sodium"],
    "auth": ["auth", "oauth", "jwt", "session"],
}


# ═══════════════════════════════════════════════════════════
#  LAYER 1: INTERFACE & SUPERCLASS DISCOVERY
# ═══════════════════════════════════════════════════════════

def discover_by_interface(runner, task="ssl_pinning", timeout=30):
    """Find classes implementing known security interfaces."""

    targets = INTERFACE_TARGETS.get(task, INTERFACE_TARGETS["ssl_pinning"])
    targets_json = json.dumps(targets)

    # Build keyword filter from target class names for fast pre-screening
    # e.g. "javax.net.ssl.X509TrustManager" → ["ssl", "trust", "hostname", "certificate", "pinner", ...]
    keywords = set()
    for t in targets:
        parts = t.lower().replace(".", " ").split()
        for p in parts:
            if len(p) > 3 and p not in ("javax", "java", "android", "internal", "net", "com"):
                keywords.add(p)
    # Add common SSL/security related terms
    keywords.update(["ssl", "trust", "pinning", "certificate", "hostname",
                     "verifier", "conscrypt", "trustkit", "okhttp"])
    keywords_json = json.dumps(list(keywords))

    print(f"[LAYER 1] Searching for implementations of {len(targets)} interfaces...")

    inner_js = f"""
        var targets = {targets_json};
        var keywords = {keywords_json};
        var found = [];

        // Step 1: Fast sync enumeration + keyword pre-filter
        var allClasses = Java.enumerateLoadedClassesSync();
        console.log("  Total loaded classes: " + allClasses.length);

        var candidates = [];
        for (var c = 0; c < allClasses.length; c++) {{
            var cl = allClasses[c].toLowerCase();
            for (var k = 0; k < keywords.length; k++) {{
                if (cl.indexOf(keywords[k]) !== -1) {{
                    candidates.push(allClasses[c]);
                    break;
                }}
            }}
        }}
        console.log("  Pre-filtered candidates: " + candidates.length);

        // Step 2: isAssignableFrom only on candidates (much faster)
        for (var i = 0; i < candidates.length; i++) {{
            var className = candidates[i];
            try {{
                var clazz = Java.use(className);
                for (var t = 0; t < targets.length; t++) {{
                    try {{
                        var iface = Java.use(targets[t]);
                        if (iface.class.isAssignableFrom(clazz.class)) {{
                            if (className !== targets[t]) {{
                                var methods = clazz.class.getDeclaredMethods();
                                var methodNames = [];
                                for (var m = 0; m < methods.length && m < 20; m++) {{
                                    methodNames.push(methods[m].getName());
                                }}
                                found.push({{
                                    "class": className,
                                    "implements": targets[t],
                                    "methods": methodNames
                                }});
                            }}
                        }}
                    }} catch(e2) {{}}
                }}
            }} catch(e) {{}}
        }}

        console.log("__JSON__:" + JSON.stringify(found));
    """

    js = wrap_java_script(inner_js, wait_ms=8000, settle_ms=3000)
    result = runner.run(js, timeout=timeout + 15)

    # Debug: show what came back
    if result.debug_lines:
        for dl in result.debug_lines[:5]:
            print(f"  [debug] {dl}")

    findings = result.all_flat()
    print(f"[LAYER 1] Found {len(findings)} implementations")

    if result.errors:
        for e in result.errors[:3]:
            print(f"  [!] {e}")

    if not findings and not result.errors:
        print(f"  [debug] done={result.done}, raw_len={len(result.raw_stdout)}")

    return findings


# ═══════════════════════════════════════════════════════════
#  LAYER 2: METHOD SIGNATURE ANALYSIS
# ═══════════════════════════════════════════════════════════

def enumerate_methods(runner, class_list, timeout=30):
    """Get full method signatures for discovered classes."""

    if not class_list:
        print("[LAYER 2] No classes to enumerate, skipping")
        return {}

    classes_json = json.dumps(class_list[:30])  # cap at 30
    print(f"[LAYER 2] Enumerating methods for {min(len(class_list), 30)} classes...")

    inner_js = f"""
        var classes = {classes_json};
        var result = {{}};

        for (var i = 0; i < classes.length; i++) {{
            var className = classes[i];
            try {{
                var clazz = Java.use(className);
                var methods = clazz.class.getDeclaredMethods();
                var methodList = [];

                for (var m = 0; m < methods.length && m < 30; m++) {{
                    var method = methods[m];
                    var params = method.getParameterTypes();
                    var paramNames = [];
                    for (var p = 0; p < params.length; p++) {{
                        paramNames.push(params[p].getName());
                    }}
                    methodList.push({{
                        "name": method.getName(),
                        "returns": method.getReturnType().getName(),
                        "params": paramNames,
                        "modifiers": method.getModifiers()
                    }});
                }}

                result[className] = methodList;
            }} catch(e) {{
                result[className] = [{{"error": e.toString()}}];
            }}
        }}

        console.log("__JSON__:" + JSON.stringify(result));
    """

    js = wrap_java_script(inner_js, wait_ms=8000, settle_ms=3000)
    res = runner.run(js, timeout=timeout)

    signatures = res.first() or {}
    total_methods = sum(len(v) for v in signatures.values() if isinstance(v, list))
    print(f"[LAYER 2] Enumerated {total_methods} methods across {len(signatures)} classes")

    return signatures


# ═══════════════════════════════════════════════════════════
#  LAYER 3: KNOWN LIBRARY FINGERPRINTING
# ═══════════════════════════════════════════════════════════

def fingerprint_libraries(runner, task="ssl_pinning", timeout=45):
    """Detect known security libraries by checking specific class+method combos."""

    fingerprints = LIBRARY_FINGERPRINTS.get(task, LIBRARY_FINGERPRINTS.get("ssl_pinning", {}))

    if not fingerprints:
        print("[LAYER 3] No fingerprints for this task, skipping")
        return []

    fp_json = json.dumps(fingerprints)
    print(f"[LAYER 3] Checking {len(fingerprints)} library fingerprints...")

    inner_js = f"""
        var fingerprints = {fp_json};
        var found = [];

        var classNames = Object.keys(fingerprints);
        for (var i = 0; i < classNames.length; i++) {{
            var className = classNames[i];
            var fp = fingerprints[className];

            try {{
                var clazz = Java.use(className);
                var methods = clazz.class.getDeclaredMethods();
                var methodNames = [];
                for (var m = 0; m < methods.length; m++) {{
                    methodNames.push(methods[m].getName());
                }}

                var matchedMethods = [];
                for (var j = 0; j < fp.methods.length; j++) {{
                    if (methodNames.indexOf(fp.methods[j]) !== -1) {{
                        matchedMethods.push({{
                            "method": fp.methods[j],
                            "params": ""
                        }});
                    }}
                }}

                if (matchedMethods.length > 0) {{
                    found.push({{
                        "class": className,
                        "description": fp.description,
                        "matched_methods": matchedMethods,
                        "confidence": matchedMethods.length / fp.methods.length
                    }});
                }}
            }} catch(e) {{
                // Class not loaded — skip
            }}
        }}

        console.log("__JSON__:" + JSON.stringify(found));
    """

    js = wrap_java_script(inner_js, wait_ms=8000, settle_ms=3000)
    res = runner.run(js, timeout=timeout)

    libs = res.all_flat()
    print(f"[LAYER 3] Detected {len(libs)} libraries")

    for lib in libs:
        conf = int(lib.get("confidence", 0) * 100)
        print(f"  [{conf}%] {lib.get('description', '?')} — {lib.get('class', '?')}")

    return libs


# ═══════════════════════════════════════════════════════════
#  LAYER 4: NATIVE MODULE SCANNING
# ═══════════════════════════════════════════════════════════

def scan_native_modules(runner, task="ssl_pinning", timeout=20):
    """Scan loaded native .so modules for security-relevant exports."""

    patterns = NATIVE_PATTERNS.get(task, NATIVE_PATTERNS["ssl_pinning"])
    patterns_json = json.dumps(patterns)

    print(f"[LAYER 4] Scanning native modules for {len(patterns)} patterns...")

    # Native scanning doesn't need Java.perform
    inner_js = f"""
        var patterns = {patterns_json};
        var found = [];

        var modules = Process.enumerateModules();
        for (var i = 0; i < modules.length; i++) {{
            var mod = modules[i];
            var nameLower = mod.name.toLowerCase();

            var isRelevant = false;
            for (var p = 0; p < patterns.length; p++) {{
                if (nameLower.indexOf(patterns[p]) !== -1) {{
                    isRelevant = true;
                    break;
                }}
            }}

            if (isRelevant) {{
                var exports = [];
                try {{
                    var modExports = mod.enumerateExports();
                    for (var e = 0; e < modExports.length && e < 50; e++) {{
                        var exp = modExports[e];
                        if (exp.type === "function") {{
                            var expLower = exp.name.toLowerCase();
                            for (var p2 = 0; p2 < patterns.length; p2++) {{
                                if (expLower.indexOf(patterns[p2]) !== -1) {{
                                    exports.push({{
                                        "name": exp.name,
                                        "address": exp.address.toString()
                                    }});
                                    break;
                                }}
                            }}
                        }}
                    }}
                }} catch(e) {{}}

                if (exports.length > 0) {{
                    found.push({{
                        "module": mod.name,
                        "path": mod.path,
                        "exports": exports
                    }});
                }}
            }}
        }}

        console.log("__JSON__:" + JSON.stringify(found));
    """

    js = wrap_plain_script(inner_js, wait_ms=8000, settle_ms=3000)
    res = runner.run(js, timeout=timeout)

    modules = res.all_flat()
    print(f"[LAYER 4] Found {len(modules)} relevant native modules")

    for mod in modules:
        print(f"  {mod.get('module', '?')} — {len(mod.get('exports', []))} exports")

    return modules


# ═══════════════════════════════════════════════════════════
#  LAYER 5: NETWORK SECURITY CONFIG
# ═══════════════════════════════════════════════════════════

def read_network_security_config(package_name, timeout=15):
    """Read network_security_config.xml via static APK analysis (no Frida session)."""

    print("[LAYER 5] Checking for network security config...")

    result = {"has_config": False, "content": ""}

    try:
        apk_path = _pull_apk(package_name, timeout)
        if not apk_path:
            print("[LAYER 5] No network security config found")
            return result

        try:
            nsc_bytes = _extract_nsc_from_apk(apk_path)
            if nsc_bytes is None:
                print("[LAYER 5] No network security config found")
                return result

            xml_text = _decode_axml(nsc_bytes)
            if xml_text:
                result = _parse_nsc_xml(xml_text)
        finally:
            try:
                os.unlink(apk_path)
            except OSError:
                pass
    except Exception as e:
        print(f"[LAYER 5] Warning: could not read network security config: {e}")

    if result.get("has_config"):
        print("[LAYER 5] Network security config FOUND")
        if result.get("has_pins"):
            print("  [!] Certificate pinning configured via XML")
    else:
        print("[LAYER 5] No network security config found")

    return result


def _pull_apk(package_name, timeout=15):
    """Pull APK from device via adb. Returns temp file path or None."""
    try:
        pm = subprocess.run(
            ["adb", "shell", "pm", "path", package_name],
            capture_output=True, text=True, timeout=timeout
        )
        device_path = None
        for line in pm.stdout.strip().splitlines():
            if line.startswith("package:"):
                device_path = line.split("package:", 1)[1]
                break
        if not device_path:
            return None

        fd, tmp_path = tempfile.mkstemp(suffix=".apk", prefix="fridai_nsc_")
        os.close(fd)

        subprocess.run(
            ["adb", "pull", device_path, tmp_path],
            capture_output=True, text=True, timeout=60
        )
        if os.path.getsize(tmp_path) == 0:
            os.unlink(tmp_path)
            return None
        return tmp_path
    except Exception:
        return None


def _extract_nsc_from_apk(apk_path):
    """Extract network_security_config.xml bytes from an APK zip."""
    try:
        with zipfile.ZipFile(apk_path) as zf:
            if "res/xml/network_security_config.xml" in zf.namelist():
                return zf.read("res/xml/network_security_config.xml")
    except Exception:
        pass
    return None


def _decode_axml(raw_bytes):
    """Decode binary AXML to XML text using pyaxmlparser."""
    if _AXML is None:
        print("[LAYER 5] WARNING: pyaxmlparser not installed, cannot parse binary XML")
        print("  Install: pip install pyaxmlparser")
        return None

    fd, tmp_path = tempfile.mkstemp(suffix=".xml", prefix="fridai_axml_")
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(raw_bytes)
        axml = _AXML(tmp_path)
        xml_result = axml.get_xml()
        if isinstance(xml_result, bytes):
            xml_result = xml_result.decode('utf-8', errors='replace')
        return xml_result
    except Exception as e:
        print(f"[LAYER 5] WARNING: failed to decode AXML: {e}")
        return None
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


def _parse_nsc_xml(xml_text):
    """Parse decoded network_security_config XML text."""
    return {
        "has_config": True,
        "content": xml_text,
        "has_pins": "pin-set" in xml_text.lower() if xml_text else False,
    }


# ═══════════════════════════════════════════════════════════
#  ORCHESTRATOR
# ═══════════════════════════════════════════════════════════

def _build_combined_js(task):
    """Build a single JS payload that runs Layers 1-4 in one Frida session."""

    targets = INTERFACE_TARGETS.get(task, INTERFACE_TARGETS["ssl_pinning"])
    targets_json = json.dumps(targets)

    keywords = set()
    for t in targets:
        parts = t.lower().replace(".", " ").split()
        for p in parts:
            if len(p) > 3 and p not in ("javax", "java", "android", "internal", "net", "com"):
                keywords.add(p)
    keywords.update(["ssl", "trust", "pinning", "certificate", "hostname",
                     "verifier", "conscrypt", "trustkit", "okhttp"])
    keywords_json = json.dumps(list(keywords))

    fingerprints = LIBRARY_FINGERPRINTS.get(task, LIBRARY_FINGERPRINTS.get("ssl_pinning", {}))
    fp_json = json.dumps(fingerprints)

    patterns = NATIVE_PATTERNS.get(task, NATIVE_PATTERNS["ssl_pinning"])
    patterns_json = json.dumps(patterns)

    return f"""
setTimeout(function() {{
    // ── Layer 4: Native module scanning (no Java needed) ──
    try {{
        var patterns = {patterns_json};
        var nativeFound = [];
        var modules = Process.enumerateModules();
        for (var i = 0; i < modules.length; i++) {{
            var mod = modules[i];
            var nameLower = mod.name.toLowerCase();
            var isRelevant = false;
            for (var p = 0; p < patterns.length; p++) {{
                if (nameLower.indexOf(patterns[p]) !== -1) {{
                    isRelevant = true;
                    break;
                }}
            }}
            if (isRelevant) {{
                var exports = [];
                try {{
                    var modExports = mod.enumerateExports();
                    for (var e = 0; e < modExports.length && e < 50; e++) {{
                        var exp = modExports[e];
                        if (exp.type === "function") {{
                            var expLower = exp.name.toLowerCase();
                            for (var p2 = 0; p2 < patterns.length; p2++) {{
                                if (expLower.indexOf(patterns[p2]) !== -1) {{
                                    exports.push({{
                                        "name": exp.name,
                                        "address": exp.address.toString()
                                    }});
                                    break;
                                }}
                            }}
                        }}
                    }}
                }} catch(ex) {{}}
                if (exports.length > 0) {{
                    nativeFound.push({{
                        "module": mod.name,
                        "path": mod.path,
                        "exports": exports
                    }});
                }}
            }}
        }}
        console.log("__JSON__:" + JSON.stringify({{"layer": "layer4", "data": nativeFound}}));
    }} catch(e) {{
        console.log("__ERROR__:layer4:" + e.toString());
        console.log("__JSON__:" + JSON.stringify({{"layer": "layer4", "data": []}}));
    }}

    // ── Java layers (1, 3, 2) ──
    try {{
        Java.perform(function() {{
            // Layer 1: Interface & superclass discovery
            var layer1Results = [];
            try {{
                var targets = {targets_json};
                var keywords = {keywords_json};
                var allClasses = Java.enumerateLoadedClassesSync();
                console.log("  Total loaded classes: " + allClasses.length);

                var candidates = [];
                for (var c = 0; c < allClasses.length; c++) {{
                    var cl = allClasses[c].toLowerCase();
                    for (var k = 0; k < keywords.length; k++) {{
                        if (cl.indexOf(keywords[k]) !== -1) {{
                            candidates.push(allClasses[c]);
                            break;
                        }}
                    }}
                }}
                console.log("  Pre-filtered candidates: " + candidates.length);

                for (var i = 0; i < candidates.length; i++) {{
                    var className = candidates[i];
                    try {{
                        var clazz = Java.use(className);
                        for (var t = 0; t < targets.length; t++) {{
                            try {{
                                var iface = Java.use(targets[t]);
                                if (iface.class.isAssignableFrom(clazz.class)) {{
                                    if (className !== targets[t]) {{
                                        var methods = clazz.class.getDeclaredMethods();
                                        var methodNames = [];
                                        for (var m = 0; m < methods.length && m < 20; m++) {{
                                            methodNames.push(methods[m].getName());
                                        }}
                                        layer1Results.push({{
                                            "class": className,
                                            "implements": targets[t],
                                            "methods": methodNames
                                        }});
                                    }}
                                }}
                            }} catch(e2) {{}}
                        }}
                    }} catch(e) {{}}
                }}
            }} catch(e) {{
                console.log("__ERROR__:layer1:" + e.toString());
            }}
            console.log("__JSON__:" + JSON.stringify({{"layer": "layer1", "data": layer1Results}}));

            // Layer 3: Known library fingerprinting
            var layer3Results = [];
            try {{
                var fingerprints = {fp_json};
                var classNames = Object.keys(fingerprints);
                for (var i = 0; i < classNames.length; i++) {{
                    var className = classNames[i];
                    var fp = fingerprints[className];
                    try {{
                        var clazz = Java.use(className);
                        var methods = clazz.class.getDeclaredMethods();
                        var methodNames = [];
                        for (var m = 0; m < methods.length; m++) {{
                            methodNames.push(methods[m].getName());
                        }}
                        var matchedMethods = [];
                        for (var j = 0; j < fp.methods.length; j++) {{
                            if (methodNames.indexOf(fp.methods[j]) !== -1) {{
                                matchedMethods.push({{
                                    "method": fp.methods[j],
                                    "params": ""
                                }});
                            }}
                        }}
                        if (matchedMethods.length > 0) {{
                            layer3Results.push({{
                                "class": className,
                                "description": fp.description,
                                "matched_methods": matchedMethods,
                                "confidence": matchedMethods.length / fp.methods.length
                            }});
                        }}
                    }} catch(e) {{}}
                }}
            }} catch(e) {{
                console.log("__ERROR__:layer3:" + e.toString());
            }}
            console.log("__JSON__:" + JSON.stringify({{"layer": "layer3", "data": layer3Results}}));

            // Layer 2: Method signature analysis (depends on Layer 1 + Layer 3)
            var layer2Results = {{}};
            try {{
                var discoveredClasses = [];
                for (var i = 0; i < layer1Results.length; i++) {{
                    discoveredClasses.push(layer1Results[i]["class"]);
                }}
                for (var i = 0; i < layer3Results.length; i++) {{
                    var lc = layer3Results[i]["class"];
                    if (discoveredClasses.indexOf(lc) === -1) {{
                        discoveredClasses.push(lc);
                    }}
                }}

                var maxClasses = Math.min(discoveredClasses.length, 30);
                for (var i = 0; i < maxClasses; i++) {{
                    var className = discoveredClasses[i];
                    try {{
                        var clazz = Java.use(className);
                        var methods = clazz.class.getDeclaredMethods();
                        var methodList = [];
                        for (var m = 0; m < methods.length && m < 30; m++) {{
                            var method = methods[m];
                            var params = method.getParameterTypes();
                            var paramNames = [];
                            for (var p = 0; p < params.length; p++) {{
                                paramNames.push(params[p].getName());
                            }}
                            methodList.push({{
                                "name": method.getName(),
                                "returns": method.getReturnType().getName(),
                                "params": paramNames,
                                "modifiers": method.getModifiers()
                            }});
                        }}
                        layer2Results[className] = methodList;
                    }} catch(e) {{
                        layer2Results[className] = [{{"error": e.toString()}}];
                    }}
                }}
            }} catch(e) {{
                console.log("__ERROR__:layer2:" + e.toString());
            }}
            console.log("__JSON__:" + JSON.stringify({{"layer": "layer2", "data": layer2Results}}));
        }});
    }} catch(e) {{
        console.log("__ERROR__:Java.perform failed: " + e.toString());
    }}

    setTimeout(function() {{
        console.log("__DONE__");
    }}, 5000);
}}, 8000);
"""


def _combined_recon(runner, recon_data, task, timeout):
    """Run Layers 1-4 in a single Frida session (one app spawn)."""

    print("\n[RECON] Single-session mode (one app spawn for all layers)")

    js = _build_combined_js(task)
    result = runner.run(js, timeout=max(timeout * 3, 90))

    for payload in result.all_flat():
        if not isinstance(payload, dict) or "layer" not in payload:
            continue
        layer = payload["layer"]
        data = payload.get("data")
        if layer == "layer1" and isinstance(data, list):
            recon_data["interface_implementations"] = data
        elif layer == "layer2" and isinstance(data, dict):
            recon_data["method_signatures"] = data
        elif layer == "layer3" and isinstance(data, list):
            recon_data["library_fingerprints"] = data
        elif layer == "layer4" and isinstance(data, list):
            recon_data["native_modules"] = data

    impls = recon_data["interface_implementations"]
    libs = recon_data["library_fingerprints"]
    sigs = recon_data["method_signatures"]
    mods = recon_data["native_modules"]

    print(f"[LAYER 1] Found {len(impls)} implementations")
    print(f"[LAYER 3] Detected {len(libs)} libraries")
    for lib in libs:
        conf = int(lib.get("confidence", 0) * 100)
        print(f"  [{conf}%] {lib.get('description', '?')} — {lib.get('class', '?')}")
    total_methods = sum(len(v) for v in sigs.values() if isinstance(v, list))
    print(f"[LAYER 2] Enumerated {total_methods} methods across {len(sigs)} classes")
    print(f"[LAYER 4] Found {len(mods)} relevant native modules")
    for mod in mods:
        print(f"  {mod.get('module', '?')} — {len(mod.get('exports', []))} exports")

    if result.debug_lines:
        for dl in result.debug_lines[:5]:
            print(f"  [debug] {dl}")

    if result.errors:
        for e in result.errors[:5]:
            print(f"  [!] {e}")


def _legacy_recon(runner, recon_data, task, timeout):
    """Original multi-session recon (one Frida spawn per layer)."""

    print()
    recon_data["interface_implementations"] = discover_by_interface(
        runner, task=task, timeout=timeout
    )
    discovered_classes = [
        f["class"] for f in recon_data["interface_implementations"]
    ]

    print()
    recon_data["library_fingerprints"] = fingerprint_libraries(
        runner, task=task, timeout=timeout + 15
    )
    for lib in recon_data["library_fingerprints"]:
        if lib["class"] not in discovered_classes:
            discovered_classes.append(lib["class"])

    if discovered_classes:
        print()
        recon_data["method_signatures"] = enumerate_methods(
            runner, discovered_classes, timeout=timeout
        )

    print()
    recon_data["native_modules"] = scan_native_modules(
        runner, task=task, timeout=30
    )


def deep_recon(package_name, task="ssl_pinning", timeout=30, legacy=False):
    """
    Run all reconnaissance layers and produce a comprehensive
    data package for the LLM.

    By default, Layers 1-4 run in a single Frida session (one app spawn).
    Use legacy=True to run each layer in a separate session.
    Layer 5 (network security config) is always standalone static analysis.
    """
    print()
    print("=" * 55)
    print(f"  DEEP RECON — {task}")
    if legacy:
        print("  (legacy multi-session mode)")
    print("=" * 55)

    runner = FridaRunner(package_name, spawn=True)

    recon_data = {
        "package": package_name,
        "task": task,
        "interface_implementations": [],
        "method_signatures": {},
        "library_fingerprints": [],
        "native_modules": [],
        "network_security_config": None,
    }

    try:
        if legacy:
            _legacy_recon(runner, recon_data, task, timeout)
        else:
            _combined_recon(runner, recon_data, task, timeout)

        # Layer 5: Static APK analysis (no Frida session needed)
        if task == "ssl_pinning":
            print()
            recon_data["network_security_config"] = read_network_security_config(
                package_name, timeout=15
            )

    finally:
        runner.cleanup()

    # Summary
    print()
    print("-" * 55)
    print("[RECON] Summary:")
    print(f"  Interface implementations: {len(recon_data['interface_implementations'])}")
    print(f"  Classes with methods:      {len(recon_data['method_signatures'])}")
    print(f"  Library fingerprints:      {len(recon_data['library_fingerprints'])}")
    print(f"  Native module hits:        {len(recon_data['native_modules'])}")
    has_nsc = recon_data["network_security_config"] and \
              recon_data["network_security_config"].get("has_config")
    print(f"  Network security config:   {'Found' if has_nsc else 'Not found'}")
    print("-" * 55)

    return recon_data


def save_recon(recon_data, output_path="output/recon_results.json"):
    """Save full recon results to JSON for debugging."""
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(recon_data, f, indent=2, ensure_ascii=False)
    print(f"[RECON] Full results saved to {output_path}")


def format_for_llm(recon_data):
    """
    Convert rich recon data into a structured text prompt section
    that the LLM can understand and use to write precise hooks.
    """
    sections = []

    # Section 1: Interface implementations with methods
    if recon_data["interface_implementations"]:
        section = "=== DISCOVERED IMPLEMENTATIONS ===\n"
        section += "(Classes implementing security-relevant interfaces)\n\n"

        for impl in recon_data["interface_implementations"]:
            cls = impl["class"]
            iface = impl["implements"]
            section += f"Class: {cls}\n"
            section += f"  Implements: {iface}\n"

            methods = recon_data["method_signatures"].get(cls, [])
            if methods:
                section += "  Methods:\n"
                for m in methods:
                    if isinstance(m, dict) and "name" in m:
                        params = ", ".join(m.get("params", [])) if m.get("params") else ""
                        section += f"    {m.get('returns', 'void')} {m['name']}({params})\n"
            section += "\n"

        sections.append(section)

    # Section 2: Library fingerprints
    if recon_data["library_fingerprints"]:
        section = "=== IDENTIFIED LIBRARIES ===\n"
        section += "(Known security libraries detected via method fingerprinting)\n\n"

        for lib in recon_data["library_fingerprints"]:
            section += f"Library: {lib['description']}\n"
            section += f"  Class: {lib['class']}\n"
            section += f"  Confidence: {int(lib.get('confidence', 0) * 100)}%\n"
            section += "  Methods found:\n"
            for m in lib.get("matched_methods", []):
                section += f"    {m['method']}({m.get('params', '')})\n"

            methods = recon_data["method_signatures"].get(lib["class"], [])
            if methods:
                section += "  All methods in this class:\n"
                for m in methods:
                    if isinstance(m, dict) and "name" in m:
                        params = ", ".join(m.get("params", [])) if m.get("params") else ""
                        section += f"    {m.get('returns', 'void')} {m['name']}({params})\n"
            section += "\n"

        sections.append(section)

    # Section 3: Native modules
    if recon_data["native_modules"]:
        section = "=== NATIVE MODULES ===\n"
        section += "(SSL/crypto functions found in native .so libraries)\n\n"

        for mod in recon_data["native_modules"]:
            section += f"Module: {mod['module']} ({mod.get('path', '')})\n"
            for exp in mod.get("exports", []):
                section += f"  Export: {exp['name']} @ {exp.get('address', '?')}\n"
            section += "\n"

        sections.append(section)

    # Section 4: Network security config
    nsc = recon_data.get("network_security_config")
    if nsc and nsc.get("has_config"):
        section = "=== NETWORK SECURITY CONFIG ===\n"
        section += "(Android XML-based certificate pinning configuration)\n\n"
        section += nsc.get("content", "Could not read content")
        section += "\n"
        sections.append(section)

    if not sections:
        return "No security-relevant classes or modules were found through deep analysis."

    return "\n".join(sections)