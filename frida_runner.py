"""
frida_runner.py — Subprocess-based Frida execution engine

Replaces Frida Python API's create_script() which has a known bug
where Java bridge is not loaded (Java is not defined).

Strategy:
  1. Write JS code to a temp file
  2. Run: timeout <T> frida -U -f <package> -l script.js
  3. Parse stdout lines (console.log output)
  4. Return structured results

Convention:
  - Scripts use console.log() for output (not send())
  - JSON payloads: console.log("__JSON__:" + JSON.stringify(data))
  - Completion signal: console.log("__DONE__")
  - Error signal: console.log("__ERROR__:" + message)
"""

import atexit
import subprocess
import tempfile
import json
import os
import time


_temp_files_registry = []


def _atexit_cleanup():
    for path in list(_temp_files_registry):
        try:
            os.unlink(path)
        except OSError:
            pass
    _temp_files_registry.clear()


atexit.register(_atexit_cleanup)


class FridaRunner:
    """
    Runs Frida JS scripts via subprocess (frida CLI).

    Usage:
        runner = FridaRunner("com.target.app")
        results = runner.run(js_code, timeout=30)
        # results = list of parsed payloads
        runner.cleanup()
    """

    def __init__(self, package_name, spawn=True):
        """
        Args:
            package_name: Android package to target
            spawn: If True, use -f (spawn). If False, use -n (attach to running).
        """
        self.package = package_name
        self.spawn = spawn
        self._temp_files = []

    def run(self, js_code, timeout=30, wait_before_exit=5):
        """
        Execute a Frida JS script and return parsed results.

        The JS code should use:
          - console.log("__JSON__:" + JSON.stringify(obj))  for data
          - console.log("__DONE__")  as completion signal
          - console.log("__ERROR__:" + msg)  for errors
          - Plain console.log() for debug info

        Args:
            js_code: JavaScript source code to inject
            timeout: Max seconds before killing frida process
            wait_before_exit: Extra seconds in JS before __DONE__ (let hooks settle)

        Returns:
            FridaResult with .payloads, .errors, .raw_output, .success
        """
        # Write JS to temp file
        script_path = self._write_temp(js_code)

        # Build frida command (no 'timeout' cmd — we manage it ourselves)
        cmd = ["frida", "-U"]

        if self.spawn:
            cmd += ["-f", self.package]
        else:
            cmd += ["-n", self.package]

        cmd += ["-l", script_path]

        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,  # line-buffered
        )

        stdout_lines = []
        done = False
        start = time.monotonic()

        try:
            while time.monotonic() - start < timeout:
                line = proc.stdout.readline()
                if not line:
                    if proc.poll() is not None:
                        break
                    continue
                stdout_lines.append(line.rstrip("\n"))

                # Check for completion signal
                # Handle REPL prompt prefix: [device::app ]-> __DONE__
                check_line = line.strip()
                if "]-> " in check_line:
                    check_line = check_line[check_line.index("]-> ") + 4:]
                if check_line == "__DONE__":
                    done = True
                    break
        except Exception:
            pass

        # Kill process if still running
        if proc.poll() is None:
            try:
                proc.kill()
                proc.wait(timeout=3)
            except Exception:
                pass

        # Read any remaining stderr
        stderr = ""
        try:
            stderr = proc.stderr.read() or ""
        except Exception:
            pass

        stdout = "\n".join(stdout_lines)
        return self._parse_output(stdout, stderr)

    def run_and_keep(self, js_code, timeout=60):
        """
        Start a Frida script and return the Popen process.
        Used for long-running hooks (injection phase).
        Caller manages the process lifecycle.

        Returns:
            (process, script_path) — Popen object + temp script path
        """
        script_path = self._write_temp(js_code)

        cmd = ["frida", "-U"]
        if self.spawn:
            cmd += ["-f", self.package]
        else:
            cmd += ["-n", self.package]
        cmd += ["-l", script_path]

        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,  # line-buffered
        )

        return proc, script_path

    def _write_temp(self, js_code):
        """Write JS code to a temp file, return path."""
        fd, path = tempfile.mkstemp(suffix=".js", prefix="fridai_")
        with os.fdopen(fd, "w") as f:
            f.write(js_code)
        self._temp_files.append(path)
        _temp_files_registry.append(path)
        return path

    def _parse_output(self, stdout, stderr):
        """Parse frida CLI stdout into structured results."""
        payloads = []
        errors = []
        debug_lines = []
        done = False

        for line in stdout.splitlines():
            line = line.strip()

            # Skip frida banner lines
            if not line or line.startswith(("____", "/ _", "| (_", "> _",
                                           "/_/", ". . .", "Spawned",
                                           "Resuming", "Commands:", "More info",
                                           "Connected to")):
                continue

            # Frida REPL prompt can prepend to output lines, e.g.:
            #   [SM M317F::com.app ]-> __JSON__:{...}
            #   [SM M317F::com.app ]-> __DONE__
            # Strip the prompt prefix if present
            prompt_marker = "]-> "
            if prompt_marker in line:
                line = line[line.index(prompt_marker) + len(prompt_marker):]

            if not line:
                continue

            if line == "__DONE__":
                done = True
                continue

            if line.startswith("__JSON__:"):
                json_str = line[9:]  # len("__JSON__:") == 9
                try:
                    obj = json.loads(json_str)
                    payloads.append(obj)
                except json.JSONDecodeError:
                    debug_lines.append(f"[JSON PARSE FAIL] {json_str[:200]}")
                continue

            if line.startswith("__ERROR__:"):
                errors.append(line[10:])
                continue

            # Anything else is debug output
            debug_lines.append(line)

        # Check stderr for frida errors
        if stderr:
            for line in stderr.splitlines():
                line = line.strip()
                if line and not line.startswith("Warning:"):
                    errors.append(f"[stderr] {line}")

        return FridaResult(
            payloads=payloads,
            errors=errors,
            debug_lines=debug_lines,
            raw_stdout=stdout,
            done=done,
        )

    def cleanup(self):
        """Remove temp script files."""
        for path in self._temp_files:
            try:
                os.unlink(path)
            except OSError:
                pass
            try:
                _temp_files_registry.remove(path)
            except ValueError:
                pass
        self._temp_files.clear()


class FridaResult:
    """Structured result from a Frida script execution."""

    def __init__(self, payloads, errors, debug_lines, raw_stdout, done):
        self.payloads = payloads        # list of parsed JSON objects
        self.errors = errors            # list of error strings
        self.debug_lines = debug_lines  # list of plain console.log lines
        self.raw_stdout = raw_stdout    # full stdout string
        self.done = done                # True if __DONE__ was received

    @property
    def success(self):
        """True if we got at least one payload and no critical errors."""
        return len(self.payloads) > 0 and len(self.errors) == 0

    @property
    def has_data(self):
        """True if any payloads were received."""
        return len(self.payloads) > 0

    def first(self):
        """Return first payload or None."""
        return self.payloads[0] if self.payloads else None

    def all_flat(self):
        """
        If each payload is a list, flatten them all into one list.
        Common pattern: each send() batch is a list of findings.
        """
        flat = []
        for p in self.payloads:
            if isinstance(p, list):
                flat.extend(p)
            else:
                flat.append(p)
        return flat

    def __repr__(self):
        return (
            f"FridaResult(payloads={len(self.payloads)}, "
            f"errors={len(self.errors)}, done={self.done})"
        )


# ═══════════════════════════════════════════════════════════
#  JS WRAPPER HELPERS
#  Wrap raw JS logic with proper setTimeout + __DONE__ signal
# ═══════════════════════════════════════════════════════════

def wrap_java_script(inner_js, wait_ms=5000, settle_ms=2000):
    """
    Wrap JS code that uses Java.perform() with proper timing.

    The wrapper:
      1. Waits wait_ms for Java VM to be ready
      2. Runs inner_js inside Java.perform()
      3. Waits settle_ms after execution
      4. Prints __DONE__ marker

    inner_js should use:
      console.log("__JSON__:" + JSON.stringify(data))
    for structured output.
    """
    return f"""
setTimeout(function() {{
    try {{
        Java.perform(function() {{
            try {{
                {inner_js}
            }} catch(e) {{
                console.log("__ERROR__:" + e.toString());
            }}
        }});
    }} catch(e) {{
        console.log("__ERROR__:Java.perform failed: " + e.toString());
    }}

    setTimeout(function() {{
        console.log("__DONE__");
    }}, {settle_ms});
}}, {wait_ms});
"""


def wrap_plain_script(inner_js, wait_ms=2000, settle_ms=1000):
    """
    Wrap JS code that does NOT need Java.perform().
    For native module scanning, Process.enumerateModules, etc.
    """
    return f"""
setTimeout(function() {{
    try {{
        {inner_js}
    }} catch(e) {{
        console.log("__ERROR__:" + e.toString());
    }}

    setTimeout(function() {{
        console.log("__DONE__");
    }}, {settle_ms});
}}, {wait_ms});
"""