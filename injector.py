"""
Phase 3: Self-Healing Injection Engine (subprocess-based)

Uses FridaRunner (subprocess frida CLI) instead of Frida Python API.
Injects LLM-generated hooks, monitors stdout for errors,
and sends errors back to LLM for auto-correction.
"""

import json
import os
import select
import signal
import time

from frida_runner import FridaRunner
from llm_bridge import request_fix


def inject_with_healing(package_name, hook_code, config):
    """
    Inject hook code with automatic error correction loop.

    Changed from old API:
      OLD: inject_with_healing(session, hook_code, config)
      NEW: inject_with_healing(package_name, hook_code, config)

    Args:
        package_name: Target Android package
        hook_code: JavaScript hook code to inject
        config: Dict with max_retries, inject_wait, model

    Returns:
        Tuple of (success: bool, process_or_errors)
          - On success: (True, Popen process) — caller manages lifecycle
          - On failure: (False, list of errors or None)
    """

    max_retries = config.get("max_retries", 3)
    inject_wait = config.get("inject_wait", 5)
    model = config.get("model", "claude-sonnet-4-20250514")

    runner = FridaRunner(package_name, spawn=True)
    current_code = hook_code

    try:
        for attempt in range(1, max_retries + 1):
            print(f"\n[INJECT] ===== Attempt #{attempt}/{max_retries} =====")

            if current_code is None:
                print("[INJECT] No code to inject, stopping")
                return False, None

            # Start long-running hook process
            proc, script_path = runner.run_and_keep(current_code)

            # Wait for hooks to load and check for errors
            print(f"[INJECT] Code injected, waiting {inject_wait}s for hooks to settle...")
            time.sleep(inject_wait)

            # Read whatever output is available so far
            # (non-blocking check — process should still be running)
            errors = []
            logs = []

            if proc.poll() is not None:
                # Process already exited — likely an error
                stdout, stderr = proc.communicate()
                errors, logs = _parse_inject_output(stdout, stderr)

                if errors:
                    print("[INJECT] Process exited with errors:")
                    for err in errors[:5]:
                        print(f"  {err}")

                    _save_attempt(attempt, current_code, errors)

                    if attempt < max_retries:
                        error_text = json.dumps(errors, indent=2, ensure_ascii=False)
                        current_code = request_fix(
                            current_code, error_text, model=model
                        )
                        continue
                    else:
                        print(f"[INJECT] Max retries ({max_retries}) exhausted")
                        return False, errors
            else:
                # Try to detect early errors in first few seconds
                early_errors = _check_early_errors(proc, check_duration=2)

                if early_errors:
                    print("[INJECT] Early errors detected:")
                    for err in early_errors[:5]:
                        print(f"  {err}")

                    # Kill the broken process
                    _kill_proc(proc)
                    _save_attempt(attempt, current_code, early_errors)

                    if attempt < max_retries:
                        error_text = json.dumps(early_errors, indent=2, ensure_ascii=False)
                        current_code = request_fix(
                            current_code, error_text, model=model
                        )
                        continue
                    else:
                        print(f"[INJECT] Max retries ({max_retries}) exhausted")
                        return False, early_errors

            # If we got here, process is running without errors — success!
            print(f"[INJECT] Hook loaded successfully! Process PID: {proc.pid}")
            return True, proc

        return False, None
    finally:
        runner.cleanup()


def _parse_inject_output(stdout, stderr):
    """Parse stdout/stderr from a completed inject process."""
    errors = []
    logs = []

    if stdout:
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            if line.startswith("__ERROR__:"):
                errors.append(line[10:])
            elif "Error:" in line or "ReferenceError:" in line or "TypeError:" in line:
                errors.append(line)
            else:
                logs.append(line)

    if stderr:
        for line in stderr.splitlines():
            line = line.strip()
            if line and not line.startswith("Warning:"):
                errors.append(f"[stderr] {line}")

    return errors, logs


def _check_early_errors(proc, check_duration=2):
    """
    Non-blocking check for early errors in the first few seconds.
    Reads stderr for Frida error messages.
    """
    errors = []
    end_time = time.time() + check_duration

    while time.time() < end_time:
        if proc.poll() is not None:
            # Process died
            stdout, stderr = proc.communicate()
            errs, _ = _parse_inject_output(stdout or "", stderr or "")
            errors.extend(errs)
            break

        # Check if stderr has data (non-blocking)
        # POSIX-only: select() on pipe FDs doesn't work on Windows.
        # Acceptable because Frida Android tooling requires a Linux/macOS host.
        try:
            ready, _, _ = select.select([proc.stderr], [], [], 0.1)
            if ready:
                line = proc.stderr.readline()
                if line:
                    line = line.strip()
                    if "Error:" in line or "error:" in line:
                        errors.append(line)
        except (ValueError, OSError):
            break

    return errors


def _kill_proc(proc):
    """Safely kill a Frida process."""
    try:
        proc.kill()
        proc.wait(timeout=3)
    except Exception:
        try:
            os.kill(proc.pid, signal.SIGKILL)
        except Exception:
            pass


def _save_attempt(attempt_num, code, errors):
    """Save failed attempt details for debugging."""
    os.makedirs("output", exist_ok=True)

    with open(f"output/attempt_{attempt_num}_code.js", "w") as f:
        f.write(code or "# None")

    with open(f"output/attempt_{attempt_num}_errors.json", "w") as f:
        json.dump(errors, f, indent=2, ensure_ascii=False)

    print(f"[INJECT] Attempt #{attempt_num} saved to output/")