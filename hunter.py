#!/usr/bin/env python3
"""
Auto-Hunter — Frida + Claude Autonomous Android Security Agent

Main entry point that orchestrates all three phases:
  1. Recon: Enumerate and filter loaded classes via Frida CLI (subprocess)
  2. LLM Bridge: Generate targeted hook code via Claude API
  3. Injection: Self-healing code injection with auto-retry

All Frida execution goes through FridaRunner (subprocess-based)
to avoid the 'Java is not defined' bug in frida-python 17.x.

Usage:
    python3 hunter.py
    python3 hunter.py --package com.target.app --task ssl_pinning
"""

import argparse
import json
import os
import subprocess
import sys
import time

from recon import deep_recon, save_recon, format_for_llm
from llm_bridge import generate_hook_from_recon, save_hook
from injector import inject_with_healing


BANNER = """
╔═════════════════════════════════════════════════════╗
║            AUTO-HUNTER  v0.2                        ║
║   Frida + Claude Autonomous Security Agent          ║
║   (subprocess-based -- no Python API bugs)          ║
╚═════════════════════════════════════════════════════╝
"""


def load_config(config_path="config.json"):
    """Load configuration from JSON file with defaults."""
    defaults = {
        "target_package": "",
        "task": "ssl_pinning",
        "model": "claude-sonnet-4-20250514",
        "max_retries": 3,
        "recon_timeout": 30,
        "inject_wait": 5,
    }

    if os.path.exists(config_path):
        with open(config_path) as f:
            user_config = json.load(f)
        defaults.update(user_config)

    return defaults


def preflight_checks(config):
    """Verify all dependencies are ready before starting."""
    print("[PREFLIGHT] Running checks...")
    ok = True

    # Check Anthropic API key
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if api_key:
        model = config.get("model", "claude-sonnet-4-20250514")
        print(f"  [+] Claude API key found")
        print(f"      Model: {model}")
    else:
        print("  [!] ANTHROPIC_API_KEY not set")
        print('      Run: export ANTHROPIC_API_KEY="sk-ant-..."')
        ok = False

    # Check Frida CLI is available
    try:
        result = subprocess.run(
            ["frida", "--version"],
            capture_output=True, text=True, timeout=5
        )
        version = result.stdout.strip()
        print(f"  [+] Frida CLI: v{version}")
    except (FileNotFoundError, subprocess.TimeoutExpired):
        print("  [!] Frida CLI not found")
        print("      Install: pip install frida-tools")
        ok = False

    # Check USB device via frida CLI
    try:
        result = subprocess.run(
            ["frida-ls-devices"],
            capture_output=True, text=True, timeout=10
        )
        if "usb" in result.stdout.lower():
            # Extract device name from output
            for line in result.stdout.splitlines():
                if "usb" in line.lower():
                    print(f"  [+] USB device: {line.strip()}")
                    break
        else:
            print("  [!] No USB device found")
            print("      Check: adb devices")
            ok = False
    except (FileNotFoundError, subprocess.TimeoutExpired):
        print("  [!] Could not list Frida devices")
        ok = False

    # Check target package
    package = config["target_package"]
    if not package:
        print("  [!] No target_package set in config.json")
        ok = False
    else:
        try:
            result = subprocess.run(
                ["frida-ps", "-U"],
                capture_output=True, text=True, timeout=10
            )
            if package in result.stdout:
                print(f"  [+] Target: {package} is running")
            else:
                print(f"  [~] {package} not currently running (will be spawned)")
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

    return ok


def main():
    print(BANNER)

    # Parse CLI arguments
    parser = argparse.ArgumentParser(
        description="Auto-Hunter: Autonomous Android Security Agent"
    )
    parser.add_argument("--package", "-p", help="Target package name")
    # Future tasks (root_detection, crypto, auth) not yet implemented
    parser.add_argument(
        "--task", "-t",
        choices=["ssl_pinning"],
        help="Analysis task"
    )
    parser.add_argument("--config", "-c", default="config.json", help="Config file path")
    parser.add_argument("--skip-checks", action="store_true", help="Skip preflight checks")
    parser.add_argument("--recon-only", action="store_true", help="Run only recon phase")
    parser.add_argument("--legacy-recon", action="store_true",
                        help="Run each recon layer in a separate Frida session (old behavior)")
    args = parser.parse_args()

    # Load config
    config = load_config(args.config)

    # CLI overrides
    if args.package:
        config["target_package"] = args.package
    if args.task:
        config["task"] = args.task

    package = config["target_package"]
    task = config["task"]

    if not package:
        print("[ERROR] No target package specified.")
        print("  Set in config.json or: python3 hunter.py -p com.example.app")
        sys.exit(1)

    print(f"  Target:  {package}")
    print(f"  Task:    {task}")
    print(f"  Model:   {config['model']}")
    print(f"  Retries: {config['max_retries']}")
    print()

    # Preflight
    if not args.skip_checks:
        if not preflight_checks(config):
            print("\n[ERROR] Preflight checks failed.")
            print("        Use --skip-checks to bypass")
            sys.exit(1)
        print()

    # ═══════════════════════════════════════════
    # PHASE 1: DEEP RECON
    # ═══════════════════════════════════════════
    recon_data = deep_recon(
        package, task=task, timeout=config["recon_timeout"],
        legacy=args.legacy_recon
    )
    save_recon(recon_data)

    if args.recon_only:
        print("\n[*] Recon-only mode. Done.")
        print(f"    Results: output/recon_results.json")
        sys.exit(0)

    # ═══════════════════════════════════════════
    # PHASE 2: LLM HOOK GENERATION
    # ═══════════════════════════════════════════
    print()
    print("=" * 55)
    print("  PHASE 2 — LLM HOOK GENERATION")
    print("=" * 55)

    hook_code = generate_hook_from_recon(
        recon_data, model=config["model"]
    )

    if hook_code is None:
        print("[ERROR] Claude failed to generate hook code.")
        print("  Check: echo $ANTHROPIC_API_KEY")
        sys.exit(1)

    save_hook(hook_code)

    # ═══════════════════════════════════════════
    # PHASE 3: SELF-HEALING INJECTION
    # ═══════════════════════════════════════════
    print()
    print("=" * 55)
    print("  PHASE 3 — SELF-HEALING INJECTION")
    print("=" * 55)

    success, result = inject_with_healing(package, hook_code, config)

    if success and result:
        proc = result  # Popen process

        print()
        print("╔═════════════════════════════════════════════════════╗")
        print("║  HOOK IS ACTIVE                                    ║")
        print("║  Use the app on your device -- logs appear below   ║")
        print("║  Press Ctrl+C to stop                              ║")
        print("╚═════════════════════════════════════════════════════╝")
        print()

        try:
            # Stream stdout from the Frida process
            while True:
                line = proc.stdout.readline()
                if not line:
                    if proc.poll() is not None:
                        print("[*] Frida process exited")
                        break
                    continue
                line = line.strip()
                if line:
                    print(f"  [HOOK] {line}")
        except KeyboardInterrupt:
            print("\n[*] Stopping...")
            try:
                proc.kill()
                proc.wait(timeout=3)
            except Exception:
                pass
            print("[*] Done.")
    else:
        print()
        print("╔═════════════════════════════════════════════════════╗")
        print("║  INJECTION FAILED                                  ║")
        print("╚═════════════════════════════════════════════════════╝")

        if result and isinstance(result, list):
            error_path = "output/final_errors.json"
            os.makedirs("output", exist_ok=True)
            with open(error_path, "w") as f:
                json.dump(result, f, indent=2, ensure_ascii=False)
            print(f"  Errors saved to {error_path}")

        print("  Check output/ folder for debug files.")
        sys.exit(1)


if __name__ == "__main__":
    main()