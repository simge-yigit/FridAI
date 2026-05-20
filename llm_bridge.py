"""
Phase 2: LLM Bridge via Anthropic Claude API

Sends rich reconnaissance data to Claude Sonnet/Opus and receives
precisely crafted Frida hook scripts. Handles prompt engineering,
response cleaning, and fix requests for the self-healing loop.

Requires: pip install anthropic
Requires: ANTHROPIC_API_KEY environment variable
"""

import json
import os
import re

try:
    import anthropic
except ImportError:
    print("[LLM] ERROR: anthropic package not installed")
    print("  Run: pip install anthropic")
    raise


# ═══════════════════════════════════════════════════════════
#  CLAUDE API CORE
# ═══════════════════════════════════════════════════════════

# System prompt that stays constant across all requests
SYSTEM_PROMPT = """You are an elite Android security researcher and Frida instrumentation expert.
You write production-grade Frida hooks based on real runtime reconnaissance data.

STRICT RULES:
1. Return ONLY executable JavaScript code
2. Never use markdown formatting, backticks, or code fences
3. Never add explanations, comments about what you're doing, or preamble
4. All Java hooks go inside a single Java.perform(function(){ ... }) block
5. Each hook must be in its own try-catch block
6. Use exact class names and method signatures from the provided recon data
7. For overloaded methods, always use .overload() with exact parameter types
8. Add console.log("[HOOK]") for every hooked method
9. Never invent or guess class/method names that aren't in the recon data"""


def get_client():
    """Get Anthropic client, checking for API key."""
    api_key = os.environ.get("ANTHROPIC_API_KEY")

    if not api_key:
        print("[LLM] ERROR: ANTHROPIC_API_KEY environment variable not set")
        print("  Get your key from: https://console.anthropic.com/settings/keys")
        print("  Then run:")
        print('    export ANTHROPIC_API_KEY="sk-ant-..."')
        print("  Or add to ~/.bashrc for persistence")
        return None

    return anthropic.Anthropic(api_key=api_key)


def ask_claude(prompt, model="claude-sonnet-4-20250514", max_tokens=8192):
    """
    Send a prompt to Claude and return the response text.

    Args:
        prompt: The user prompt string
        model: Claude model to use
            - "claude-sonnet-4-20250514" (fast, great for code)
            - "claude-opus-4-20250514" (best quality, slower)
        max_tokens: Maximum response length

    Returns:
        Response text string, or None on failure
    """

    client = get_client()
    if client is None:
        return None

    try:
        message = client.messages.create(
            model=model,
            max_tokens=max_tokens,
            system=SYSTEM_PROMPT,
            messages=[
                {"role": "user", "content": prompt}
            ]
        )

        # Extract text from response
        text = ""
        for block in message.content:
            if block.type == "text":
                text += block.text

        # Log token usage
        usage = message.usage
        print(f"[LLM] Tokens — input: {usage.input_tokens}, output: {usage.output_tokens}")

        return text

    except anthropic.AuthenticationError:
        print("[LLM] ERROR: Invalid API key")
        print("  Check your ANTHROPIC_API_KEY")
        return None
    except anthropic.RateLimitError:
        print("[LLM] ERROR: Rate limit exceeded")
        print("  Wait a moment and try again")
        return None
    except anthropic.APIError as e:
        print(f"[LLM] API Error: {e}")
        return None
    except Exception as e:
        print(f"[LLM] Unexpected error: {e}")
        return None


# ═══════════════════════════════════════════════════════════
#  CODE CLEANING
# ═══════════════════════════════════════════════════════════

def clean_code(raw):
    """
    Extract clean JavaScript code from LLM response.
    Strips markdown fences, explanations, and preamble.
    """

    if raw is None:
        return None

    # Try to extract from markdown code block first
    pattern = r"```(?:javascript|js)?\s*\n(.*?)```"
    match = re.search(pattern, raw, re.DOTALL)
    if match:
        return match.group(1).strip()

    # Look for Java.perform as code start marker
    lines = raw.strip().split("\n")
    code_start = -1
    for i, line in enumerate(lines):
        if "Java.perform" in line or "Interceptor." in line:
            code_start = i
            break

    if code_start >= 0:
        code_lines = lines[code_start:]
        while code_lines and not code_lines[-1].strip():
            code_lines.pop()
        return "\n".join(code_lines).strip()

    # Fallback: return as-is
    return raw.strip()


# ═══════════════════════════════════════════════════════════
#  HOOK GENERATION FROM DEEP RECON
# ═══════════════════════════════════════════════════════════

def generate_hook_from_recon(recon_data, model="claude-sonnet-4-20250514"):
    """
    Generate a Frida hook script using rich recon data from deep_recon().

    Sends structured data to Claude: interface implementations, method
    signatures, library IDs, native exports, and network config.
    Claude writes precise hooks using exact class/method names.
    """

    from recon import format_for_llm

    task = recon_data.get("task", "ssl_pinning")
    formatted_data = format_for_llm(recon_data)

    has_native = bool(recon_data.get("native_modules"))

    native_instruction = ""
    if has_native:
        native_instruction = """
- NATIVE HOOKS: The recon found native SSL/crypto exports. Include Interceptor.attach
  hooks for the native functions listed under NATIVE MODULES. Log their arguments.
  Use Module.findExportByName() with the module name and export name from the recon data."""

    prompt = f"""Below is DETAILED reconnaissance data from a live Android application.
This includes exact interface implementations, full method signatures with parameter types,
identified libraries, native module exports, and network security configuration.

Use this data to write PRECISE Frida hooks. You have the exact class names, method names,
and parameter types — use them exactly as shown.

=== RECONNAISSANCE DATA ===

{formatted_data}

=== END RECON DATA ===

TASK: Write a comprehensive Frida hook script for: {task}

ADDITIONAL REQUIREMENTS:
- Use the EXACT class names and method signatures from the recon data
- For methods with overloads, use .overload() with the exact parameter types shown
- Wrap each hook in its own try-catch so one failure doesn't break others
- Log intercepted data: certificate info for SSL, return values for root detection, key material for crypto
- Do NOT invent or guess — only hook what the recon data shows{native_instruction}

Write the hook code now:"""

    print(f"[LLM] Generating hook via Claude ({model})...")
    print(f"[LLM] Task: {task}")
    print(f"[LLM] Recon: {len(recon_data.get('interface_implementations', []))} interfaces, "
          f"{len(recon_data.get('library_fingerprints', []))} libraries, "
          f"{len(recon_data.get('native_modules', []))} native modules")

    raw_response = ask_claude(prompt, model=model)

    if raw_response is None:
        return None

    code = clean_code(raw_response)

    if code and ("Java.perform" in code or "Interceptor" in code):
        print(f"[LLM] Code generated successfully ({len(code)} chars)")
        return code
    else:
        print("[LLM] WARNING: Generated code may be invalid")
        if raw_response:
            print(f"[LLM] Raw response preview: {raw_response[:300]}...")
        return code


# ═══════════════════════════════════════════════════════════
#  SELF-HEALING: FIX REQUEST
# ═══════════════════════════════════════════════════════════

def request_fix(broken_code, error_message, model="claude-sonnet-4-20250514"):
    """
    Send broken code + error to Claude for correction.
    """

    prompt = f"""The following Frida JavaScript code produced an error when injected into an Android app.

BROKEN CODE:
{broken_code}

ERROR MESSAGE:
{error_message}

Analyze the error, fix the code, and return ONLY the corrected JavaScript code.
Do not add any explanation."""

    print("[LLM] Requesting fix from Claude...")
    raw = ask_claude(prompt, model=model)
    fixed = clean_code(raw)

    if fixed:
        print(f"[LLM] Fix received ({len(fixed)} chars)")
    else:
        print("[LLM] Failed to get a fix")

    return fixed


# ═══════════════════════════════════════════════════════════
#  UTILITIES
# ═══════════════════════════════════════════════════════════

def save_hook(code, output_path="output/generated_hook.js"):
    """Save generated hook code to file for debugging."""
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    with open(output_path, "w") as f:
        f.write(code)

    print(f"[LLM] Hook code saved to {output_path}")
