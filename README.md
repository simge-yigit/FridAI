# FridAI

AI-powered Android security automation tool. Combines [Frida](https://frida.re/) dynamic instrumentation with the [Claude LLM](https://www.anthropic.com/) to autonomously discover and bypass SSL certificate pinning in Android applications.

> **Intended use:** authorized security testing, penetration testing engagements, and security research on applications you own or have explicit permission to test.

## How It Works

FridAI runs a three-phase pipeline:

```
Phase 1: RECON            Phase 2: LLM               Phase 3: INJECT
┌────────────────┐        ┌────────────────┐         ┌────────────────┐
│  5-Layer Deep  │   ->   │  Claude API    │   ->    │  Self-Healing  │
│  Enumeration   │        │  Hook Gen      │         │  Injection     │
└────────────────┘        └────────────────┘         └────────────────┘
  Frida CLI                 Anthropic API              Auto-retry +
  subprocess                Sonnet 4                   LLM error fix
```

### Phase 1 -- Deep Recon

Spawns the target app and runs 5 discovery layers in a single Frida session:

| Layer | What it does | Why it matters |
|-------|-------------|----------------|
| 1 | Interface & superclass discovery | Finds TrustManager/HostnameVerifier implementations even when obfuscated |
| 2 | Method signature analysis | Gives LLM exact param types for precise hook overloads |
| 3 | Known library fingerprinting | Detects OkHttp, TrustKit, Conscrypt, Cronet by method patterns |
| 4 | Native module scanning | Finds libssl.so, libcrypto.so exports for native pinning |
| 5 | Network security config (static) | Parses binary AXML pin-set configurations from the APK |

Layers 1--4 run inside a single Frida session (one app spawn) to avoid triggering anti-frida heuristics in hardened apps. Layer 5 is pure static APK analysis via `adb` + `pyaxmlparser` and requires no Frida session.

### Phase 2 -- LLM Hook Generation

Sends the structured recon data to Claude, which writes targeted Frida JavaScript hooks using the exact class names, method signatures, and overload parameters discovered in Phase 1.

### Phase 3 -- Self-Healing Injection

Injects the generated hooks into the running app. If runtime errors occur, it captures the error message, sends it back to Claude for correction, and retries automatically (up to N times, configurable via `max_retries`).

## Project Structure

```
FridAI/
  hunter.py           # Main entry point -- orchestrates all 3 phases
  recon.py            # Phase 1: 5-layer deep reconnaissance engine
  llm_bridge.py       # Phase 2: Claude API integration + prompt engineering
  injector.py         # Phase 3: Self-healing injection with auto-retry
  frida_runner.py     # Subprocess-based Frida execution engine
  config.example.json # Template configuration
  requirements.txt    # Runtime dependencies
  requirements-dev.txt# Dev/test dependencies
  tests/              # Pytest unit tests
```

## Prerequisites

- **Python 3.10+**
- **Rooted Android device** (or emulator) with USB debugging enabled
- **Frida server** running on the device (`frida-server` binary matching your device architecture)
- **ADB** configured and the device visible via `adb devices`
- **Anthropic API key** for the full pipeline (recon-only mode works without one)

> **Important:** The `frida` Python package version must match the `frida-server` version on your device exactly. Verify with `frida --version` (host) vs `frida-server --version` (device).

## Setup

```bash
git clone https://github.com/simge-yigit/FridAI.git
cd FridAI

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

cp config.example.json config.json
# Edit config.json with your target package name
```

## Usage

### Recon only (no API key needed)

```bash
python3 hunter.py -p com.target.app --task ssl_pinning --recon-only --skip-checks
```

Results are saved to `output/recon_results.json`.

### Full pipeline (recon -> hook generation -> injection)

```bash
export ANTHROPIC_API_KEY="sk-ant-..."
python3 hunter.py -p com.target.app --task ssl_pinning
```

Once the hook is active, use the app on your device -- intercepted traffic and hook logs appear in the terminal. Press `Ctrl+C` to stop.

### CLI flags

| Flag | Description |
|------|-------------|
| `-p`, `--package` | Target Android package name |
| `-t`, `--task` | Analysis task (currently: `ssl_pinning`) |
| `-c`, `--config` | Path to config file (default: `config.json`) |
| `--skip-checks` | Skip preflight checks (Frida, ADB, API key) |
| `--recon-only` | Run only the recon phase, skip LLM and injection |
| `--legacy-recon` | Run each recon layer in a separate Frida session (old behavior, useful for debugging) |

### Configuration

Edit `config.json` (copied from `config.example.json`):

```json
{
    "target_package": "com.example.app",
    "task": "ssl_pinning",
    "model": "claude-sonnet-4-20250514",
    "max_retries": 3,
    "recon_timeout": 30,
    "inject_wait": 5
}
```

| Key | Description |
|-----|-------------|
| `target_package` | Android package to target |
| `task` | Analysis task |
| `model` | Claude model to use (`claude-sonnet-4-20250514` or `claude-opus-4-20250514`) |
| `max_retries` | Max self-healing retry attempts |
| `recon_timeout` | Base timeout (seconds) for each recon layer |
| `inject_wait` | Seconds to wait after injection before checking for errors |

## Testing

```bash
pip install -r requirements-dev.txt
pytest tests/ -v
```

Tests cover the pure-logic functions (no device needed): LLM response cleaning, recon data formatting, injection log parsing, and the AXML network security config parser.

## License

[MIT](LICENSE)
