"""Load and validate the TOML config. Secrets come from environment variables, never the file."""
import os
import re
import tomllib
import urllib.parse

ENV_RE = re.compile(r"\$\{([A-Za-z0-9_]+)\}")
PRODUCTION_NAMES = {"prod", "production", "live", "prd"}
LAYERS = ("data", "processing", "model_state", "logs")
SOURCE_TYPES = ("path", "command", "http")
PROBES = ("context_window", "rate_limit", "content_policy")


class ConfigError(Exception):
    pass


def expand_env(value):
    """Replace ${VAR} with the environment value. Missing variables are an error, not an empty string."""
    if isinstance(value, str):
        def repl(m):
            name = m.group(1)
            if name not in os.environ:
                raise ConfigError(f"environment variable {name} is referenced in the config but not set")
            return os.environ[name]
        return ENV_RE.sub(repl, value)
    if isinstance(value, dict):
        return {k: expand_env(v) for k, v in value.items()}
    if isinstance(value, list):
        return [expand_env(v) for v in value]
    return value


def require_env(command):
    """Check that every ${VAR} in a shell command is set, without substituting it.

    Commands are left for the shell to expand, so a secret never becomes part of the command
    string (where shell metacharacters in it could change the command).
    """
    for name in ENV_RE.findall(command):
        if name not in os.environ:
            raise ConfigError(f"environment variable {name} is referenced in the config but not set")
    return command


def _plaintext_with_credentials(url, headers):
    """True for http:// URLs that would carry headers over the network unencrypted."""
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != "http" or not headers:
        return False
    return parts.hostname not in ("localhost", "127.0.0.1", "::1")


def load(path, allow_production=False):
    with open(path, "rb") as f:
        cfg = tomllib.load(f)

    env = str(cfg.get("environment", "")).strip()
    if not env:
        raise ConfigError("set `environment` (for example \"staging\") at the top of the config")
    if env.lower() in PRODUCTION_NAMES and not allow_production:
        raise ConfigError(
            f"environment is '{env}'. canarykit refuses to run against production unless you pass "
            "--i-understand-this-is-production. Run it in staging first."
        )

    border = cfg.get("border") or {}
    if not border.get("allowed_locations"):
        raise ConfigError("set [border] allowed_locations, for example [\"DE\"]")

    target = cfg.get("target") or {}
    for key in ("url", "body", "prompt"):
        if key not in target:
            raise ConfigError(f"[target] is missing `{key}`")

    for i, src in enumerate(cfg.get("sources", [])):
        label = src.get("name", f"source #{i + 1}")
        if src.get("type") not in SOURCE_TYPES:
            raise ConfigError(f"source '{label}': type must be one of {SOURCE_TYPES}")
        if src.get("layer") not in LAYERS:
            raise ConfigError(f"source '{label}': layer must be one of {LAYERS}")
        if not src.get("location"):
            raise ConfigError(f"source '{label}': set `location` (for example \"DE\" or \"US\")")
        urls = [src.get("url")] if isinstance(src.get("url"), str) else src.get("url") or []
        if any(_plaintext_with_credentials(u, src.get("headers")) for u in urls) and not cfg.get("allow_plaintext_http"):
            raise ConfigError(f"source '{label}': headers would be sent over plain http. Use https, an "
                              "SSH tunnel to localhost, or set allow_plaintext_http = true")

    if _plaintext_with_credentials(target["url"], target.get("headers")) and not cfg.get("allow_plaintext_http"):
        raise ConfigError("[target] headers would be sent over plain http. Use https, an SSH tunnel to "
                          "localhost, or set allow_plaintext_http = true")

    probes = cfg.get("probes") or {}
    for name, probe in probes.items():
        if name not in PROBES:
            raise ConfigError(f"[probes.{name}]: unknown probe. Use context_window, rate_limit or content_policy")
        if name == "content_policy" and not probe.get("prompt"):
            raise ConfigError("[probes.content_policy] needs a `prompt` your local model or guardrail rejects")
        if not 1 <= int(probe.get("concurrency", 1)) <= 64:
            raise ConfigError(f"[probes.{name}] concurrency must be between 1 and 64")
    cfg["probes"] = probes

    cfg.setdefault("output_dir", "runs")
    cfg.setdefault("requests_per_phase", 20)
    cfg.setdefault("request_id_header", "X-Canary-Request-Id")
    cfg.setdefault("watch_destinations", DEFAULT_WATCH)
    return cfg


# Public model API hostnames to look for in egress evidence. Extend for your providers.
DEFAULT_WATCH = [
    "api.openai.com",
    "*.openai.azure.com",
    "api.anthropic.com",
    "generativelanguage.googleapis.com",
    "*-aiplatform.googleapis.com",
    "bedrock-runtime.*.amazonaws.com",
    "api.mistral.ai",
    "api.cohere.com",
    "api.together.xyz",
    "api.groq.com",
    "api.deepseek.com",
    "openrouter.ai",
    "*.services.ai.azure.com",
    "*.cognitiveservices.azure.com",
    "aiplatform.googleapis.com",
    "api.x.ai",
    "api.fireworks.ai",
]
