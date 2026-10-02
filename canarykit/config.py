"""Load and validate the TOML config. Secrets come from environment variables, never the file."""
import os
import re
import tomllib

ENV_RE = re.compile(r"\$\{([A-Za-z0-9_]+)\}")
PRODUCTION_NAMES = {"prod", "production", "live", "prd"}
LAYERS = ("data", "processing", "model_state", "logs")
SOURCE_TYPES = ("path", "command", "http")


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
]
