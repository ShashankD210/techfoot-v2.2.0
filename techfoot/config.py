"""
Configuration resolution for techfoot — currently just the NVD API key.

IMPORTANT: an NVD API key is not something that can be "randomly generated"
by this tool. It's issued by NIST after you register at
https://nvd.nist.gov/developers/request-an-api-key and is validated
server-side on every request — a locally-generated random string will
simply be rejected (or silently ignored, falling back to the slower
unauthenticated rate limit). What this module *does* provide:

  - A resolution order so you don't have to pass --nvd-api-key on every
    invocation: CLI flag > TECHFOOT_NVD_API_KEY env var > NVD_API_KEY env
    var > a .env file (cwd, then this package's directory).
  - `generate_placeholder_key()`, which produces a random, correctly
    *formatted* (UUIDv4, matching NVD's real key format) example value —
    for populating .env.example so you can see the expected shape before
    swapping in your real key. It is never used as an actual credential.
"""

import os
import uuid


ENV_VAR_NAMES = ("TECHFOOT_NVD_API_KEY", "NVD_API_KEY")


def generate_placeholder_key():
    """Random UUIDv4 string in the same format NVD issues real keys in.
    Cosmetic/example use only — see module docstring."""
    return str(uuid.uuid4())


def _load_dotenv(path):
    """Minimal .env parser (KEY=VALUE per line, '#' comments, optional
    quotes) — no third-party `python-dotenv` dependency."""
    values = {}
    if not os.path.isfile(path):
        return values
    try:
        with open(path, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, val = line.partition("=")
                key = key.strip()
                val = val.strip().strip('"').strip("'")
                if key:
                    values[key] = val
    except OSError:
        pass
    return values


def resolve_nvd_api_key(cli_value=None, search_dirs=None):
    """
    Resolution order:
      1. `cli_value` (i.e. --nvd-api-key on the command line), if given.
      2. TECHFOOT_NVD_API_KEY or NVD_API_KEY environment variables.
      3. A `.env` file, checked in each of `search_dirs` in order
         (defaults to [cwd, this package's parent directory]).
    Returns None if no key is found anywhere (the tool still works
    without one — just at NVD's slower unauthenticated rate limit).
    """
    if cli_value:
        return cli_value

    for name in ENV_VAR_NAMES:
        val = os.environ.get(name)
        if val:
            return val

    if search_dirs is None:
        here = os.path.dirname(os.path.abspath(__file__))
        search_dirs = [os.getcwd(), os.path.dirname(here)]

    for d in search_dirs:
        dotenv = _load_dotenv(os.path.join(d, ".env"))
        for name in ENV_VAR_NAMES:
            if dotenv.get(name):
                return dotenv[name]

    return None
