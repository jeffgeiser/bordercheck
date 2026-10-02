"""Generate a synthetic customer with unique canary values, and the byte patterns used to find them."""
import base64
import secrets

# No 0/O, 1/I/L, U: easy to read aloud and unlikely to collide with real identifiers.
ALPHABET = "ABCDEFGHJKMNPQRSTVWXYZ23456789"

FIRST = ["Anna", "Lena", "Miriam", "Jonas", "Felix", "Clara", "Tobias", "Nora", "Elias", "Ida"]
LAST = ["Brandvoll", "Kestermann", "Ulbrecht", "Saalfeld", "Wendrich", "Morhaupt", "Treskow", "Ilgner"]
CITIES = ["Munich", "Frankfurt", "Hamburg", "Cologne", "Stuttgart"]
ROLES = ["data protection officer", "treasury analyst", "branch manager", "software engineer"]


def _code(n):
    return "".join(secrets.choice(ALPHABET) for _ in range(n))


def new_record():
    """A synthetic customer. Nothing here is real; the canary and account number exist nowhere else."""
    return {
        "synthetic": True,
        "name": f"{secrets.choice(FIRST)} {secrets.choice(LAST)}",
        "role": secrets.choice(ROLES),
        "city": secrets.choice(CITIES),
        "product": "mortgage application",
        "amount": "EUR 650,000",
        "canary": f"CNRY-{_code(4)}-{_code(4)}",
        # Digits only, so you can test whether numeric identifiers get redacted too.
        "account": "99" + "".join(secrets.choice("0123456789") for _ in range(12)),
    }


def _base64_cores(token):
    """Base64 fragments that appear whenever `token` is base64-encoded inside a larger value.

    Base64 works in 3-byte groups, so the encoding of a substring depends on where it starts.
    For each of the three alignments, encode only the groups made entirely of token bytes.
    """
    out = []
    for offset in range(3):
        skip = (3 - offset) % 3
        core = token[skip:]
        core = core[: len(core) // 3 * 3]
        if len(core) >= 6:
            enc = base64.b64encode(core)
            out.append(enc)
            url = enc.replace(b"+", b"-").replace(b"/", b"_")
            if url != enc:
                out.append(url)
    return out


def needles(record, run_id):
    """(kind, label, bytes) patterns to search for. Kinds: canary, account, run_id."""
    canary = record["canary"].encode()
    account = record["account"].encode()
    spaced = b" ".join(account[i:i + 4] for i in range(0, len(account), 4))
    result = [
        ("canary", "canary", canary),
        ("canary", "canary (lowercase)", canary.lower()),
        ("account", "account number", account),
        ("account", "account number (spaced)", spaced),
        ("run_id", "harness request id", run_id.encode()),
    ]
    for i, core in enumerate(_base64_cores(canary)):
        result.append(("canary", f"canary (base64 #{i + 1})", core))
    return result
