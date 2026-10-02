"""Generate a synthetic customer with unique canary values, and the byte patterns used to find them.

Besides the canary and account number, the customer has an email, phone number and IBAN in real
formats, so a run shows which formats your redaction catches. Each one is reserved or impossible:

- email at example.com, reserved by RFC 2606. (Not .invalid: Presidio's email check needs a real
  public suffix, so it would never be flagged and the test would say nothing.)
- phone in 069 90009-000..999, which the Bundesnetzagentur keeps unassigned for media use.
- IBAN with a valid checksum but a bank code starting with 9. German bank codes start with the
  clearing-area digit 1 to 8, so it can't belong to a real account.
"""
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


def _digits(n):
    return "".join(secrets.choice("0123456789") for _ in range(n))


def iban_de(bban):
    """German IBAN for an 18-digit BBAN, with the ISO 13616 mod-97 check digits."""
    check = 98 - int(bban + "131400") % 97   # "DE" -> 1314, then "00"
    return f"DE{check:02d}{bban}"


def new_record():
    """A synthetic customer. Nothing here is real; the canary and account number exist nowhere else."""
    first, last = secrets.choice(FIRST), secrets.choice(LAST)
    canary = f"CNRY-{_code(4)}-{_code(4)}"
    return {
        "synthetic": True,
        "name": f"{first} {last}",
        "role": secrets.choice(ROLES),
        "city": secrets.choice(CITIES),
        "product": "mortgage application",
        "amount": "EUR 650,000",
        "canary": canary,
        # Digits only, so you can test whether numeric identifiers get redacted too.
        "account": "99" + _digits(12),
        # The canary's code in the mailbox keeps the address unique to this run.
        "email": f"{first.lower()}.{last.lower()}.{canary[5:].replace('-', '').lower()}@example.com",
        "phone": "+49 69 90009" + _digits(3),
        "iban": iban_de("9" + _digits(17)),
    }


# Identifier kinds that count as "the customer's data" in a hit. run_id is the harness's own.
IDENTIFIER_KINDS = ("canary", "account", "email", "phone", "iban")


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


def _groups(value, n=4):
    return b" ".join(value[i:i + n] for i in range(0, len(value), n))


def needles(record, run_id):
    """(kind, label, bytes) patterns to search for. Kinds: IDENTIFIER_KINDS and run_id."""
    canary = record["canary"].encode()
    account = record["account"].encode()
    result = [
        ("canary", "canary", canary),
        ("canary", "canary (lowercase)", canary.lower()),
        ("account", "account number", account),
        ("account", "account number (spaced)", _groups(account)),
        ("run_id", "harness request id", run_id.encode()),
    ]
    # Runs from before these fields existed don't have them.
    if "email" in record:
        email = record["email"].encode()
        local, domain = email.split(b"@")
        phone = record["phone"].replace(" ", "").encode()      # +496990009123
        iban = record["iban"].encode()
        result += [
            ("email", "email", email),
            ("email", "email (URL-encoded)", local + b"%40" + domain),
            ("phone", "phone (international)", phone),
            ("phone", "phone (as written)", record["phone"].encode()),
            ("phone", "phone (national)", b"0" + phone[3:]),
            ("phone", "phone (national, spaced)", b"069 " + phone[5:]),
            ("iban", "IBAN", iban),
            ("iban", "IBAN (grouped)", _groups(iban)),
        ]
    for i, core in enumerate(_base64_cores(canary)):
        result.append(("canary", f"canary (base64 #{i + 1})", core))
    return result
