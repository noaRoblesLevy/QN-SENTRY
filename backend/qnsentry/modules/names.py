"""Names as parts of an email address (data contract 10.4.2 and 10.4.3).

One place for both the Metadata module (#8), which detects the convention from the
published addresses, and the Breach module (#12), which applies it to names without a
published address, so detecting and applying a convention can never disagree.
"""

import unicodedata

# The values of ScanContext.email_convention, data contract 10.4.2
CONVENTIONS = ("first.last", "firstlast", "flast", "f.last", "first_last", "last.first", "first")

# How a last name of several words is written (ScanContext.last_name_style)
JOINED = "joined"  # lotte.vandenbroeck@
SEPARATED = "separated"  # lotte.van.den.broeck@

# Letters that Unicode NFKD does not split into a base letter and an accent
SPECIAL_LETTERS = str.maketrans({"ß": "ss", "æ": "ae", "ø": "o", "ł": "l", "đ": "d", "œ": "oe", "þ": "th"})
APOSTROPHES = "'’`´"


def normalise_word(word: str) -> str:
    """One word of a name as it appears in an address: "Gérard" -> "gerard", "D'Hondt" -> "dhondt"."""
    word = word.lower().translate(SPECIAL_LETTERS)
    word = "".join(c for c in unicodedata.normalize("NFKD", word) if not unicodedata.combining(c))
    word = "".join(c for c in word if c not in APOSTROPHES)
    # Keep letters, digits and hyphens ("dierckx-gerard"); anything else cannot be in an address
    return "".join(c for c in word if c.isascii() and (c.isalnum() or c == "-")).strip("-")


def split_name(name: str) -> tuple[str, list[str]] | None:
    """("first name", [words of the last name]), or None when there is no first and last name.

    The first word is the first name and the rest the last name: a heuristic, since
    "Anne Marie Peeters" could also have "Anne Marie" as first name (contract 10.4.3).
    """
    words = [w for w in (normalise_word(part) for part in name.split()) if w]
    if len(words) < 2:
        return None
    return words[0], words[1:]


def separator(convention: str) -> str:
    return "_" if "_" in convention else "." if "." in convention else ""


def local_part(name: str, convention: str, last_name_style: str = JOINED) -> str | None:
    """The part before the @ for `name` in `convention`, or None when the name is not usable.

    local_part("Lotte Van den Broeck", "first.last")             -> "lotte.vandenbroeck"
    local_part("Lotte Van den Broeck", "first.last", SEPARATED)  -> "lotte.van.den.broeck"
    """
    if convention not in CONVENTIONS:
        raise ValueError(f"Unknown email convention {convention!r}")
    parts = split_name(name)
    if parts is None:
        return None
    first, last_words = parts
    sep = separator(convention)
    last = sep.join(last_words) if last_name_style == SEPARATED else "".join(last_words)
    return {
        "first.last": f"{first}.{last}",
        "firstlast": f"{first}{last}",
        "flast": f"{first[0]}{last}",
        "f.last": f"{first[0]}.{last}",
        "first_last": f"{first}_{last}",
        "last.first": f"{last}.{first}",
        "first": first,
    }[convention]
