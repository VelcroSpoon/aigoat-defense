"""Undo the cheap tricks attackers use to hide an instruction from a scanner.

Every transform that fires is reported back: hiding text is itself a signal,
because honest product documentation has no reason to use zero-width
characters, Cyrillic look-alikes or base64 blobs.
"""
from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from dataclasses import dataclass, field

_INVISIBLE = re.compile(r"[­᠎​-‏‪-‮⁠-⁤﻿]")

# Cyrillic and Greek letters that render like Latin ones.
_HOMOGLYPHS = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "һ": "h", "ӏ": "l", "ԛ": "q", "ԝ": "w",
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O",
    "Р": "P", "С": "C", "Т": "T", "Х": "X", "У": "Y", "І": "I", "Ј": "J", "Ѕ": "S",
    "α": "a", "ε": "e", "ο": "o", "ρ": "p", "ι": "i", "κ": "k", "ν": "v", "τ": "t",
    "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I", "Κ": "K",
    "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T", "Χ": "X", "Υ": "Y",
})

_LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t"})
# A swapped digit sits between letters or leads into one ("n0te", "1gnore"), unlike
# sizes, prices and codes ("free100", "24/7").
_LEET_WORD = re.compile(r"\b(?:[a-z]*[013457]+[a-z][a-z013457]*|[a-z][013457])\b")

# "i g n o r e" or "i.g.n.o.r.e": four or more single letters split by one separator.
_SPACED = re.compile(r"\b(?:[a-z][ .\-_]){3,}[a-z]\b")

_BASE64 = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")


@dataclass
class Normalized:
    original: str
    text: str
    transforms: list[str] = field(default_factory=list)
    decoded: list[str] = field(default_factory=list)


def _strip_accents(text: str) -> str:
    decomposed = unicodedata.normalize("NFKD", text)
    return "".join(ch for ch in decomposed if not unicodedata.combining(ch))


def _decode_base64(text: str) -> list[str]:
    found: list[str] = []
    for blob in _BASE64.findall(text):
        try:
            raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True)
            decoded = raw.decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        letters = sum(ch.isalpha() or ch.isspace() for ch in decoded)
        if len(decoded) >= 12 and letters / len(decoded) > 0.8:
            found.append(decoded)
    return found


def normalize(text: str) -> Normalized:
    """Return a lowercase, accent-free, de-obfuscated copy for matching.

    The original text is never changed; this copy only feeds the detectors.
    """
    original = text or ""
    transforms: list[str] = []

    work = unicodedata.normalize("NFKC", original)
    if work != unicodedata.normalize("NFC", original):
        transforms.append("compatibility characters")

    stripped = _INVISIBLE.sub("", work)
    if stripped != work:
        transforms.append("invisible characters")
    work = stripped

    swapped = work.translate(_HOMOGLYPHS)
    if swapped != work:
        transforms.append("look-alike letters")
    work = swapped

    decoded = _decode_base64(work)
    if decoded:
        transforms.append("base64 payload")
        work = work + "\n" + "\n".join(decoded)

    work = _strip_accents(work).lower()

    def _join_spaced(match: re.Match[str]) -> str:
        return re.sub(r"[ .\-_]", "", match.group(0))

    joined = _SPACED.sub(_join_spaced, work)
    if joined != work:
        transforms.append("spaced-out letters")
    work = joined

    def _unleet(match: re.Match[str]) -> str:
        return match.group(0).translate(_LEET)

    unleeted = _LEET_WORD.sub(_unleet, work)
    if unleeted != work:
        transforms.append("digit-for-letter swaps")
    work = unleeted

    work = re.sub(r"\s+", " ", work).strip()
    return Normalized(original=original, text=work, transforms=transforms, decoded=decoded)
