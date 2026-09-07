"""TALOS — EXTRA UTILITY MODULES (31-35).

31 ROT13 / Caesar cipher tool
32 base converter (between number bases)
33 Lorem Ipsum generator
34 timestamp converter
35 color code converter (HEX/RGB/HSL)
"""
from __future__ import annotations

import secrets
import string
import sys
from datetime import datetime, timezone
from typing import Optional, Tuple

from src.core.context import Session
from src.core.table import print_table

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def _ask(prompt: str, default: Optional[str] = None) -> str:
    suffix = f" [{default}]" if default is not None else ""
    try:
        return input(f"  {prompt}{suffix}: ").strip() or (default or "")
    except EOFError:
        return default or ""


# ---------------------------------------------------------------------------
# [31] ROT13 / Caesar Cipher
# ---------------------------------------------------------------------------
def rot13_cipher(session: Session) -> None:
    """Encode/decode text with ROT13 or a custom Caesar shift.

    ROT13 shifts each letter by 13 positions in the alphabet. It's its
    own inverse: applying ROT13 twice returns the original text. Caesar
    cipher uses a configurable shift (1-25). Non-alphabetic characters
    (spaces, numbers, punctuation) are left unchanged.

    Examples:
      ROT13: 'Hello' -> 'Uryyb', 'Uryyb' -> 'Hello'
      Caesar shift 3: 'Hello' -> 'Khoor', 'Khoor' -> 'Hello'
    """
    print("  Classic letter-substitution cipher.")
    print("  ROT13: shifts every letter by 13 (its own inverse).")
    print("  Caesar: shifts every letter by a custom amount (1-25).")
    print("  Non-letters (spaces, digits, punctuation) are unchanged.")
    print()
    print("  Examples:")
    print("    ROT13:   'Hello World'  ->  'Uryyb Jbeyq'")
    print("    Caesar3: 'Hello World'  ->  'Khoor Zruog'")
    print()
    text = _ask("Text to encode/decode")
    if not text:
        print("[ERROR] No input given; aborting.")
        return

    print()
    print("  rot13 = fixed shift of 13 (most common, self-inverting)")
    print("  caesar = custom shift between 1 and 25")
    mode = _ask("Mode", "rot13").lower()
    if mode == "rot13":
        shift = 13
    elif mode == "caesar":
        print()
        print("  How many positions to shift each letter (1-25).")
        print("  Common choices: 3 (classic Caesar), 13 (ROT13), 7, etc.")
        shift_str = _ask("Shift value (1-25)", "3")
        try:
            shift = int(shift_str) % 26
        except ValueError:
            shift = 3
    else:
        print("[ERROR] Mode must be 'rot13' or 'caesar'.")
        return

    result = []
    for ch in text:
        if ch.isalpha():
            base = ord("A") if ch.isupper() else ord("a")
            result.append(chr((ord(ch) - base + shift) % 26 + base))
        else:
            result.append(ch)
    encoded = "".join(result)

    # Also provide the decode
    decode_shift = 26 - shift
    decoded = []
    for ch in encoded:
        if ch.isalpha():
            base = ord("A") if ch.isupper() else ord("a")
            decoded.append(chr((ord(ch) - base + decode_shift) % 26 + base))
        else:
            decoded.append(ch)
    decoded = "".join(decoded)

    rows = [
        ("input", text),
        ("mode", f"{mode} (shift={shift})"),
        ("encoded", encoded),
        ("decoded", decoded),
    ]
    print()
    print_table(["field", "value"], rows)
    print(f"\n[INFO] Encoding reverses with the same shift ({26 - shift} for decoding).")
    session.set_result("cipher", {"input": text, "shift": shift, "encoded": encoded, "decoded": decoded})


# ---------------------------------------------------------------------------
# [32] Base Converter
# ---------------------------------------------------------------------------
def base_converter(session: Session) -> None:
    """Convert a number between binary, octal, decimal, hex, and arbitrary bases (2-36).

    Supports any base from 2 to 36. Common bases:
      2  = binary  (digits: 0-1)       — used in computing, networking
      8  = octal   (digits: 0-7)       — Unix file permissions
      10 = decimal (digits: 0-9)       — everyday numbers
      16 = hex     (digits: 0-9, a-f)  — memory addresses, colors, hashes
      36 = max     (digits: 0-9, a-z)  — compact representations

    Examples:
      255 (base 10) -> ff (base 16)
      1010 (base 2) -> 10 (base 10)
      777 (base 8) -> 1ff (base 16)
    """
    print("  Converts a number from one base to another (base 2-36).")
    print("  Common bases: 2=binary, 8=octal, 10=decimal, 16=hex")
    print()
    print("  Examples:")
    print("    255 (base 10) -> ff (base 16)")
    print("    1010 (base 2) -> 10 (base 10)")
    print("    777 (base 8)  -> 1ff (base 16)")
    print()
    value = _ask("Number to convert (use a-z for digits > 9 in high bases)")
    if not value:
        print("[ERROR] No number given; aborting.")
        return
    print()
    print("  The base the number is currently in (e.g. 10 for decimal, 16 for hex).")
    from_base_str = _ask("Source base (2-36)", "10")
    print()
    print("  The base you want to convert to (e.g. 2 for binary, 16 for hex).")
    to_base_str = _ask("Target base (2-36)", "16")
    try:
        from_base = int(from_base_str)
        to_base = int(to_base_str)
    except ValueError:
        print("[ERROR] Bases must be integers.")
        return
    if not (2 <= from_base <= 36 and 2 <= to_base <= 36):
        print("[ERROR] Bases must be between 2 and 36.")
        return

    try:
        decimal_value = int(value, from_base)
    except ValueError:
        print(f"[ERROR] '{value}' is not a valid number in base {from_base}.")
        print(f"[INFO] For base {from_base}, valid digits are: ", end="")
        if from_base <= 10:
            print(f"0-{from_base - 1}")
        else:
            print(f"0-9, a-{chr(ord('a') + from_base - 11)}")
        return

    if decimal_value < 0:
        negative = True
        decimal_value = -decimal_value
    else:
        negative = False

    if decimal_value == 0:
        converted = "0"
    else:
        digits = []
        n = decimal_value
        while n > 0:
            n, remainder = divmod(n, to_base)
            digits.append(string.digits[remainder] if remainder < 10 else chr(ord("a") + remainder - 10))
        converted = "".join(reversed(digits))
    if negative:
        converted = "-" + converted

    rows = [
        ("input", value),
        ("source base", f"{from_base} ({_base_name(from_base)})"),
        ("target base", f"{to_base} ({_base_name(to_base)})"),
        ("decimal equivalent", str(decimal_value if not negative else -decimal_value)),
        ("converted result", converted),
    ]
    print()
    print_table(["field", "value"], rows)
    session.set_result("base_convert", {"input": value, "from": from_base, "to": to_base, "result": converted})


def _base_name(base: int) -> str:
    names = {2: "binary", 8: "octal", 10: "decimal", 16: "hexadecimal"}
    return names.get(base, f"base-{base}")


# ---------------------------------------------------------------------------
# [33] Lorem Ipsum Generator
# ---------------------------------------------------------------------------
_LOREM_WORDS = (
    "lorem ipsum dolor sit amet consectetur adipiscing elit sed do eiusmod tempor"
    " incididunt ut labore et dolore magna aliqua ut enim ad minim veniam quis"
    " nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat"
    " duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore"
    " eu fugiat nulla pariatur excepteur sint occaecat cupidatat non proident sunt"
    " in culpa qui officia deserunt mollit anim id est laborum"
).split()


def lorem_generator(session: Session) -> None:
    """Generate Lorem Ipsum placeholder text.

    Lorem Ipsum is standard placeholder text used in design and publishing.
    It looks like real English but is intentionally nonsensical, so it
    doesn't distract from the visual layout. Each sentence has 8-16 words.
    """
    print("  Generates placeholder text for design mockups and layouts.")
    print("  Standard 'Lorem Ipsum' text that looks like real English.")
    print("  Each sentence contains 8-16 words.")
    print()
    print("  Common amounts:")
    print("    1-3 sentences  — short label or button placeholder")
    print("    5-10 sentences — paragraph placeholder")
    print("    20-50 sentences — full page of placeholder text")
    count_str = _ask("Number of sentences to generate (1-50)", "5")
    try:
        count = max(1, min(50, int(count_str)))
    except ValueError:
        count = 5

    result_parts: List[str] = []
    for _ in range(count):
        # Generate 8-16 words per sentence
        word_count = secrets.randbelow(9) + 8
        words = [secrets.choice(_LOREM_WORDS) for _ in range(word_count)]
        words[0] = words[0].capitalize()
        sentence = " ".join(words) + "."
        result_parts.append(sentence)

    text = " ".join(result_parts)
    total_words = len(text.split())
    print(f"\n  Generated text ({total_words} words, {count} sentences):")
    print("  " + "-" * 60)
    # Word-wrap at ~72 chars
    line = "  "
    for word in text.split():
        if len(line) + len(word) + 1 > 74:
            print(line)
            line = "  " + word
        else:
            line += " " + word if line.strip() else "  " + word
    if line.strip():
        print(line)
    print("  " + "-" * 60)
    print()

    session.set_result("lorem", {"sentences": count, "words": total_words, "text": text})
    print(f"[INFO] Generated {total_words} words in {count} sentences. Stored as 'lorem' in session.")


# ---------------------------------------------------------------------------
# [34] Timestamp Converter
# ---------------------------------------------------------------------------
def timestamp_converter(session: Session) -> None:
    """Convert between Unix timestamps and human-readable date strings.

    Unix timestamps are the number of seconds (or milliseconds) since
    Jan 1, 1970 00:00:00 UTC. They're used everywhere in computing:
    logs, databases, APIs, file systems, etc.

    This tool converts in both directions and auto-detects whether your
    input is seconds or milliseconds (values > 1 trillion are treated
    as milliseconds).
    """
    print("  Converts between Unix timestamps and human-readable dates.")
    print("  Unix timestamps = seconds since Jan 1, 1970 00:00:00 UTC.")
    print("  Auto-detects seconds vs milliseconds (values > 10^12 = ms).")
    print()
    print("  Examples:")
    print("    1700000000       -> 2023-11-14 22:13:20 UTC")
    print("    1700000000000    -> 2023-11-14 22:13:20 UTC (auto-detected as ms)")
    print("    2024-01-15 10:30 -> 1705313400")
    print()
    print("  ts2date = timestamp -> human-readable date")
    print("  date2ts = human-readable date -> timestamp")
    mode = _ask("Conversion direction", "ts2date").lower()
    if mode == "ts2date":
        print()
        print("  Enter a Unix timestamp. Can be in seconds (10 digits) or")
        print("  milliseconds (13 digits). The tool auto-detects which one.")
        print("  Examples: 1700000000, 1700000000000, 0")
        ts_str = _ask("Unix timestamp")
        if not ts_str:
            print("[ERROR] No timestamp given; aborting.")
            return
        try:
            ts_val = float(ts_str)
        except ValueError:
            print("[ERROR] Invalid numeric timestamp. Enter a number like 1700000000.")
            return
        # Auto-detect milliseconds
        if ts_val > 1e12:
            print(f"  (auto-detected as milliseconds, converting to seconds: {ts_val / 1000:.3f})")
            ts_val = ts_val / 1000.0
        try:
            dt_utc = datetime.fromtimestamp(ts_val, tz=timezone.utc)
            dt_local = datetime.fromtimestamp(ts_val)
        except (OSError, ValueError) as exc:
            print(f"[ERROR] Could not convert timestamp: {exc}")
            return
        rows = [
            ("unix timestamp (seconds)", f"{ts_val:.3f}"),
            ("UTC", dt_utc.strftime("%Y-%m-%d %H:%M:%S UTC")),
            ("local time", dt_local.strftime("%Y-%m-%d %H:%M:%S")),
            ("ISO 8601", dt_utc.isoformat()),
            ("day of week", dt_utc.strftime("%A")),
        ]
        print()
        print_table(["field", "value"], rows)
        session.set_result("timestamp", {"unix": ts_val, "utc": dt_utc.isoformat(), "local": dt_local.isoformat()})
    elif mode == "date2ts":
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print()
        print(f"  Current time: {now_str}")
        print("  Enter a date in YYYY-MM-DD HH:MM:SS format.")
        print("  Examples: 2024-01-15 10:30:00, 2023-12-25 00:00:00")
        date_str = _ask("Date and time", now_str)
        if not date_str:
            print("[ERROR] No date given; aborting.")
            return
        try:
            dt = datetime.strptime(date_str, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            print("[ERROR] Date must be in YYYY-MM-DD HH:MM:SS format.")
            print("[INFO] Example: 2024-01-15 10:30:00")
            return
        ts_val = dt.timestamp()
        rows = [
            ("input date", date_str),
            ("unix timestamp (seconds)", f"{ts_val:.3f}"),
            ("unix timestamp (milliseconds)", f"{ts_val * 1000:.0f}"),
            ("ISO 8601", dt.replace(tzinfo=timezone.utc).isoformat()),
            ("day of week", dt.strftime("%A")),
        ]
        print()
        print_table(["field", "value"], rows)
        session.set_result("timestamp", {"input": date_str, "unix": ts_val, "iso": dt.isoformat()})
    else:
        print("[ERROR] Mode must be 'ts2date' or 'date2ts'.")


# ---------------------------------------------------------------------------
# [35] Color Code Converter
# ---------------------------------------------------------------------------
def _hex_to_rgb(hex_color: str) -> Tuple[int, int, int]:
    hex_color = hex_color.lstrip("#")
    if len(hex_color) == 3:
        hex_color = "".join(c * 2 for c in hex_color)
    if len(hex_color) != 6:
        raise ValueError(f"invalid hex color: #{hex_color}")
    return (int(hex_color[0:2], 16), int(hex_color[2:4], 16), int(hex_color[4:6], 16))


def _rgb_to_hex(r: int, g: int, b: int) -> str:
    return f"#{r:02x}{g:02x}{b:02x}"


def _rgb_to_hsl(r: int, g: int, b: int) -> Tuple[float, float, float]:
    r_n, g_n, b_n = r / 255.0, g / 255.0, b / 255.0
    mx = max(r_n, g_n, b_n)
    mn = min(r_n, g_n, b_n)
    l = (mx + mn) / 2.0
    if mx == mn:
        h = s = 0.0
    else:
        d = mx - mn
        s = d / (2.0 - mx - mn) if l > 0.5 else d / (mx + mn)
        if mx == r_n:
            h = (g_n - b_n) / d + (6 if g_n < b_n else 0)
        elif mx == g_n:
            h = (b_n - r_n) / d + 2
        else:
            h = (r_n - g_n) / d + 4
        h /= 6.0
    return (round(h * 360, 1), round(s * 100, 1), round(l * 100, 1))


def _hsl_to_rgb(h: float, s: float, l: float) -> Tuple[int, int, int]:
    h_n, s_n, l_n = h / 360.0, s / 100.0, l / 100.0
    if s_n == 0:
        r = g = b = l_n
    else:
        def _hue2rgb(p: float, q: float, t: float) -> float:
            if t < 0:
                t += 1.0
            if t > 1:
                t -= 1.0
            if t < 1 / 6:
                return p + (q - p) * 6 * t
            if t < 1 / 2:
                return q
            if t < 2 / 3:
                return p + (q - p) * (2 / 3 - t) * 6
            return p
        q = l_n * (1 + s_n) if l_n < 0.5 else l_n + s_n - l_n * s_n
        p = 2 * l_n - q
        r = _hue2rgb(p, q, h_n + 1 / 3)
        g = _hue2rgb(p, q, h_n)
        b = _hue2rgb(p, q, h_n - 1 / 3)
    return (round(r * 255), round(g * 255), round(b * 255))


def color_converter(session: Session) -> None:
    """Convert between HEX, RGB, and HSL color codes.

    Three common color formats:
      HEX: #rrggbb (e.g. #ff5733) — used in CSS, HTML, design tools
      RGB: rgb(r, g, b) — 0-255 per channel — used in CSS, image editors
      HSL: hsl(h, s%, l%) — hue (0-360), saturation (0-100%), lightness (0-100%)
           — more intuitive for humans (pick a color, then adjust)

    Converts your input to all three formats so you can copy whichever
    you need.
    """
    print("  Converts colors between HEX, RGB, and HSL formats.")
    print("  Enter one format, get all three back.")
    print()
    print("  Format explanations:")
    print("    HEX: #rrggbb — e.g. #ff5733 (web/CSS standard)")
    print("    RGB: r,g,b   — e.g. 255,87,51 (0-255 per channel)")
    print("    HSL: h,s,l   — e.g. 11,100%,60% (hue 0-360, sat/light 0-100%)")
    print()
    print("  Common colors for reference:")
    print("    Red:    #ff0000  /  255,0,0    /  0,100%,50%")
    print("    Green:  #00ff00  /  0,255,0    /  120,100%,50%")
    print("    Blue:   #0000ff  /  0,0,255    /  240,100%,50%")
    print("    White:  #ffffff  /  255,255,255 /  0,0%,100%")
    print("    Black:  #000000  /  0,0,0      /  0,0%,0%")
    print()
    print("  hex = input as #rrggbb (e.g. #ff5733)")
    print("  rgb = input as r,g,b (e.g. 255,87,51)")
    print("  hsl = input as h,s,l (e.g. 11,100,60)")
    mode = _ask("Input format", "hex").lower()
    if mode == "hex":
        print()
        print("  Enter a hex color with or without the # prefix.")
        print("  Short form OK: #f00 = #ff0000 (red)")
        hex_val = _ask("HEX color value (e.g. #ff5733 or ff5733)")
        if not hex_val:
            print("[ERROR] No color given; aborting.")
            return
        try:
            r, g, b = _hex_to_rgb(hex_val)
        except ValueError as exc:
            print(f"[ERROR] {exc}")
            print("[INFO] Valid formats: #ff5733, ff5733, #f00, f00")
            return
    elif mode == "rgb":
        print()
        print("  Enter each channel as a number from 0 to 255.")
        print("  0 = no color (dark), 255 = full brightness.")
        print()
        r_str = _ask("Red channel (0-255, where 0=none, 255=full red)")
        g_str = _ask("Green channel (0-255, where 0=none, 255=full green)")
        b_str = _ask("Blue channel (0-255, where 0=none, 255=full blue)")
        try:
            r, g, b = int(r_str), int(g_str), int(b_str)
            if not all(0 <= v <= 255 for v in (r, g, b)):
                raise ValueError
        except ValueError:
            print("[ERROR] RGB values must be integers between 0 and 255.")
            print("[INFO] Example: 255,87,51 for a red-orange color")
            return
    elif mode == "hsl":
        print()
        print("  HSL is the most intuitive format for picking colors:")
        print("    Hue:        0-360 (color wheel: 0=red, 120=green, 240=blue)")
        print("    Saturation: 0-100% (0=gray, 100=vivid)")
        print("    Lightness:  0-100% (0=black, 50=normal, 100=white)")
        print()
        h_str = _ask("Hue (0-360 degrees on the color wheel)")
        s_str = _ask("Saturation (0-100%, where 0=gray, 100=vivid)")
        l_str = _ask("Lightness (0-100%, where 0=black, 50=normal, 100=white)")
        try:
            h, s, l = float(h_str), float(s_str), float(l_str)
            if not (0 <= h <= 360 and 0 <= s <= 100 and 0 <= l <= 100):
                raise ValueError
            r, g, b = _hsl_to_rgb(h, s, l)
        except ValueError:
            print("[ERROR] Invalid HSL values.")
            print("[INFO] Hue must be 0-360, saturation and lightness must be 0-100.")
            print("[INFO] Example: 11,100,60 for a red-orange color")
            return
    else:
        print("[ERROR] Format must be 'hex', 'rgb', or 'hsl'.")
        return

    h, s, l = _rgb_to_hsl(r, g, b)
    hex_val = _rgb_to_hex(r, g, b)

    rows = [
        ("HEX", hex_val),
        ("RGB", f"rgb({r}, {g}, {b})"),
        ("HSL", f"hsl({h}°, {s}%, {l}%)"),
        ("Red channel", f"{r} / 255 ({r * 100 // 255}%)"),
        ("Green channel", f"{g} / 255 ({g * 100 // 255}%)"),
        ("Blue channel", f"{b} / 255 ({b * 100 // 255}%)"),
    ]
    print()
    print_table(["format", "value"], rows)

    # Visual preview hint
    print()
    if l < 20:
        print("  [dark color — low lightness]")
    elif l > 80:
        print("  [light/pastel color — high lightness]")
    elif s < 10:
        print("  [near-gray — low saturation]")
    else:
        print(f"  [vivid color — {s}% saturation, {l}% lightness]")

    session.set_result("color", {"hex": hex_val, "rgb": (r, g, b), "hsl": (h, s, l)})
    print(f"\n[INFO] Color values stored as 'color' in session.")
