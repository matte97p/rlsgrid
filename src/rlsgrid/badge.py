"""Badge generation for fuzz results.

Two output shapes are supported:

- **Shields.io endpoint JSON** — the project commits the JSON file to its
  repo and references it from a `https://img.shields.io/endpoint?url=…`
  badge URL. Shields renders the badge; no asset hosting needed.
- **Static SVG** — a self-contained shields-style badge that the project
  can host wherever it wants (GitHub Pages, S3, raw URL).
"""

from __future__ import annotations

from dataclasses import dataclass

LABEL = "rlsgrid"


@dataclass(frozen=True)
class BadgeData:
    message: str
    color: str  # shields.io color name or 6-hex


def from_fuzz_report(*, ok: bool, breaches: int, skipped: int) -> BadgeData:
    """Map a fuzz outcome to the displayed message + colour."""
    if ok:
        return BadgeData(message="no cross-tenant leaks", color="brightgreen")
    return BadgeData(
        message=f"{breaches} leak" + ("" if breaches == 1 else "s"),
        color="critical",
    )


def make_shields_json(badge: BadgeData) -> dict[str, object]:
    return {
        "schemaVersion": 1,
        "label": LABEL,
        "message": badge.message,
        "color": badge.color,
    }


_COLOR_HEX = {
    "brightgreen": "#4c1",
    "green": "#97ca00",
    "yellowgreen": "#a4a61d",
    "yellow": "#dfb317",
    "orange": "#fe7d37",
    "red": "#e05d44",
    "critical": "#e05d44",
    "blue": "#007ec6",
    "lightgrey": "#9f9f9f",
    "lightgray": "#9f9f9f",
    "gray": "#555",
    "grey": "#555",
}


def _color_to_hex(color: str) -> str:
    return _COLOR_HEX.get(color, color if color.startswith("#") else "#9f9f9f")


def make_svg(badge: BadgeData) -> str:
    """Render a flat shields-style SVG without external dependencies.

    Width is computed from character counts at 7px/char — adequate for the
    short status strings rlsgrid emits. For pixel-perfect rendering, use
    the shields.io endpoint output instead.
    """
    label_w = max(56, 6 + 7 * len(LABEL))
    msg_w = max(40, 12 + 7 * len(badge.message))
    total = label_w + msg_w
    color = _color_to_hex(badge.color)

    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{total}" height="20" '
        'role="img" aria-label="rlsgrid: ' + _xml_escape(badge.message) + '">\n'
        '  <linearGradient id="s" x2="0" y2="100%">\n'
        '    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>\n'
        '    <stop offset="1" stop-opacity=".1"/>\n'
        '  </linearGradient>\n'
        f'  <rect width="{total}" height="20" rx="3" fill="#555"/>\n'
        f'  <rect x="{label_w}" width="{msg_w}" height="20" rx="3" fill="{color}"/>\n'
        f'  <rect width="{total}" height="20" rx="3" fill="url(#s)"/>\n'
        '  <g fill="#fff" text-anchor="middle" '
        'font-family="DejaVu Sans,Verdana,Geneva,sans-serif" font-size="11">\n'
        f'    <text x="{label_w // 2}" y="14">{LABEL}</text>\n'
        f'    <text x="{label_w + msg_w // 2}" y="14">{_xml_escape(badge.message)}</text>\n'
        '  </g>\n'
        '</svg>\n'
    )


def _xml_escape(value: str) -> str:
    return (
        value.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )
