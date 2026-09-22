"""The light theme palettes, and the rules that have to read them.

Themes are token overrides: :root defines the dark palette and each
``html[data-theme="light-*"]`` block redefines the tokens. That only works while
two things hold, and neither is enforced by anything a browser will tell you
about:

  1. every light block redefines EVERY colour token :root defines. Miss one and
     that one stays at its dark value, on a pale ground, forever;
  2. no rule hardcodes a colour a theme is supposed to own. ``.topbar`` did
     exactly that -- ``background: rgba(8,11,9,0.82)`` -- so all three light
     themes wore the near-black top bar, and ``.badge.cyan`` / ``.flash-info``
     hardcoded a dark border beside it.

Both classes fail silently and only in a theme nobody screenshots. Hence a test.

The palette values themselves come from the Claude Design project
(042e9f5e-9ea0-45ef-94ca-6223075f4b89, styles.css), which had in turn ported an
earlier version of these blocks from this file. The contrast floors below are
that design's stated intent -- accent colours double as text ink here, so each
is the dark INK step rather than the mid hue the dark theme uses.
"""
import re

import pytest

CSS = "hashview/static/css/phosphor.css"
APP_CSS = "hashview/static/css/phosphor-app.css"
LIGHT_THEMES = ("light-paper", "light-invert", "light-clean")

# Tokens that are structural rather than colour, so a light theme is allowed to
# inherit them from :root.
NON_COLOUR = {
    "mono", "sans", "row-pad", "card-pad", "gap", "radius", "radius-lg",
    "sidebar-w", "primary-rgb", "glow-sm", "glow", "glow-text",
    "primary-deep", "primary-dim",
}


def _source(path=CSS):
    return re.sub(r"/\*.*?\*/", "", open(path, encoding="utf-8").read(), flags=re.S)


def _block(selector, src=None):
    src = src if src is not None else _source()
    start = src.index(selector)
    return src[start:start + src[start:].index("\n}")]


def _tokens(selector, src=None):
    return {k: v.strip()
            for k, v in re.findall(r"--([\w-]+):\s*([^;]+);", _block(selector, src))}


def _resolve(token, table, seen=()):
    value = table.get(token, "")
    ref = re.fullmatch(r"var\(--([\w-]+)\)", value)
    if ref and ref.group(1) not in seen:
        return _resolve(ref.group(1), table, seen + (token,))
    return value


def _contrast(fg, bg):
    def channels(value):
        value = value.strip().lstrip("#")
        if len(value) == 3:
            value = "".join(c * 2 for c in value)
        return tuple(int(value[i:i + 2], 16) for i in (0, 2, 4))

    def luminance(rgb):
        def linear(c):
            c /= 255
            return c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4
        r, g, b = map(linear, channels(rgb))
        return 0.2126 * r + 0.7152 * g + 0.0722 * b

    a, b = luminance(fg), luminance(bg)
    return (max(a, b) + 0.05) / (min(a, b) + 0.05)


# --- the structural rule: a light theme may not inherit a dark colour ---------

@pytest.mark.parametrize("theme", LIGHT_THEMES)
def test_every_light_theme_redefines_every_colour_token(theme):
    """The bug class, stated as a test.

    A token added to :root and not to the light blocks keeps its dark value
    under a light theme. That is how the top bar stayed near-black: nothing
    fails, nothing warns, and it is only visible to someone running that theme.
    """
    dark = set(_tokens(":root {")) - NON_COLOUR
    light = set(_tokens(f'html[data-theme="{theme}"] {{'))

    missing = sorted(dark - light)
    assert not missing, (
        f"{theme} inherits these from the DARK palette: {missing}. Add an "
        "override to the light block (or list it in NON_COLOUR if it carries no "
        "colour).")


@pytest.mark.parametrize("theme", LIGHT_THEMES)
def test_each_theme_tints_its_own_top_bar(theme):
    """The reported symptom. --topbar-bg must exist per theme and must not be
    the dark bar."""
    dark_bar = _tokens(":root {")["topbar-bg"]
    light_bar = _tokens(f'html[data-theme="{theme}"] {{')["topbar-bg"]

    assert light_bar != dark_bar, f"{theme} is still wearing the dark top bar"
    assert light_bar.startswith("rgba("), light_bar


def test_no_rule_hardcodes_the_top_bar_background():
    """.topbar must read the token, or the themes cannot reach it."""
    topbar = _block(".topbar {")
    assert "var(--topbar-bg)" in topbar, topbar
    assert not re.search(r"background:\s*(#|rgba?\()", topbar), (
        "the top bar is painting a literal colour again")


@pytest.mark.parametrize("path", [CSS, APP_CSS])
def test_no_themed_rule_hardcodes_a_dark_literal(path):
    """Badge and flash fills derive from their token via color-mix.

    They used to be dark-theme rgba() literals, so a light theme got a dark tint
    behind light ink. Anything that needs a *neutral* literal (modal scrims,
    drop shadows, the scanline overlay) is deliberately exempt -- those are
    black-on-purpose at every theme, exactly as the design has them.
    """
    src = _source(path)
    offenders = []
    for rule in re.finditer(r"\.(badge|flash)[\w.-]*\s*\{([^}]*)\}", src):
        body = rule.group(2)
        if re.search(r"(background|border-color):\s*(#|rgba?\()", body):
            if "violet" in rule.group(0):      # ours, not the design's — see below
                continue
            offenders.append(rule.group(0).strip()[:88])
    assert not offenders, "themed rules still carry dark literals:\n" + "\n".join(offenders)


def test_the_slack_badge_is_themed_even_though_the_design_has_none():
    """.badge.violet is ours (Slack) and has no counterpart in the imported
    palettes, so it needs its own light override or it stays a dark chip."""
    src = _source()
    assert 'html[data-theme^="light"] .badge.violet' in src


# --- the palette's stated intent: accents are legible as text ----------------

@pytest.mark.parametrize("theme", LIGHT_THEMES)
def test_accent_ink_is_readable_on_every_ground_it_lands_on(theme):
    """Status pills, ETAs and hash types paint these tokens as TEXT.

    Checked against --surface-3, the darkest ground accent text sits on, not
    just --surface: passing only on the lightest ground is how the previous
    palette scored 2.2:1 in practice while looking fine in a mockup.
    """
    table = _tokens(f'html[data-theme="{theme}"] {{')
    grounds = {name: _resolve(name, table)
               for name in ("surface", "bg", "surface-3", "surface-2")}

    failures = []
    for ink in ("text", "text-dim", "text-mute", "primary", "green", "amber",
                "red", "cyan"):
        value = _resolve(ink, table)
        if not value.startswith("#"):
            continue
        for ground_name, ground in grounds.items():
            ratio = _contrast(value, ground)
            if ratio < 4.5:
                failures.append(f"--{ink} on --{ground_name}: {ratio:.2f}:1")
    assert not failures, f"{theme} below WCAG AA 4.5:1 —\n  " + "\n  ".join(failures)


@pytest.mark.parametrize("theme", LIGHT_THEMES)
def test_light_inks_are_opaque(theme):
    """8-digit hex collapses toward the ground on a pale theme.

    --text-faint was #8a806690 and friends; alpha-blended onto paper that lands
    near 2:1 and the text effectively vanishes. The imported palette makes every
    ink opaque.
    """
    table = _tokens(f'html[data-theme="{theme}"] {{')
    alpha = {f"--{k}": v for k, v in table.items()
             if re.fullmatch(r"#[0-9a-fA-F]{8}", v)}
    assert not alpha, f"{theme} has alpha-blended ink: {alpha}"


# --- dark is not part of this change ----------------------------------------

def test_the_dark_palette_is_untouched_except_for_additive_tokens():
    """The request was explicit: keep dark as is.

    The two tokens added to :root are seeded with the exact literals the rules
    they replaced were painting, so dark renders identically -- that is what
    makes them safe, and it is worth pinning rather than asserting.
    """
    dark = _tokens(":root {")
    assert dark["topbar-bg"].replace(" ", "") == "rgba(8,11,9,0.82)", (
        "--topbar-bg no longer reproduces the literal .topbar used to paint, so "
        "the dark top bar has moved")
    assert dark["cyan-dim"] == "#1f3d40", (
        "--cyan-dim no longer reproduces the literal .badge.cyan used to paint")
