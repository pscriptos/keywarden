#!/usr/bin/env python3
"""
Tabler Icons Subset Tool for Keywarden
=======================================
Scans all HTML templates for used ti-* icon classes, then generates:
  1. A subsetted woff2 font with only the needed glyphs
  2. A minimal CSS file with only the matching icon rules

Prerequisites (one-time):
  pip install fonttools brotli

Usage:
  python tools/subset-icons.py

Source files (full Tabler Icons 3.6.0) are stored in tools/tabler-icons-full/.
Output goes directly to web/static/css/ and web/static/css/fonts/.
"""

import os
import re
import subprocess
import sys

# ── Paths (relative to project root) ──
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)

TEMPLATE_DIR = os.path.join(PROJECT_ROOT, "web", "templates")
FULL_CSS = os.path.join(SCRIPT_DIR, "tabler-icons-full", "tabler-icons.min.css")
FULL_FONT = os.path.join(SCRIPT_DIR, "tabler-icons-full", "tabler-icons.woff2")

OUT_CSS = os.path.join(PROJECT_ROOT, "web", "static", "css", "tabler-icons.min.css")
OUT_FONT = os.path.join(PROJECT_ROOT, "web", "static", "css", "fonts", "tabler-icons.woff2")


def find_used_icons():
    """Scan all .html templates for ti-* class names."""
    icons = set()
    pattern = re.compile(r"ti-[a-z][a-z0-9-]+")
    for root, _, files in os.walk(TEMPLATE_DIR):
        for f in files:
            if not f.endswith(".html"):
                continue
            with open(os.path.join(root, f), encoding="utf-8") as fh:
                for match in pattern.finditer(fh.read()):
                    icons.add(match.group(0))
    # ti-spin is a CSS animation class, not an icon glyph
    icons.discard("ti-spin")
    return sorted(icons)


def extract_codepoints(css_text, icons):
    """Extract Unicode codepoints from the full CSS for each icon."""
    codepoints = []
    missing = []
    for icon in icons:
        pat = re.escape("." + icon) + r':before\{content:"\\([0-9a-f]+)"\}'
        m = re.search(pat, css_text)
        if m:
            codepoints.append(m.group(1))
        else:
            missing.append(icon)
    return codepoints, missing


def build_subset_css(css_text, icons):
    """Build a minimal CSS containing only the @font-face, .ti base rule,
    and the individual icon rules for the used icons."""
    # Extract header comment + @font-face + .ti base rule
    m = re.match(r'(/\*[\s\S]*?\*/)(@font-face\{[^}]+\})(\.ti\{[^}]+\})', css_text)
    if not m:
        print("ERROR: Could not parse base CSS rules from full source")
        sys.exit(1)

    # Patch @font-face: keep only woff2 and add font-display:swap
    font_face = m.group(2)
    # Remove woff and truetype sources, keep only woff2
    font_face = re.sub(
        r',url\("[^"]*\.woff\?[^"]*"\)\s*format\("woff"\)', '', font_face
    )
    font_face = re.sub(
        r',url\("[^"]*\.ttf[^"]*"\)\s*format\("truetype"\)', '', font_face
    )
    # Add font-display:swap if not present
    if "font-display" not in font_face:
        font_face = font_face.replace(
            "font-weight:400;",
            "font-weight:400;font-display:swap;"
        )

    header = m.group(1) + font_face + m.group(3)

    # Extract individual icon rules
    rules = []
    for icon in icons:
        pat = re.escape("." + icon) + r':before\{content:"\\[0-9a-f]+"\}'
        match = re.search(pat, css_text)
        if match:
            rules.append(match.group(0))

    # Keep .ti-spin animation if present
    result = header + "".join(rules)
    spin_kf = re.search(r'@keyframes\s+spin\{[^}]+\{[^}]+\}\}', css_text)
    spin_cls = re.search(r'\.ti-spin\{[^}]+\}', css_text)
    if spin_kf:
        result += spin_kf.group(0)
    if spin_cls:
        result += spin_cls.group(0)

    return result, len(rules)


def subset_font(codepoints):
    """Run pyftsubset to create a woff2 with only the needed glyphs."""
    unicodes = ",".join(f"U+{cp}" for cp in codepoints)
    cmd = [
        sys.executable, "-m", "fontTools.subset",
        FULL_FONT,
        f"--output-file={OUT_FONT}",
        "--flavor=woff2",
        "--no-layout-closure",
        "--drop-tables+=GSUB,GPOS,GDEF",
        f"--unicodes={unicodes}",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print("ERROR: pyftsubset failed:")
        print(result.stderr)
        sys.exit(1)


def main():
    # Verify source files exist
    for path in (FULL_CSS, FULL_FONT):
        if not os.path.exists(path):
            print(f"ERROR: Source file missing: {path}")
            print("These should be in tools/tabler-icons-full/")
            sys.exit(1)

    # Try importing fonttools
    try:
        import fontTools  # noqa: F401
    except ImportError:
        print("ERROR: fonttools not installed. Run: pip install fonttools brotli")
        sys.exit(1)

    print("Scanning templates for icon usage...")
    icons = find_used_icons()
    print(f"  Found {len(icons)} unique icons")

    print("Reading full CSS source...")
    with open(FULL_CSS, encoding="utf-8") as f:
        full_css = f.read()

    print("Extracting Unicode codepoints...")
    codepoints, missing = extract_codepoints(full_css, icons)
    if missing:
        print(f"  WARNING: No codepoint found for: {', '.join(missing)}")
    print(f"  Mapped {len(codepoints)} codepoints")

    print("Subsetting font...")
    subset_font(codepoints)
    orig_size = os.path.getsize(FULL_FONT)
    new_size = os.path.getsize(OUT_FONT)
    print(f"  {orig_size//1024} KB -> {new_size//1024} KB ({100-round(new_size/orig_size*100,1)}% smaller)")

    print("Building subset CSS...")
    css_out, rule_count = build_subset_css(full_css, icons)
    with open(OUT_CSS, "w", encoding="utf-8") as f:
        f.write(css_out)
    orig_css_size = os.path.getsize(FULL_CSS)
    new_css_size = os.path.getsize(OUT_CSS)
    print(f"  {rule_count} icon rules, {orig_css_size//1024} KB -> {new_css_size//1024} KB")

    print("\nDone! Subsetted files written to:")
    print(f"  Font: {os.path.relpath(OUT_FONT, PROJECT_ROOT)}")
    print(f"  CSS:  {os.path.relpath(OUT_CSS, PROJECT_ROOT)}")


if __name__ == "__main__":
    main()
