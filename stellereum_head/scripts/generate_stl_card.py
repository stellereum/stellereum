#!/usr/bin/env python3
"""
Stellereum .STL NFT Card Production Generator
Pure Minimalist Architecture (NO corner logos, NO clutter):
- Authentic Roboto Mono Bold typography
- Bold, solid black #000000 lettering
- Calibrated font sizing with balanced margins inside the pill
- Middle truncation with ellipsis (prefix...suffix.stl) for long names
- Clean cosmic background with stars & volumetric glow
- Automatic deterministic or random cosmic hue shift
"""

import hashlib
import os
import subprocess
import sys

BASE_CARD = "/home/imm/icons/card_stl.png"
FONT_PATH = "/home/imm/icons/fonts/RobotoMono-RealBold.ttf"

def generate_card(domain: str, output_path: str, hue_deg: int = None):
    # Ensure domain ends with .stl
    if not domain.endswith(".stl"):
        domain = domain + ".stl"

    name_part = domain[:-4]

    # Truncation logic matching user rule:
    # If name part is longer than 10 characters, truncate in the middle:
    # exactly 5 letters + '...' + 3 letters + '.stl' (e.g. ghtdf...ddd.stl)
    if len(name_part) > 10:
        display_text = f"{name_part[:5]}...{name_part[-3:]}.stl"
        font_size = 84
        y_offset = 12
    else:
        display_text = domain
        disp_len = len(display_text)
        if disp_len <= 7:
            font_size = 135
            y_offset = 2
        elif disp_len <= 9:
            font_size = 120
            y_offset = 4
        elif disp_len <= 11:
            font_size = 108
            y_offset = 6
        else:
            font_size = 98
            y_offset = 8

    # Derive Hue if not set
    if hue_deg is None:
        h = int(hashlib.sha256(domain.encode()).hexdigest(), 16)
        hue_deg = h % 360

    escaped_text = display_text.replace(":", "\\:").replace("'", "\\'")

    # Clean, pure minimalist filter:
    # 1. Shift hue on base card
    # 2. Draw black Roboto Mono Bold text with optical center compensation:
    #    y = (h - text_h) / 2 + y_offset
    vf = (
        f"hue=h={hue_deg},"
        f"drawtext=fontfile={FONT_PATH}:"
        f"text='{escaped_text}':"
        f"fontsize={font_size}:"
        f"fontcolor=0x000000:"
        f"x=(w-text_w)/2:"
        f"y=(h-text_h)/2+{y_offset}"
    )

    cmd = [
        "ffmpeg", "-y",
        "-i", BASE_CARD,
        "-vf", vf,
        output_path
    ]

    subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
    print(f"Generated: {output_path} | Text: '{display_text}' | Size: {font_size}px | Hue: {hue_deg}°")

if __name__ == "__main__":
    test_suite = [
        ("alex.stl", "/home/imm/icons/alex_clean.png", 0),                 # Original Ice Blue
        ("durovgram.stl", "/home/imm/icons/durovgram_clean.png", 0),       # Reference length
        ("ceo.stl", "/home/imm/icons/ceo_clean.png", 210),                 # Amber / Gold
        ("satoshi.stl", "/home/imm/icons/satoshi_clean.png", 115),         # Royal Purple
        ("community.stl", "/home/imm/icons/community_clean.png", 280),     # Emerald
        ("jdhkfsjhdfkshsda.stl", "/home/imm/icons/jdhkf_clean.png", 140),  # Middle dots
    ]

    for dom, out, h in test_suite:
        generate_card(dom, out, hue_deg=h)
