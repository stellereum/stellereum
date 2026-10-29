#!/usr/bin/env python3
"""
Generate STL NFT Cards matching the reference style:
- Big, confident, bold typography filling the pill badge
- Rubik-ExtraBold (subtly rounded corners, heavy weight)
- Clean, solid black text
- Middle truncation with '...' for overly long nicknames
"""

import hashlib
import subprocess
import os

BASE_CARD = "/home/imm/icons/card_stl.png"
FONT_PATH = "/home/imm/icons/fonts/Rubik-ExtraBold.ttf"

def render_reference_card(domain: str, output_path: str, hue_deg: int = None):
    if not domain.endswith(".stl"):
        domain = domain + ".stl"

    name_part = domain[:-4]
    char_len = len(domain)

    # 1. Truncation logic:
    # If the domain has more than 13 characters (e.g. longer than durovgram.stl),
    # truncate in the middle: prefix (5 chars) + '...' + suffix (4 chars) + '.stl'
    if len(name_part) > 10:
        display_text = f"{name_part[:5]}...{name_part[-4:]}.stl"
    else:
        display_text = domain

    # 2. Font size scaling to fill ~50-60% of the pill height (pill is 281px tall):
    disp_len = len(display_text)
    if disp_len <= 8:
        # e.g. "alex.stl" (8 chars)
        font_size = 155
    elif disp_len <= 10:
        # e.g. "crypto.stl" (10 chars)
        font_size = 135
    elif disp_len <= 13:
        # e.g. "durovgram.stl" (13 chars)
        font_size = 118
    else:
        # e.g. "jdhkf...sda.stl" (15 chars)
        font_size = 110

    # 3. Derive Hue if not set
    if hue_deg is None:
        h = int(hashlib.sha256(domain.encode()).hexdigest(), 16)
        hue_deg = h % 360

    escaped_text = display_text.replace(":", "\\:").replace("'", "\\'")

    # In card_stl.png, canvas is 1200x1200, pill Y is 455..736 (center 595)
    vf = (
        f"hue=h={hue_deg},"
        f"drawtext=fontfile='{FONT_PATH}':"
        f"text='{escaped_text}':"
        f"fontsize={font_size}:"
        f"fontcolor=0x0a0c10:"
        f"x=(w-text_w)/2:"
        f"y=595-(text_h/2)-8"
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
    render_reference_card("alex.stl", "/home/imm/icons/ref_alex.png", hue_deg=0) # original blue
    render_reference_card("durovgram.stl", "/home/imm/icons/ref_durovgram.png", hue_deg=180) # cyan/ice
    render_reference_card("jdhkfsjhdfkshsda.stl", "/home/imm/icons/ref_middle_dots.png", hue_deg=115) # purple/pink
