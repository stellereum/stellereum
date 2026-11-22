#!/usr/bin/env python3
"""
Test rendering exact font and size matching the reference:
- RobotoMono.ttf (exact match to durovgram.ton)
- Bold, solid black #000000
- Perfectly fills the pill with balanced margins
"""

import subprocess

BASE_CARD = "/home/imm/icons/card_stl.png"
ROBOTO_MONO = "/home/imm/icons/fonts/RobotoMono.ttf"
RUBIK = "/home/imm/icons/fonts/Rubik.ttf"

def render(text: str, font_path: str, font_size: int, out_path: str, hue: int = 0):
    # Canvas 1200x1200. Pill center is at Y=595.
    vf = (
        f"hue=h={hue},"
        f"drawtext=fontfile={font_path}:"
        f"text='{text}':"
        f"fontsize={font_size}:"
        f"fontcolor=0x000000:"
        f"x=(w-text_w)/2:"
        f"y=595-(text_h/2)-6"
    )
    cmd = ["ffmpeg", "-y", "-i", BASE_CARD, "-vf", vf, out_path]
    subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
    print(f"Rendered: {out_path} ({text}, {font_size}px)")

if __name__ == "__main__":
    # Monospace Roboto Mono (exact 1:1 to durovgram.ton):
    render("durovgram.stl", ROBOTO_MONO, 96, "/home/imm/icons/durovgram_roboto.png", 0)
    render("alex.stl", ROBOTO_MONO, 145, "/home/imm/icons/alex_roboto.png", 0)
    render("jdhkf...sda.stl", ROBOTO_MONO, 88, "/home/imm/icons/jdhkf_roboto.png", 120)

    # Proportional Rubik Bold (wider letters, heavy weight):
    render("durovgram.stl", RUBIK, 118, "/home/imm/icons/durovgram_rubik.png", 0)
    render("alex.stl", RUBIK, 155, "/home/imm/icons/alex_rubik.png", 0)
    render("jdhkf...sda.stl", RUBIK, 105, "/home/imm/icons/jdhkf_rubik.png", 120)
