#!/usr/bin/env python3
"""
Test calibrated centering and exact 5...3.stl truncation rule:
- Rule: 5 letters + "..." + 3 letters + ".stl" (e.g. ghtdf...ddd.stl)
- Exact optical vertical centering: for smaller fonts (middle-dots), adjust Y offset down
  so it is never shifted higher than short names.
"""

import subprocess

BASE_CARD = "/home/imm/icons/card_stl.png"
FONT_PATH = "/home/imm/icons/fonts/RobotoMono-RealBold.ttf"

def test_render(name: str, out_name: str, y_offset: int, hue: int = 140):
    name_part = name[:-4] if name.endswith(".stl") else name
    # 5 letters + "..." + 3 letters + ".stl"
    if len(name_part) > 10:
        display_text = f"{name_part[:5]}...{name_part[-3:]}.stl"
        font_size = 84
    else:
        display_text = f"{name_part}.stl"
        font_size = 120

    # Canvas: 1200x1200, Pill bounds Y=[455, 736], Center Y = 595.5
    # For small text, we need positive baseline compensation (+y_offset)
    vf = (
        f"hue=h={hue},"
        f"drawtext=fontfile={FONT_PATH}:"
        f"text='{display_text}':"
        f"fontsize={font_size}:"
        f"fontcolor=0x000000:"
        f"x=(w-text_w)/2:"
        f"y=(h-text_h)/2+{y_offset}"
    )

    cmd = ["ffmpeg", "-y", "-i", BASE_CARD, "-vf", vf, f"/home/imm/icons/{out_name}"]
    subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
    print(f"Generated /home/imm/icons/{out_name} with y_offset={y_offset}")

if __name__ == "__main__":
    test_render("ghtdf123456789ddd.stl", "test_center_y5.png", y_offset=5)
    test_render("ghtdf123456789ddd.stl", "test_center_y12.png", y_offset=12)
    test_render("ghtdf123456789ddd.stl", "test_center_y18.png", y_offset=18)
    test_render("alex.stl", "test_alex_centered.png", y_offset=0, hue=0)
