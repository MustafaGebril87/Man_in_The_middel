"""
Generate PNG icons for the MITM Detector Chrome extension.
Requires: pip install Pillow
Run once: python generate_icons.py
"""

from PIL import Image, ImageDraw, ImageFont
import os

def make_shield_icon(size, output_path, alert=False):
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    pad = size * 0.08
    cx = size / 2
    sw = size - 2 * pad  # shield width

    # Shield body color
    body_color = (239, 68, 68, 255) if alert else (79, 110, 247, 255)
    dark_color  = (200, 40, 40, 255) if alert else (50, 80, 200, 255)

    # Draw shield shape as a rounded polygon
    # Shield: top-left, top-right, bottom-center
    top_y   = pad
    mid_y   = size * 0.55
    bot_y   = size - pad * 0.5
    left_x  = pad
    right_x = size - pad

    points = [
        (left_x, top_y),
        (right_x, top_y),
        (right_x, mid_y),
        (cx, bot_y),
        (left_x, mid_y),
    ]
    draw.polygon(points, fill=body_color)

    # Inner highlight
    inset = size * 0.12
    inner = [
        (left_x + inset, top_y + inset),
        (right_x - inset, top_y + inset),
        (right_x - inset, mid_y - inset * 0.3),
        (cx, bot_y - inset * 1.2),
        (left_x + inset, mid_y - inset * 0.3),
    ]
    draw.polygon(inner, fill=dark_color)

    # Draw checkmark or exclamation
    lc = (255, 255, 255, 240)
    lw = max(1, int(size * 0.07))
    icon_cx = cx
    icon_cy = size * 0.42

    if alert:
        # Exclamation mark
        bar_w = max(2, int(size * 0.1))
        bar_h = size * 0.22
        dot_r = max(1, int(size * 0.07))
        draw.rectangle(
            [icon_cx - bar_w, icon_cy - bar_h, icon_cx + bar_w, icon_cy + bar_h * 0.1],
            fill=lc
        )
        draw.ellipse(
            [icon_cx - dot_r, icon_cy + bar_h * 0.25 - dot_r,
             icon_cx + dot_r, icon_cy + bar_h * 0.25 + dot_r],
            fill=lc
        )
    else:
        # Checkmark
        check_pts = [
            (icon_cx - size * 0.17, icon_cy),
            (icon_cx - size * 0.04, icon_cy + size * 0.14),
            (icon_cx + size * 0.18, icon_cy - size * 0.14),
        ]
        for i in range(len(check_pts) - 1):
            draw.line([check_pts[i], check_pts[i + 1]], fill=lc, width=lw)

    img.save(output_path, "PNG")
    print(f"  Saved {output_path} ({size}x{size})")


if __name__ == "__main__":
    os.makedirs("icons", exist_ok=True)
    for sz in [16, 48, 128]:
        make_shield_icon(sz, f"icons/icon{sz}.png", alert=False)
    make_shield_icon(48, "icons/icon_alert.png", alert=True)
    print("Done. Icons written to icons/")
