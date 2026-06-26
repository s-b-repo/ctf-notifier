#!/usr/bin/env python3
"""Generate icon.png used by the app launcher and the GUI window title bar."""
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont


def main() -> None:
    size = 256
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)

    # rounded black tile with a red border
    d.rounded_rectangle([8, 8, size - 8, size - 8], radius=46, fill=(13, 13, 13, 255))
    d.rounded_rectangle([8, 8, size - 8, size - 8], radius=46, outline=(255, 77, 77, 255), width=4)

    # red flag on a yellow pole
    d.rounded_rectangle([74, 54, 86, 196], radius=6, fill=(255, 210, 63, 255))
    d.polygon([(86, 64), (196, 92), (86, 122)], fill=(255, 77, 77, 255))

    # "CTF" wordmark
    font = None
    for path in (
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
        "/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf",
    ):
        if Path(path).exists():
            font = ImageFont.truetype(path, 70)
            break
    if font is None:
        font = ImageFont.load_default()

    text = "CTF"
    tb = d.textbbox((0, 0), text, font=font)
    tw = tb[2] - tb[0]
    d.text(((size - tw) / 2 - tb[0], 150), text, font=font, fill=(255, 210, 63, 255))

    out = Path(__file__).with_name("icon.png")
    img.save(out)
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
