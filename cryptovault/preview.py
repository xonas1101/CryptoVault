"""View-only previews with the viewer's identity burned into every pixel.

This is deterrence, not cryptography. Anyone who can see a file can photograph the
screen. What a watermark adds is attribution: a leaked screenshot shows who leaked it and when.
"""
import io
from datetime import datetime

import pypdfium2 as pdfium
from PIL import Image, ImageDraw, ImageFont

MAX_TEXT = 200_000  # characters shown in a text preview
TEXT_TYPES = ("application/json", "application/xml", "application/javascript", "application/x-sh")


def kind(mime: str) -> str | None:
    if mime.startswith("image/") and mime != "image/svg+xml":  # SVG can contain scripts, so it's never rendered
        return "image"
    if mime == "application/pdf":
        return "pdf"
    if mime.startswith("text/") or mime in TEXT_TYPES:
        return "text"
    return None


def stamp(viewer: str) -> str:
    return f"{viewer} · {datetime.now():%d %b %Y %H:%M}"


def tile(text: str, size: int = 18) -> Image.Image:
    font = ImageFont.load_default(size=size)
    img = Image.new("RGBA", (int(font.getlength(text)) + 4 * size, size * 5), (0, 0, 0, 0))
    # red text with a light outline stays readable on both dark and light content
    ImageDraw.Draw(img).text((2 * size, 2 * size), text, font=font, fill=(220, 40, 40, 130),
                             stroke_width=max(1, size // 14), stroke_fill=(255, 255, 255, 130))
    return img.rotate(25, expand=True)


def watermark(img: Image.Image, text: str) -> Image.Image:
    img = img.convert("RGBA")
    t = tile(text, size=max(14, img.width // 45))
    overlay = Image.new("RGBA", img.size, (0, 0, 0, 0))
    for row, y in enumerate(range(-t.height // 3, img.height, t.height * 2 // 3)):
        for x in range(-(row % 2) * t.width // 2, img.width, t.width):
            # alpha_composite (not paste) keeps the tile's transparency exact; it can't take negative offsets, so crop instead
            overlay.alpha_composite(t, dest=(max(0, x), max(0, y)), source=(max(0, -x), max(0, -y)))
    return Image.alpha_composite(img, overlay).convert("RGB")


def page_count(data: bytes, k: str) -> int:
    return len(pdfium.PdfDocument(data)) if k == "pdf" else 1


def render_page(data: bytes, k: str, n: int, viewer: str) -> bytes:
    """One watermarked PNG: page n of a PDF, or the image itself."""
    if k == "pdf":
        img = pdfium.PdfDocument(data)[n].render(scale=1.5).to_pil()
    else:
        img = Image.open(io.BytesIO(data))  # Pillow refuses decompression bombs by default
    out = io.BytesIO()
    watermark(img, stamp(viewer)).save(out, "PNG")
    return out.getvalue()


def tile_png(viewer: str) -> bytes:
    """Background tile laid over text previews."""
    out = io.BytesIO()
    tile(stamp(viewer), size=14).save(out, "PNG")
    return out.getvalue()
