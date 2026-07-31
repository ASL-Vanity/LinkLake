from __future__ import annotations

import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from PIL import Image


ROOT = Path(__file__).resolve().parent
PNG_DIR = ROOT / "png"
CHROME_CANDIDATES = (
    Path(r"C:\Program Files\Google\Chrome\Application\chrome.exe"),
    Path(r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"),
)


def chrome_path() -> Path:
    for candidate in CHROME_CANDIDATES:
        if candidate.exists():
            return candidate
    raise FileNotFoundError("找不到 Chrome 或 Edge，无法渲染 SVG")


def render_svg(svg_name: str, png_name: str, width: int, height: int, transparent: bool) -> Path:
    svg_path = ROOT / svg_name
    png_path = ROOT / png_name
    png_path.unlink(missing_ok=True)
    with tempfile.TemporaryDirectory(prefix="linklake-brand-") as profile:
        args = [
            str(chrome_path()),
            "--headless=new",
            "--disable-gpu",
            "--hide-scrollbars",
            "--force-device-scale-factor=1",
            f"--window-size={width},{height}",
            f"--user-data-dir={profile}",
            f"--screenshot={png_path}",
        ]
        if transparent:
            args.append("--default-background-color=00000000")
        args.append(svg_path.as_uri())
        subprocess.run(args, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(50):
        if png_path.exists() and png_path.stat().st_size > 0:
            return png_path
        time.sleep(0.05)
    raise RuntimeError(f"Chrome 未生成 {png_path}")


def resize(source: Image.Image, name: str, size: tuple[int, int]) -> None:
    image = source.resize(size, Image.Resampling.LANCZOS)
    image.save(PNG_DIR / name, format="PNG", optimize=True)


def export() -> None:
    PNG_DIR.mkdir(exist_ok=True)

    masters = {
        "app": render_svg("linklake-app-icon.svg", ".app-master.png", 1024, 1024, True),
        "maskable": render_svg("linklake-maskable-icon.svg", ".maskable-master.png", 1024, 1024, False),
        "favicon": render_svg("favicon.svg", ".favicon-master.png", 512, 512, True),
        "mark": render_svg("linklake-mark.svg", ".mark-master.png", 1024, 1024, True),
        "mono_dark": render_svg("linklake-mark-mono-dark.svg", ".mono-dark-master.png", 512, 512, True),
        "mono_light": render_svg("linklake-mark-mono-light.svg", ".mono-light-master.png", 512, 512, True),
        "lockup_light": render_svg("linklake-lockup-on-light.svg", ".lockup-light-master.png", 1200, 320, True),
        "lockup_dark": render_svg("linklake-lockup-on-dark.svg", ".lockup-dark-master.png", 1200, 320, True),
    }

    with Image.open(masters["app"]).convert("RGBA") as app:
        resize(app, "app-icon-1024.png", (1024, 1024))
        resize(app, "app-icon-512.png", (512, 512))
        resize(app, "app-icon-256.png", (256, 256))
        resize(app, "app-icon-128.png", (128, 128))
        resize(app, "app-icon-64.png", (64, 64))
        resize(app, "apple-touch-icon-180.png", (180, 180))
        resize(app, "pwa-icon-192.png", (192, 192))
        resize(app, "pwa-icon-512.png", (512, 512))

    with Image.open(masters["maskable"]).convert("RGBA") as maskable:
        resize(maskable, "pwa-maskable-192.png", (192, 192))
        resize(maskable, "pwa-maskable-512.png", (512, 512))

    with Image.open(masters["favicon"]).convert("RGBA") as favicon:
        resize(favicon, "favicon-16.png", (16, 16))
        resize(favicon, "favicon-32.png", (32, 32))
        resize(favicon, "favicon-48.png", (48, 48))
        favicon.save(
            ROOT / "linklake.ico",
            format="ICO",
            sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)],
        )

    with Image.open(masters["mark"]).convert("RGBA") as mark:
        resize(mark, "linklake-mark-512.png", (512, 512))
        resize(mark, "linklake-mark-256.png", (256, 256))

    for key, prefix in (("mono_dark", "tray-dark"), ("mono_light", "tray-light")):
        with Image.open(masters[key]).convert("RGBA") as tray:
            for size in (16, 20, 24, 32):
                resize(tray, f"{prefix}-{size}.png", (size, size))

    for key, name in (("lockup_light", "lockup-on-light-1200.png"), ("lockup_dark", "lockup-on-dark-1200.png")):
        with Image.open(masters[key]).convert("RGBA") as lockup:
            lockup.save(PNG_DIR / name, format="PNG", optimize=True)

    for master in masters.values():
        master.unlink(missing_ok=True)


if __name__ == "__main__":
    export()
