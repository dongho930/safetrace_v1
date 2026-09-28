import io

from PIL import Image

from safetrace.preview import preview_image


def _png(tmp_path, img, name):
    p = tmp_path / name
    img.save(p, "PNG")
    return p


def test_photo_like_screenshot_becomes_smaller_jpeg(tmp_path):
    # 사진이 들어간 긴 페이지(잡음) → JPEG 가 훨씬 작다
    img = Image.effect_noise((1280, 3000), 60).convert("RGB")
    p = _png(tmp_path, img, "s001_observe.png")
    data, media = preview_image(p)
    assert media == "image/jpeg" and len(data) < p.stat().st_size / 2
    with Image.open(io.BytesIO(data)) as out:
        assert out.size == (1280, 3000)


def test_simple_screenshot_keeps_png_when_smaller(tmp_path):
    p = _png(tmp_path, Image.new("RGB", (1280, 800), "white"), "s002_after.png")
    data, media = preview_image(p)
    assert media == "image/png" and data == p.read_bytes()


def test_wide_image_is_downscaled(tmp_path):
    p = _png(tmp_path, Image.effect_noise((2560, 1600), 60).convert("RGB"), "s003_final.png")
    data, media = preview_image(p)
    with Image.open(io.BytesIO(data)) as out:
        assert out.size == (1280, 800)
