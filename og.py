"""Per-lab social share image (1200x630) in the onion brand.

Optional: build.py calls render_lab() only when Pillow is importable (CI installs it).
Without Pillow every page falls back to the shared /og-image.png.
"""
import os
from PIL import Image, ImageDraw, ImageFilter, ImageFont

W, H, PAD = 1200, 630, 88
BG, BRIGHT, DIM, ACCENT, CREAM, CORE = '#0F1217', '#F4F7FB', '#979FAB', '#EB5160', '#EFE4C9', '#E8384A'
LINE, SURFACE = '#262D38', '#161A21'
SEV = {'critical': '#FF5C6C', 'high': '#FF9F45', 'medium': '#FFC24A', 'low': '#56D6A0'}

# first existing path wins: CI (Ubuntu, DejaVu) then macOS
SANS_BOLD = ['/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf',
             '/System/Library/Fonts/Supplemental/Arial Bold.ttf']
MONO = ['/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf',
        '/System/Library/Fonts/Menlo.ttc']
MONO_BOLD = ['/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf',
             '/System/Library/Fonts/Menlo.ttc']


def _font(paths, size):
    for p in paths:
        if os.path.exists(p):
            return ImageFont.truetype(p, size)
    return ImageFont.load_default(size)


def _rgb(hx):
    hx = hx.lstrip('#')
    return tuple(int(hx[i:i + 2], 16) for i in (0, 2, 4))


def onion(draw, cx, cy, s, disc=CREAM, ring=BG, core=CORE):
    """The brand mark (48-unit geometry from assets/brand/onion-cross.md) at scale s."""
    def circle(x, y, r, **kw):
        draw.ellipse([cx + (x - 24 - r) * s, cy + (y - 24 - r) * s,
                      cx + (x - 24 + r) * s, cy + (y - 24 + r) * s], **kw)
    circle(24, 24, 18, fill=disc)
    for x, r, w in ((24, 13.5, 2.3), (24.6, 9, 2.1), (25.2, 5, 1.9)):
        circle(x, x, r + w / 2, outline=ring, width=max(1, round(w * s)))
    circle(25.6, 25.6, 3, fill=core)


def _wrap(draw, text, font, width, max_lines):
    words, lines, cur = text.split(), [], ''
    for w in words:
        t = f'{cur} {w}'.strip()
        if draw.textlength(t, font=font) <= width:
            cur = t
        else:
            if cur:
                lines.append(cur)
            cur = w
    if cur:
        lines.append(cur)
    if len(lines) > max_lines:
        lines = lines[:max_lines]
        last = lines[-1]
        while last and draw.textlength(last + '…', font=font) > width:
            last = last[:-1]
        lines[-1] = last.rstrip() + '…'
    return lines


def render_lab(did, tid, name, sev, out_path):
    img = Image.new('RGB', (W, H), BG)

    # soft accent glow top-right + oversized faded mark bottom-right (brand texture)
    glow = Image.new('RGBA', (W, H), (0, 0, 0, 0))
    ImageDraw.Draw(glow).ellipse([760, -260, 1460, 300], fill=_rgb(CORE) + (46,))
    img.paste(glow.filter(ImageFilter.GaussianBlur(90)), (0, 0), glow.filter(ImageFilter.GaussianBlur(90)))
    ghost = Image.new('RGBA', (W, H), (0, 0, 0, 0))
    onion(ImageDraw.Draw(ghost), 1105, 575, 15, disc=_rgb(CREAM) + (22,), ring=(0, 0, 0, 0), core=_rgb(CORE) + (40,))
    img.paste(ghost, (0, 0), ghost)

    d = ImageDraw.Draw(img)

    # brand row
    onion(d, PAD + 20, PAD + 4, 1.05)
    d.text((PAD + 56, PAD + 4), 'Vulnerable Target', font=_font(SANS_BOLD, 30), fill=BRIGHT, anchor='lm')

    # catalogue number + severity badge
    y = 196
    f_id = _font(MONO_BOLD, 32)
    d.text((PAD, y), did, font=f_id, fill=ACCENT, anchor='lm')
    if sev in SEV:
        f_sev = _font(MONO_BOLD, 20)
        label = sev.upper()
        x0 = PAD + d.textlength(did, font=f_id) + 22
        tw = d.textlength(label, font=f_sev)
        col = _rgb(SEV[sev])
        wash = tuple(round(c * .15 + b * .85) for c, b in zip(col, _rgb(BG)))
        d.rounded_rectangle([x0, y - 18, x0 + tw + 24, y + 18], radius=6, fill=wash)
        d.text((x0 + 12, y), label, font=f_sev, fill=col, anchor='lm')

    # title (max 3 lines)
    f_t = _font(SANS_BOLD, 54)
    ty = 248
    for ln in _wrap(d, name, f_t, W - 2 * PAD, 3):
        d.text((PAD, ty), ln, font=f_t, fill=BRIGHT)
        ty += 66

    # run command + domain
    f_cmd = _font(MONO, 24)
    cmd = f'vt start --id {tid}'
    by = H - PAD - 6
    cw = d.textlength('$ ' + cmd, font=f_cmd)
    d.rounded_rectangle([PAD, by - 30, PAD + cw + 40, by + 30], radius=9, fill=SURFACE, outline=LINE)
    d.text((PAD + 20, by), '$', font=f_cmd, fill=ACCENT, anchor='lm')
    d.text((PAD + 20 + d.textlength('$ ', font=f_cmd), by), cmd, font=f_cmd, fill=BRIGHT, anchor='lm')
    d.text((W - PAD, by), 'vulnerabletarget.com', font=_font(SANS_BOLD, 22), fill=DIM, anchor='rm')

    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    img.save(out_path, 'PNG', optimize=True)
