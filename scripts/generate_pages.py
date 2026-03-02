#!/usr/bin/env python3
"""Generate per-entry HTML pages with OG meta tags and OG images for link previews."""

import json
import math
import os
import random
import sys
from html import escape

try:
    from PIL import Image, ImageDraw, ImageFont
    HAS_PIL = True
except ImportError:
    HAS_PIL = False
    print("Warning: Pillow not installed. OG images will not be generated.")

# OG Image dimensions
WIDTH = 1200
HEIGHT = 630

# Theme colors (from style.css)
BG_COLOR = (0, 0, 0)
BORDER_COLOR = (31, 31, 31)
TEXT_COLOR = (192, 192, 192)
TEXT_DIM = (80, 80, 80)
TEXT_BRIGHT = (255, 255, 255)
ACCENT_COLOR = (136, 136, 136)
DANGER_COLOR = (255, 51, 85)
WARNING_COLOR = (255, 170, 0)

# Matrix spiral characters
MATRIX_CHARS = 'アイウエオカキクケコサシスセソタチツテトナニヌネノハヒフヘホマミムメモヤユヨラリルレロワヲン0123456789ABCDEF<>{}[]'


def get_severity_color(score):
    try:
        s = float(score)
        if s >= 9.0:
            return DANGER_COLOR
        elif s >= 7.0:
            return (255, 100, 50)
        elif s >= 4.0:
            return WARNING_COLOR
        else:
            return (34, 197, 94)
    except (ValueError, TypeError):
        return TEXT_DIM


def get_font(size, bold=False):
    font_paths = [
        '/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf' if bold else '/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf',
        '/usr/share/fonts/truetype/liberation/LiberationMono-Bold.ttf' if bold else '/usr/share/fonts/truetype/liberation/LiberationMono-Regular.ttf',
        '/System/Library/Fonts/SFMono-Bold.otf' if bold else '/System/Library/Fonts/SFMono-Regular.otf',
        '/System/Library/Fonts/Menlo.ttc',
        '/System/Library/Fonts/Monaco.ttf',
    ]
    for path in font_paths:
        if os.path.exists(path):
            try:
                return ImageFont.truetype(path, size)
            except (OSError, IOError):
                continue
    return ImageFont.load_default()


def wrap_text(draw, text, font, max_width):
    words = text.split()
    lines = []
    current_line = ""
    for word in words:
        test_line = f"{current_line} {word}".strip()
        bbox = draw.textbbox((0, 0), test_line, font=font)
        if bbox[2] - bbox[0] <= max_width:
            current_line = test_line
        else:
            if current_line:
                lines.append(current_line)
            current_line = word
    if current_line:
        lines.append(current_line)
    return lines


def draw_matrix_spiral(img, seed=42):
    """Draw a matrix spiral pattern as background."""
    overlay = Image.new('RGBA', (WIDTH, HEIGHT), (0, 0, 0, 0))
    draw = ImageDraw.Draw(overlay)
    font = get_font(16)

    rng = random.Random(seed)
    cx, cy = WIDTH // 2, HEIGHT // 2
    max_radius = math.sqrt(cx ** 2 + cy ** 2)

    # Spiral arms of characters
    num_arms = 7
    chars_per_arm = 180
    for arm in range(num_arms):
        base_angle = (2 * math.pi / num_arms) * arm
        for i in range(chars_per_arm):
            t = i / chars_per_arm
            radius = t * max_radius * 1.1
            angle = base_angle + t * 4 * math.pi  # ~2 full rotations

            x = cx + radius * math.cos(angle)
            y = cy + radius * math.sin(angle)

            if x < -20 or x > WIDTH + 20 or y < -20 or y > HEIGHT + 20:
                continue

            char = rng.choice(MATRIX_CHARS)

            # Fade: brighter near center, dimmer at edges
            brightness = max(0.3, 1.0 - (radius / max_radius))
            r = int(DANGER_COLOR[0] * brightness * 0.7)
            g = int(DANGER_COLOR[1] * brightness * 0.3)
            b = int(DANGER_COLOR[2] * brightness * 0.3)
            alpha = int(255 * brightness * 0.7)

            draw.text((x, y), char, fill=(r, g, b, alpha), font=font)

    # Scattered random chars for density
    for _ in range(250):
        x = rng.randint(0, WIDTH)
        y = rng.randint(0, HEIGHT)
        char = rng.choice(MATRIX_CHARS)
        dist = math.sqrt((x - cx) ** 2 + (y - cy) ** 2)
        brightness = max(0.2, 1.0 - (dist / max_radius))
        r = int(DANGER_COLOR[0] * brightness * 0.6)
        g = int(DANGER_COLOR[1] * brightness * 0.25)
        b = int(DANGER_COLOR[2] * brightness * 0.25)
        alpha = int(255 * brightness * 0.6)
        draw.text((x, y), char, fill=(r, g, b, alpha), font=font)

    # Composite onto base image
    img_rgba = img.convert('RGBA')
    img_rgba = Image.alpha_composite(img_rgba, overlay)
    return img_rgba.convert('RGB')


def generate_og_image(template, output_path):
    if not HAS_PIL:
        return

    info = template.get('info', {})
    tid = template['id']
    name = info.get('name', tid)
    cve = info.get('cve', '')
    cvss = info.get('cvss', {})
    score = cvss.get('score', '')
    category = template.get('category', '')

    img = Image.new('RGB', (WIDTH, HEIGHT), BG_COLOR)

    # Matrix spiral background
    img = draw_matrix_spiral(img, seed=hash(tid) % 100000)
    draw = ImageDraw.Draw(img)

    # Top/bottom accent lines
    draw.rectangle([(0, 0), (WIDTH, 3)], fill=ACCENT_COLOR)
    draw.rectangle([(0, HEIGHT - 3), (WIDTH, HEIGHT)], fill=ACCENT_COLOR)

    font_brand = get_font(28, bold=True)
    font_title = get_font(36, bold=True)
    font_desc = get_font(22)
    font_id = get_font(20)
    font_category = get_font(18, bold=True)
    font_author = get_font(20, bold=True)

    # Branding
    y_pos = 40
    draw.text((60, y_pos), "VULNERABLE TARGETS", fill=TEXT_BRIGHT, font=font_brand)

    # Separator
    y_pos += 50
    draw.line([(60, y_pos), (WIDTH - 60, y_pos)], fill=BORDER_COLOR, width=1)

    # VT ID + Category on same line
    y_pos += 25
    formatted_id = 'VT-' + tid[3:] if tid.lower().startswith('vt-') else tid
    draw.text((60, y_pos), f"0x{formatted_id}", fill=ACCENT_COLOR, font=font_id)

    # Category - right of VT ID
    if category:
        id_bbox = draw.textbbox((0, 0), f"0x{formatted_id}", font=font_id)
        id_width = id_bbox[2] - id_bbox[0]
        draw.text((60 + id_width + 20, y_pos + 3), f"// {category.upper()}", fill=TEXT_BRIGHT, font=font_category)

    # CVE badge - right aligned
    if cve:
        cve_bbox = draw.textbbox((0, 0), cve, font=font_id)
        cve_width = cve_bbox[2] - cve_bbox[0]
        draw.text((WIDTH - 60 - cve_width, y_pos), cve, fill=DANGER_COLOR, font=font_id)

    # Vulnerability name (word-wrapped, max 2 lines)
    y_pos += 60
    lines = wrap_text(draw, name, font_title, WIDTH - 120)
    if len(lines) > 2:
        lines = lines[:2]
        lines[1] = lines[1][:-3] + "..." if len(lines[1]) > 3 else "..."
    for line in lines:
        draw.text((60, y_pos), line, fill=TEXT_BRIGHT, font=font_title)
        y_pos += 48

    # Description (word-wrapped, fill remaining space)
    description = info.get('description', '')
    if description:
        y_pos += 16
        available_h = (HEIGHT - 120) - y_pos
        max_lines = max(1, available_h // 32)
        desc_lines = wrap_text(draw, description, font_desc, WIDTH - 120)
        if len(desc_lines) > max_lines:
            desc_lines = desc_lines[:max_lines]
            desc_lines[-1] = desc_lines[-1][:-3] + "..." if len(desc_lines[-1]) > 3 else "..."
        for line in desc_lines:
            draw.text((60, y_pos), line, fill=TEXT_COLOR, font=font_desc)
            y_pos += 32

    # Bottom section
    bottom_y = HEIGHT - 120
    draw.line([(60, bottom_y), (WIDTH - 60, bottom_y)], fill=BORDER_COLOR, width=1)
    bottom_y += 20

    # Author
    author = info.get('author', '')
    if author:
        draw.text((60, bottom_y + 8), f"by {author}", fill=TEXT_BRIGHT, font=font_author)

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    img.save(output_path, 'PNG', optimize=True)


def generate_default_og_image(output_path):
    if not HAS_PIL:
        return

    img = Image.new('RGB', (WIDTH, HEIGHT), BG_COLOR)
    img = draw_matrix_spiral(img, seed=777)
    draw = ImageDraw.Draw(img)

    draw.rectangle([(0, 0), (WIDTH, 3)], fill=ACCENT_COLOR)
    draw.rectangle([(0, HEIGHT - 3), (WIDTH, HEIGHT)], fill=ACCENT_COLOR)

    font_brand = get_font(48, bold=True)
    font_sub = get_font(22)
    font_desc = get_font(18)

    brand_text = "VULNERABLE TARGETS"
    bbox = draw.textbbox((0, 0), brand_text, font=font_brand)
    x = (WIDTH - (bbox[2] - bbox[0])) // 2
    y = HEIGHT // 2 - 80
    draw.text((x, y), brand_text, fill=TEXT_BRIGHT, font=font_brand)

    sub_text = "// Security Research Templates Catalog //"
    bbox = draw.textbbox((0, 0), sub_text, font=font_sub)
    x = (WIDTH - (bbox[2] - bbox[0])) // 2
    draw.text((x, y + 70), sub_text, fill=ACCENT_COLOR, font=font_sub)

    desc_text = "Explore vulnerable applications and CVE PoCs"
    bbox = draw.textbbox((0, 0), desc_text, font=font_desc)
    x = (WIDTH - (bbox[2] - bbox[0])) // 2
    draw.text((x, y + 120), desc_text, fill=TEXT_DIM, font=font_desc)

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    img.save(output_path, 'PNG', optimize=True)


def format_id(tid):
    if tid.lower().startswith('vt-'):
        return 'VT-' + tid[3:]
    return tid


def generate_html_page(template, output_dir):
    tid = template['id']
    info = template.get('info', {})
    name = escape(info.get('name', tid))
    description = escape((info.get('description', f'Technical analysis and PoC for {tid}'))[:200])
    cve = info.get('cve', '')

    title = f"{cve} - {name} // VT" if cve else f"{name} // VT"
    display_id = format_id(tid)
    og_image_url = f"https://vulnerabletarget.com/og/{tid}.png"
    canonical_url = f"https://vulnerabletarget.com/{display_id}"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="refresh" content="0;url=/detail.html?id={escape(tid)}">
    <title>{title}</title>
    <meta name="description" content="{description}">
    <meta property="og:type" content="article">
    <meta property="og:url" content="{canonical_url}">
    <meta property="og:title" content="{title}">
    <meta property="og:description" content="{description}">
    <meta property="og:image" content="{og_image_url}">
    <meta property="og:image:width" content="1200">
    <meta property="og:image:height" content="630">
    <meta name="twitter:card" content="summary_large_image">
    <meta name="twitter:title" content="{title}">
    <meta name="twitter:description" content="{description}">
    <meta name="twitter:image" content="{og_image_url}">
    <link rel="canonical" href="{canonical_url}">
</head>
<body>
    <p>Redirecting...</p>
</body>
</html>"""

    # Create both lowercase (actual ID) and uppercase VT- versions
    dirs_to_create = [tid]
    upper_id = format_id(tid)
    if upper_id != tid:
        dirs_to_create.append(upper_id)

    for dir_name in dirs_to_create:
        page_dir = os.path.join(output_dir, dir_name)
        os.makedirs(page_dir, exist_ok=True)
        with open(os.path.join(page_dir, 'index.html'), 'w') as f:
            f.write(html)


def main():
    templates_path = os.path.join('assets', 'templates.json')

    if not os.path.exists(templates_path):
        print(f"Error: {templates_path} not found")
        sys.exit(1)

    with open(templates_path, 'r') as f:
        templates = json.load(f)

    print(f"Processing {len(templates)} templates...")

    # Default OG image
    default_og_path = os.path.join('assets', 'images', 'og-image.png')
    generate_default_og_image(default_og_path)
    print(f"Generated default OG image: {default_og_path}")

    # Per-entry pages and images
    for i, template in enumerate(templates):
        tid = template['id']
        generate_html_page(template, '.')
        og_path = os.path.join('og', f'{tid}.png')
        generate_og_image(template, og_path)

        if (i + 1) % 50 == 0:
            print(f"  Processed {i + 1}/{len(templates)}...")

    print(f"Done! Generated {len(templates)} pages and OG images.")


if __name__ == '__main__':
    main()
