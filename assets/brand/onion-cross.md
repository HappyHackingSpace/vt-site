# Onion cut cross-section — primary brand mark

**Status: the brand mark (in use site-wide).** It replaced the earlier target-lock mark,
whose files have been removed. `index.html` in this folder shows every file made from
the mark, served at `/assets/brand/`.

Concentric onion layers (cut top-view) in brand language. Opaque disc + contrasting
rings + offset red core. Self-contained: works on any background (disc is opaque).

## Geometry (viewBox 0 0 48 48)
| part | cx | cy | r | role |
|------|----|----|---|------|
| disc | 24 | 24 | 18 | onion body (fill = skin colour) |
| ring 1 | 24 | 24 | 13.5 | layer (stroke 2.3) |
| ring 2 | 24.6 | 24.6 | 9 | layer (stroke 2.1) |
| ring 3 | 25.2 | 25.2 | 5 | layer (stroke 1.9) |
| core | 25.6 | 25.6 | 3 | red germ (fill #E8384A) — offset down-right |

The small down-right offset of each ring/core is deliberate: it reads as a real
onion's off-centre growth point, not a mechanical bullseye.

## Colourways
- Dark (cream on ink): disc `#EFE4C9`, rings `#0F1217`, core `#E8384A` → `onion-cross-dark.svg`
- Light (ink on light): disc `#17171A`, rings `#F7F7F5`, core `#E8384A` → `onion-cross-light.svg`
- On the site the mark is inline SVG and theme-adaptive via `app.css`:
  `.ok-disc` = `currentColor`, `.ok-ring` = `var(--bg)`, `.ok-core` = `var(--accent)`.

## Web / app icon set (`web/`)
| file | use |
|------|-----|
| `favicon.ico` (16/32/48), `favicon.svg`, `favicon-*.png` | browser tab |
| `apple-touch-icon.png` (180) | iOS home screen |
| `icon-192.png`, `icon-512.png` | PWA / Android |
| `maskable-512.png` | Android adaptive icon (mark inside the 80% safe circle) |
| `og-image.png` (1200×630) | social share card; source `og-source.html` |
| `vt-onion-black.svg`, `vt-onion-white.svg` | one-colour uses (print, stamps) |
| `site.webmanifest` | PWA manifest (root-absolute icon paths) |

App and maskable icons are **full colour on an ink tile**. Do not regenerate them with
`export_variants.py --web-icons` alone: its app-icon mode flattens the mark to one colour
and the rings disappear. Re-render `vt-onion-app-icon.svg` / `vt-onion-maskable.svg` with
`render_png.py` instead.
