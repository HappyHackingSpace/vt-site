# Vulnerable Target (vt-site)

[![Website](https://img.shields.io/badge/Website-vulnerabletarget.com-red)](https://vulnerabletarget.com)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

The catalogue behind [vulnerabletarget.com](https://vulnerabletarget.com): reproducible, intentionally
vulnerable labs (CVE reproductions, security benchmarks and app labs) that run locally with one command:

```sh
vt start --id <id>
```

Every lab is defined in [vt-templates](https://github.com/HappyHackingSpace/vt-templates) and started with
the [vt CLI](https://github.com/HappyHackingSpace/vt). This repository only turns that data into the website.

## How it works

`build.py` is a dependency-free static site generator. It reads `templates.json` and writes the whole site
to `dist/`:

| Output | What it is |
|---|---|
| `index.html` | Registry: search, filters, sort. The view is kept in the URL, so it can be shared. |
| `VT-YYYY-NNNNN/index.html` | One pre-rendered page per lab, with structured data (JSON-LD). |
| `vt-…/`, `detail.html` | Redirects for the URLs the previous site published, so shared links keep working. |
| `404.html`, `sitemap.xml`, `robots.txt` | The usual. |
| `llms.txt`, `labs.json` | Machine-readable catalogue for AI answer engines. |
| `og/<id>.png` | Per-lab share image, drawn by `og.py` when Pillow is installed (CI installs it). |

## Project structure

```
vt-site/
├── build.py              # site generator
├── og.py                 # per-lab share images (optional, needs Pillow)
├── assets/
│   ├── app.css           # design system (dark theme, tokens)
│   ├── brand/            # onion mark, icon set, share image
│   └── templates.json    # fallback data; CI replaces it with the latest from vt-templates
├── docs/SCHEMA.md        # template field reference
└── .github/workflows/
    └── deploy.yml        # build + publish to GitHub Pages
```

## Run it locally

```sh
python3 build.py
python3 -m http.server 8791 -d dist
```

Then open <http://127.0.0.1:8791/>. With a `vt-templates` checkout next to this repository, `build.py` uses
its fresher `templates.json` automatically.

## Deploy

Pushing to `main`, or a `templates-updated` event from vt-templates, runs `deploy.yml`: it fetches the latest
`templates.json`, runs `build.py` and publishes `dist/` to GitHub Pages.

## Contributing

To add or fix a lab, open a pull request on [vt-templates](https://github.com/HappyHackingSpace/vt-templates).
For the website itself, pull requests here are welcome.

## License

MIT.

---

Made with 💀 by [HappyHackingSpace](https://github.com/HappyHackingSpace)
