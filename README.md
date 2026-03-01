# Vulnerable Targets (VT) 🎯

[![Website](https://img.shields.io/badge/Website-vulnerabletarget.com-red)](https://vulnerabletarget.com)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

> Next-generation vulnerability testing platform - A curated catalog of vulnerable applications, CVE PoCs, and security research templates.

## 🚀 Live Demo

**Website:** [https://vulnerabletarget.com](https://vulnerabletarget.com)

## 📋 About

Vulnerable Targets (VT) is an open-source catalog designed for security researchers, penetration testers, and CTF enthusiasts. It provides:

- 🛡️ **Vulnerable Applications** - Pre-configured vulnerable apps for practice
- 🐛 **CVE PoCs** - Proof-of-Concept exploits for known vulnerabilities
- 🧪 **Security Benchmarks** - Testing environments for security tools
- 🐳 **Docker Templates** - Ready-to-deploy containerized labs

## 🏗️ Project Structure

```
vt-site/
├── index.html          # Main page with search & catalog
├── detail.html         # Vulnerability details page
├── 404.html           # Custom 404 error page
├── assets/
│   ├── css/style.css  # Styling
│   └── templates.json # Vulnerability database
├── CNAME              # Custom domain config
└── .github/           # GitHub Actions workflows
```

## 🛠️ Tech Stack

- **Frontend:** Vanilla HTML5, CSS3, JavaScript
- **Data:** JSON-based API (templates.json)
- **Hosting:** GitHub Pages
- **Domain:** Custom domain via CNAME

## 🚀 Getting Started

### Local Development

```bash
# Clone the repository
git clone https://github.com/HappyHackingSpace/VT.git
cd vt-site

# Serve locally (Python 3)
python -m http.server 8000

# Or with Node.js
npx serve .
```

Then open [http://localhost:8000](http://localhost:8000)

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📄 License

This project is licensed under the MIT License.

---

Made with 💀 by [HappyHackingSpace](https://github.com/HappyHackingSpace)
