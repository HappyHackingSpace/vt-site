#!/usr/bin/env python3
"""Static site generator for vulnerabletarget.com.

Reads templates.json and writes the whole site to dist/ (wiped on every run):
  dist/index.html                  registry home (search, facets, sort; view state in the URL)
  dist/VT-YYYY-NNNNN/index.html    one pre-rendered page per lab, clean URL
  dist/vt-…/, dist/detail.html     redirects for the URLs the previous site published
  dist/404.html, sitemap.xml, robots.txt, llms.txt, labs.json, icons, OG images

Local:  python3 build.py && python3 -m http.server 8791 -d dist
CI:     .github/workflows/deploy.yml runs this and publishes dist/ to GitHub Pages.
"""
import json, os, shutil, html, sys, re

HERE = os.path.dirname(os.path.abspath(__file__))
try:  # per-lab share images need Pillow (CI installs it); otherwise every page uses /og-image.png
    sys.path.insert(0, HERE)
    import og
except ImportError:
    og = None
# local: a vt-templates checkout next to vt-site wins (freshest data);
# CI: deploy.yml copies the upstream file to assets/templates.json
CANDIDATES = [
    os.path.join(HERE, '..', 'vt-templates', '.assets', 'templates.json'),
    os.path.join(HERE, 'assets', 'templates.json'),
]
DIST = os.path.join(HERE, 'dist')
SITE = "https://vulnerabletarget.com"

def e(x):
    return html.escape(str(x if x is not None else ''))

def disp_id(tid):
    return 'VT-' + tid[3:] if tid.lower().startswith('vt-') else tid

def year_of(t):
    cve = t.get('info', {}).get('cve', '') or ''
    parts = (cve or t.get('id', '')).split('-')
    return parts[1] if len(parts) > 1 and parts[1].isdigit() else ''

def sev_of(t):
    return ((t.get('info', {}).get('cvss') or {}).get('severity') or '').lower()

def refs_of(t):
    return t.get('references') or t.get('info', {}).get('references') or []

def nuclei_of(t):
    poc = t.get('poc') or {}
    return poc.get('nuclei') or []

SEV_RANK = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}
NEW_DAYS = 30   # "New" badge window, relative to the build date (CI rebuilds on every template update)
BUILD_DATE = __import__('datetime').date.today()
ISSUES = 'https://github.com/HappyHackingSpace/vt-templates/issues/new'

def newest_first(ts):
    return sorted(ts, key=lambda x: str(x.get('added_date') or ''), reverse=True)

def is_new(t):
    try:
        added = __import__('datetime').date.fromisoformat(str(t.get('added_date'))[:10])
    except ValueError:
        return False
    return (BUILD_DATE - added).days <= NEW_DAYS

def related_index(ts, k=3):
    """{tid: [up to k related templates]} scored on shared targets, CWE and tags.
    Signals carried by >25% of labs (e.g. a tag every benchmark has) say nothing, so they are dropped."""
    idlike = re.compile(r'^((cve|ghsa|ghsl)(-\d{4}(-\d+)?)?|\d{4})$')   # "cve", "cve-2026", "cve-2026-1234": filing labels, not topics
    def sig(t):
        info = t.get('info', {})
        return {('t', x.lower()) for x in (info.get('targets') or [])} | \
               {('g', x.lower()) for x in (info.get('tags') or []) if not idlike.match(x.lower())} | \
               ({('c', str(info['cwe']).upper())} if info.get('cwe') else set())
    sigs = {t['id']: sig(t) for t in ts}
    df = {}
    for s in sigs.values():
        for x in s:
            df[x] = df.get(x, 0) + 1
    common = {x for x, n in df.items() if n > len(ts) * 0.25}
    weight = {'t': 3, 'c': 3, 'g': 1}
    rank = {t['id']: i for i, t in enumerate(newest_first(ts))}
    out = {}
    for t in ts:
        mine = sigs[t['id']] - common
        scored = []
        for o in ts:
            if o['id'] == t['id']:
                continue
            s = sum(weight[x[0]] for x in mine & sigs[o['id']])
            if s >= 2:
                scored.append((-s, rank[o['id']], o))
        out[t['id']] = [o for _, _, o in sorted(scored, key=lambda x: x[:2])[:k]]
    return out

# ---------------- SEO / structured data ----------------
BRAND = 'Vulnerable Target'
HOME_DESC = ('Reproducible, intentionally vulnerable labs: CVE reproductions, security benchmarks and app labs. '
             'Run any of them locally with one command: vt start --id <id>.')
ORG_ID, SITE_ID = SITE + '/#org', SITE + '/#website'
ORG = {'@type': 'Organization', '@id': ORG_ID, 'name': 'HappyHackingSpace',
       'url': 'https://github.com/HappyHackingSpace', 'logo': 'https://github.com/HappyHackingSpace.png'}
WEBSITE = {'@type': 'WebSite', '@id': SITE_ID, 'name': BRAND, 'url': SITE + '/', 'description': HOME_DESC,
           'inLanguage': 'en', 'publisher': {'@id': ORG_ID}}

def meta_desc(s, n=155):
    """One line, cut on a word boundary (search snippets show ~155 chars)."""
    s = ' '.join(str(s or '').split())
    if len(s) <= n:
        return s
    return s[:n].rsplit(' ', 1)[0].rstrip(' ,;:-–—(') + '…'

def ref_id(t):
    info = t.get('info', {})
    return info.get('cve') or info.get('ghsa') or info.get('ghsl') or ''

def page_title(t):
    """CVE/advisory first (what people search for), brand last (what SERPs truncate)."""
    info = t.get('info', {}); name = str(info.get('name') or t['id']).strip(); ref = ref_id(t)
    if ref:
        name = re.sub(r'\s*\(' + re.escape(ref) + r'\)\s*$', '', name)   # no "CVE-x: … (CVE-x)"
        head = name if ref in name else f'{ref}: {name}'
        return f'{head} – PoC lab | {BRAND}'
    kind = {'Benchmark': 'benchmark lab', 'Lab': 'vulnerable app lab'}.get(info.get('type'), 'lab')
    return f'{name} – {kind} | {BRAND}'

def iso_date(v):
    try:
        return __import__('datetime').date.fromisoformat(str(v)[:10]).isoformat()
    except ValueError:
        return ''

def jsonld(*nodes):
    data = json.dumps({'@context': 'https://schema.org', '@graph': list(nodes)}, ensure_ascii=False, separators=(',', ':'))
    return '<script type="application/ld+json">' + data.replace('</', '<\\/') + '</script>\n'

def lab_jsonld(t, url, ogimg, desc):
    info = t.get('info', {}); did = disp_id(t['id'])
    about = []
    if info.get('cve'):
        about.append({'@type': 'Thing', 'name': info['cve'], 'sameAs': f"https://nvd.nist.gov/vuln/detail/{info['cve']}"})
    if info.get('ghsa'):
        about.append({'@type': 'Thing', 'name': info['ghsa'], 'sameAs': f"https://github.com/advisories/{info['ghsa']}"})
    for n in re.findall(r'CWE-(\d+)', str(info.get('cwe') or '')):
        about.append({'@type': 'Thing', 'name': f'CWE-{n}', 'sameAs': f'https://cwe.mitre.org/data/definitions/{n}.html'})
    author = str(info.get('author') or '')
    art = {'@type': 'TechArticle', '@id': url + '#article', 'headline': str(info.get('name') or did)[:110],
           'description': desc, 'url': url, 'mainEntityOfPage': url, 'image': ogimg, 'inLanguage': 'en',
           'author': {'@id': ORG_ID} if author in ('', 'hhsteam') else {'@type': 'Person', 'name': author},
           'publisher': {'@id': ORG_ID}, 'isPartOf': {'@id': SITE_ID}}
    if iso_date(t.get('added_date')):
        art['datePublished'] = iso_date(t.get('added_date'))
    if info.get('tags'):
        art['keywords'] = ', '.join(map(str, info['tags']))
    if about:
        art['about'] = about
    crumbs = {'@type': 'BreadcrumbList', 'itemListElement': [
        {'@type': 'ListItem', 'position': 1, 'name': 'Targets', 'item': SITE + '/'},
        {'@type': 'ListItem', 'position': 2, 'name': did, 'item': url}]}
    return jsonld(art, crumbs, ORG, WEBSITE)

def issue_url(t):
    from urllib.parse import urlencode
    tid = t['id']; did = disp_id(tid); name = t.get('info', {}).get('name', tid)
    body = (f"Lab: {did} ({SITE}/{did}/)\nCommand: vt start --id {tid}\n\n"
            "**What happened?**\n\n\n**What did you expect?**\n\n\n**vt version and OS**\n")
    return ISSUES + '?' + urlencode({'title': f'[{did}] Problem with lab: {name}', 'body': body})

# ---- lightweight syntax highlighting for HTTP request/response + code ----
def _hl_json(body):
    s = html.escape(body)
    s = re.sub(r'(&quot;[^&]*?&quot;)(\s*:)', r'<span class="c-key">\1</span>\2', s)
    s = re.sub(r'(:\s*)(&quot;[^&]*?&quot;)', r'\1<span class="c-str">\2</span>', s)
    s = re.sub(r'(:\s*)(-?\d+(?:\.\d+)?)', r'\1<span class="c-num">\2</span>', s)
    s = re.sub(r'(:\s*)(true|false|null)\b', r'\1<span class="c-bool">\2</span>', s)
    return s

def _hl_body(body):
    b = body.strip()
    if b[:1] in '{[':
        return _hl_json(body)
    out = []
    for ln in body.split('\n'):
        if ln.startswith('----'):
            out.append(f'<span class="c-comment">{html.escape(ln)}</span>')
        elif '<?php' in ln or '?>' in ln or '$_' in ln:
            out.append(f'<span class="c-php">{html.escape(ln)}</span>')
        elif re.match(r'^[A-Za-z0-9-]+:\s', ln):
            m = re.match(r'^([A-Za-z0-9-]+):\s*(.*)$', ln)
            out.append(f'<span class="c-hname">{html.escape(m.group(1))}</span>: {html.escape(m.group(2))}')
        else:
            out.append(html.escape(ln))
    return '\n'.join(out)

def inline(txt):
    """Escape, then render `backtick` spans as inline code."""
    t = html.escape(str(txt))
    return re.sub(r'`([^`]+)`', r'<code class="ic">\1</code>', t)

def prose(s):
    """Reflow prose: single newlines -> spaces, blank lines -> paragraphs,
    list-like blocks -> <ul>. Fixes hard-wrapped source text rendering ragged."""
    s = str(s or '').strip()
    if not s:
        return ''
    out = []
    for blk in re.split(r'\n\s*\n', s):
        ne = [ln for ln in blk.split('\n') if ln.strip()]
        if not ne:
            continue
        listish = sum(1 for ln in ne if re.match(r'^\s*([-*•]|\d+[.)])\s+', ln))
        if len(ne) > 1 and listish >= len(ne) - 1 and listish >= 2:
            items = ''.join(f'<li>{inline(re.sub(r"^\\s*([-*•]|\\d+[.)])\\s+", "", ln.strip()))}</li>' for ln in ne)
            out.append(f'<ul class="plain">{items}</ul>')
        else:
            out.append(f'<p>{inline(" ".join(ln.strip() for ln in ne))}</p>')
    return ''.join(out)

def hl_http(text):
    lines = text.rstrip('\n').split('\n')
    out, in_body, body = [], False, []
    for i, ln in enumerate(lines):
        if in_body:
            body.append(ln); continue
        if ln.strip() == '' and i > 0:
            in_body = True; out.append(''); continue
        m = re.match(r'^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(\S+)\s+(HTTP/\d(?:\.\d)?)\s*$', ln)
        if m:
            out.append(f'<span class="c-method">{html.escape(m.group(1))}</span> <span class="c-path">{html.escape(m.group(2))}</span> <span class="c-ver">{html.escape(m.group(3))}</span>'); continue
        m = re.match(r'^(HTTP/\d(?:\.\d)?)\s+(\d{3})\s*(.*)$', ln)
        if m:
            cls = 'c-ok' if int(m.group(2)) < 400 else 'c-err'
            out.append(f'<span class="c-ver">{html.escape(m.group(1))}</span> <span class="{cls}">{html.escape(m.group(2))} {html.escape(m.group(3))}</span>'); continue
        m = re.match(r'^([A-Za-z0-9-]+):\s*(.*)$', ln)
        if m:
            out.append(f'<span class="c-hname">{html.escape(m.group(1))}</span>: <span class="c-hval">{html.escape(m.group(2))}</span>'); continue
        out.append(html.escape(ln))
    res = '\n'.join(out)
    if in_body and any(x.strip() for x in body):
        res += '\n' + _hl_body('\n'.join(body))
    return res

HEAD = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="icon" href="/favicon.ico" sizes="48x48">
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<link rel="apple-touch-icon" href="/apple-touch-icon.png">
<link rel="manifest" href="/site.webmanifest">
<link rel="alternate" type="application/rss+xml" title="Vulnerable Target: new labs" href="/feed.xml">
<meta name="theme-color" content="#0F1217">
<meta name="color-scheme" content="dark">
<title>{title}</title>
<meta name="description" content="{desc}">
<link rel="canonical" href="{canonical}">
<meta property="og:title" content="{title}">
<meta property="og:description" content="{desc}">
<meta property="og:type" content="{ogtype}">
<meta property="og:url" content="{canonical}">
<meta property="og:site_name" content="Vulnerable Target">
<meta property="og:image" content="{ogimg}">
<meta property="og:image:width" content="1200">
<meta property="og:image:height" content="630">
<meta property="og:image:alt" content="Vulnerable Target: spin up a vulnerable target from your terminal">
<meta name="twitter:card" content="summary_large_image">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Bricolage+Grotesque:opsz,wght@12..96,600;12..96,700;12..96,800&family=Hanken+Grotesk:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap">
<link rel="stylesheet" href="{css}">
{extra}</head>
<body>
"""

YEAR = __import__('datetime').date.today().year

MATRIX_JS = """<script>
(function(){
  if(window.matchMedia&&window.matchMedia('(prefers-reduced-motion: reduce)').matches)return;
  var c=document.getElementById('hero-matrix'); if(!c)return;
  var ctx=c.getContext('2d'), hero=c.parentElement, drops=[], cols=0, fs=14;
  var chars='アイウエオカキクケサシスセソ0123456789ABCDEF<>{}[]=/\\\\'.split('');
  // under the magnetic cursor, glyphs flip to letters of the brand words
  var brand='HHS HAPPYHACKINGSPACE VT VULNERABLETARGET'.replace(/ /g,'').split('');
  function col(){var s=getComputedStyle(document.documentElement);
    return {m:s.getPropertyValue('--matrix').trim()||'232,56,74',
            a:parseFloat(s.getPropertyValue('--matrix-alpha'))||0.4,
            bg:s.getPropertyValue('--bg').trim()||'#0F1217',
            hi:s.getPropertyValue('--matrix-hi').trim()||'210,224,240'};}
  var C=col();
  function size(){c.width=window.innerWidth; c.height=window.innerHeight;
    cols=Math.ceil(c.width/fs); drops=[]; for(var i=0;i<cols;i++)drops[i]=Math.random()*(-c.height/fs);}
  // WCAG 2.2.2: motion that starts by itself must stop within 5 s. The rain runs 5 s on load, then
  // freezes into a static texture; pointer movement over the background (a user action) wakes it briefly.
  var timer=null, stopAt=0;
  function tick(){ draw(); if(Date.now()>=stopAt){ clearInterval(timer); timer=null; } }
  function run(ms){ stopAt=Math.max(stopAt, Date.now()+ms); if(!timer) timer=setInterval(tick,55); }
  size(); window.addEventListener('resize',function(){ size(); run(5000); });   // resizing clears the canvas: refill
  var mx=-9999,my=-9999,R=200;
  // magnetic cursor: only in the BACKGROUND / margins — disabled while the cursor is over a readable region
  window.addEventListener('mousemove',function(ev){
    var t=ev.target;
    if(t && t.closest && t.closest('.main, aside, footer, .filterbar, .card')){ mx=-9999; my=-9999; return; }
    mx=ev.clientX; my=ev.clientY; run(1500);
  });
  window.addEventListener('mouseout',function(ev){if(!ev.relatedTarget){mx=-9999;my=-9999;}});
  function draw(){
    ctx.fillStyle='rgba('+hexToRgb(C.bg)+',0.08)'; ctx.fillRect(0,0,c.width,c.height);
    ctx.font=fs+'px JetBrains Mono, monospace';
    for(var i=0;i<drops.length;i++){
      var ch=chars[Math.floor(Math.random()*chars.length)];
      var x=i*fs, y=drops[i]*fs;
      var fade=Math.max(0.15, 1-(y/c.height));
      var a=C.a*fade, col=C.m;
      if(mx>-9000){ var dx=mx-x, dy=my-y, d=Math.sqrt(dx*dx+dy*dy);
        if(d<R){ var tt=1-d/R, pull=tt*tt*0.55;   // glyphs bend / gather toward the cursor
          x+=dx*pull; y+=dy*pull;
          a=Math.min(1, a+tt*0.8); col=C.hi;       // highlight (theme-aware), not red
          ch=brand[Math.floor(Math.random()*brand.length)]; } }   // flip to brand letters
      ctx.fillStyle='rgba('+col+','+a+')';
      ctx.fillText(ch, x, y);
      if(y>c.height && Math.random()>0.975) drops[i]=0;
      drops[i]++;
    }
  }
  function hexToRgb(h){h=h.replace('#','');if(h.length===3)h=h.split('').map(function(x){return x+x;}).join('');
    var n=parseInt(h,16);return ((n>>16)&255)+','+((n>>8)&255)+','+(n&255);}
  run(5000);
})();
</script>
"""

FOOTER = """<footer><div class="wrap">
  <div class="fgrid">
    <div class="fbrand">
      <a class="brand" href="{root}"><span class="mk" aria-hidden="true"><svg viewBox="0 0 48 48" fill="none"><circle class="ok-disc" cx="24" cy="24" r="18"/><circle class="ok-ring" cx="24" cy="24" r="13.5" stroke-width="2.3"/><circle class="ok-ring" cx="24.6" cy="24.6" r="9" stroke-width="2.1"/><circle class="ok-ring" cx="25.2" cy="25.2" r="5" stroke-width="1.9"/><circle class="ok-core" cx="25.6" cy="25.6" r="3"/></svg></span> Vulnerable Target</a>
      <p>Reproducible vulnerable labs for learning, research and tool testing.</p>
    </div>
    <div class="fcol">
      <h2>Explore</h2>
      <a href="https://github.com/HappyHackingSpace/vt-templates" target="_blank" rel="noopener">Templates</a>
      <a href="https://github.com/HappyHackingSpace/vt" target="_blank" rel="noopener">vt CLI</a>
      <a href="/feed.xml"><svg class="rss" viewBox="0 0 24 24" aria-hidden="true"><path d="M4 11a9 9 0 0 1 9 9"/><path d="M4 4a16 16 0 0 1 16 16"/><circle cx="5" cy="19" r="1.5"/></svg>New labs (RSS)</a>
    </div>
    <div class="fcol">
      <h2>Contribute</h2>
      <a href="https://github.com/HappyHackingSpace/vt-templates/issues/new" target="_blank" rel="noopener">Request or report a lab</a>
      <a href="https://github.com/HappyHackingSpace/vt-templates/pulls" target="_blank" rel="noopener">Submit a template</a>
      <a href="https://github.com/HappyHackingSpace" target="_blank" rel="noopener">HappyHackingSpace on GitHub</a>
    </div>
  </div>
  <p class="legal"><span class="legal-badge">Authorised use only</span> These environments are intentionally vulnerable. Run them only on your own machine or on systems you have explicit written permission to test. You are solely responsible for how you use them — never point VT tooling or payloads at systems you do not own or are not authorised to assess.</p>
  <div class="fbottom">
    <a class="madeby" href="https://github.com/HappyHackingSpace" target="_blank" rel="noopener">
      Made with <span class="heart">&#9829;</span> by
      <img class="hhs-logo" src="https://github.com/HappyHackingSpace.png" alt="" width="18" height="18" loading="lazy">
      HappyHackingSpace
    </a>
    <span class="copyr"><span class="mk mk-sm" aria-hidden="true"><svg viewBox="0 0 48 48" fill="none"><circle class="ok-disc" cx="24" cy="24" r="18"/><circle class="ok-ring" cx="24" cy="24" r="13.5" stroke-width="2.3"/><circle class="ok-ring" cx="24.6" cy="24.6" r="9" stroke-width="2.1"/><circle class="ok-ring" cx="25.2" cy="25.2" r="5" stroke-width="1.9"/><circle class="ok-core" cx="25.6" cy="25.6" r="3"/></svg></span>&copy; {year} Vulnerable Target</span>
  </div>
</div></footer>
"""

COPY_JS = """<script>
document.addEventListener('click',function(ev){
  var b=ev.target.closest('[data-copy]'); if(!b)return;
  navigator.clipboard.writeText(b.getAttribute('data-copy')).then(function(){
    var t=b.textContent; b.textContent='copied'; b.classList.add('copied');
    setTimeout(function(){b.textContent=t; b.classList.remove('copied');},1200);
  });
});
</script>
"""

def render_run(tid):
    cmd = f"vt start --id {tid}"
    return f"""<div class="run">
      <div class="prompt"><span class="sigil">$</span><span>{e(cmd)}</span></div>
      <button class="copy" data-copy="{e(cmd)}">copy</button>
    </div>"""

# ---------------- detail page ----------------
def render_detail(t, related=(), newer=None, older=None):
    tid = t['id']; did = disp_id(tid); info = t.get('info', {})
    name = info.get('name', tid)
    cve = info.get('cve', '')
    sev = sev_of(t)
    cvss = info.get('cvss') or {}
    score = cvss.get('score', '')
    desc = (info.get('description') or '').strip()
    title = page_title(t)
    canonical = f"{SITE}/{did}/"   # trailing slash: the URL Pages serves (and the sitemap lists) without a redirect

    chips = []
    if sev:
        chips.append(f'<span class="sev sev-{e(sev)}">{e(sev.upper())}{(" · "+e(score)) if score!="" else ""}</span>')
    chips.append(f'<span class="type">{e(info.get("type","LAB"))}</span>')
    diff = info.get('difficulty')
    if diff:
        chips.append(f'<span class="diff diff-{e(diff)}">{e(diff)}</span>')
    for tg in (info.get('tags') or [])[:4]:
        chips.append(f'<span class="tag">{e(tg)}</span>')

    # ---- spec rail: every metadata field present ----
    spec = []
    def srow(k, v, plain=False):
        if v in (None, '', [], {}): return
        spec.append(f'<div class="srow"><dt>{e(k)}</dt><dd class="{"plain" if plain else ""}">{v}</dd></div>')
    def metrics(m): return f'<div class="metrics">{e(m)}</div>' if m else ''
    srow('Type', e(info.get('type', 'Lab')))
    if diff: srow('Difficulty', e(diff))
    if info.get('simulated'): srow('Simulated', 'yes')
    if cve: srow('CVE', f'<a href="https://nvd.nist.gov/vuln/detail/{e(cve)}">{e(cve)}</a>')
    if info.get('ghsa'): srow('GHSA', e(info['ghsa']))
    if info.get('ghsl'): srow('GHSL', e(info['ghsl']))
    if info.get('cwe'): srow('CWE', e(info['cwe']))
    if cvss.get('score') not in (None, '') or sev:
        srow('CVSS v3.1', e(f"{cvss.get('score','')} {sev}".strip()) + metrics(cvss.get('metrics', '')))
    c4 = info.get('cvss_v4') or {}
    if c4.get('score') not in (None, ''):
        srow('CVSS v4', e(f"{c4.get('score','')} {c4.get('severity','')}".strip()) + metrics(c4.get('metrics', '')))
    av = info.get('affected_versions')
    if av: srow('Affected', e(', '.join(av) if isinstance(av, list) else av))
    if info.get('fixed_version'): srow('Fixed', e(info['fixed_version']))
    pv = info.get('patched_versions')
    if pv: srow('Patched', e(', '.join(pv) if isinstance(pv, list) else pv))
    if t.get('owasp'):
        ow = t['owasp']; srow('OWASP', e(', '.join(ow) if isinstance(ow, list) else str(ow)))
    tgs = info.get('targets')
    if tgs: srow('Targets', e(', '.join(tgs) if isinstance(tgs, list) else tgs), plain=True)
    srow('Author', e(info.get('author', '')), plain=True)
    if t.get('added_date'): srow('Added', e(str(t['added_date'])[:10]))
    if t.get('category'): srow('Category', e(t['category']))
    for pname, pc in (t.get('providers') or {}).items():
        val = e(pname); extra = []
        if isinstance(pc, dict):
            if pc.get('image'): extra.append(e(pc['image']))
            if pc.get('ports'): extra.append('ports ' + e(', '.join(str(x) for x in pc['ports'])))
        if extra: val += metrics(' · '.join(extra))
        srow('Lab', val)

    # ---- sections ----
    secs = []
    def mll(s): return f'<div class="mll">{e(str(s).strip())}</div>'
    if desc: secs.append(('summary', 'Summary', prose(desc)))
    if t.get('technical'): secs.append(('technical', 'Technical detail', mll(t['technical'])))
    if t.get('impact'): secs.append(('impact', 'Impact', prose(t['impact'])))

    vuln = t.get('vulnerabilities')
    vulns = vuln if isinstance(vuln, list) else ([vuln] if isinstance(vuln, dict) else [])
    nuclei = nuclei_of(t); poc = t.get('poc') or {}
    if vulns or nuclei or poc:
        body = ''
        for vb in vulns:
            if not isinstance(vb, dict): continue
            if vb.get('name'): body += f'<h3 class="vln">{e(vb["name"])}</h3>'
            if vb.get('description'): body += prose(vb['description'])
            mparts = []
            if vb.get('method'): mparts.append(f'<span class="m-method">{e(vb["method"])}</span>')
            if vb.get('endpoint'): mparts.append(f'<span class="m-path">{e(vb["endpoint"])}</span>')
            if vb.get('param'): mparts.append(f'<span class="m-param">param=<b>{e(str(vb["param"]))}</b></span>')
            auth = vb.get('authentication') or {}
            authtxt = ''
            if auth:
                authtxt = 'unauthenticated' if (auth.get('required') is False or auth.get('type') == 'none') else 'auth: ' + str(auth.get('type', ''))
            elif vb.get('auth_required') is not None:
                authtxt = 'unauthenticated' if vb['auth_required'] is False else 'auth required'
            if authtxt:
                mparts.append(f'<span class="{"m-unauth" if authtxt == "unauthenticated" else "m-auth"}">{e(authtxt)}</span>')
            if mparts:
                body += '<p class="metaline">' + '<span class="sep">·</span>'.join(mparts) + '</p>'
            if vb.get('precondition'): body += f'<p class="note">Precondition: {e(vb["precondition"])}</p>'
            if vb.get('headers'):
                hh = vb['headers']
                if isinstance(hh, dict):
                    hs = '\n'.join(f'{k}: {v}' for k, v in hh.items())
                elif isinstance(hh, list):
                    lines = []
                    for it in hh:
                        if isinstance(it, dict):
                            if 'name' in it or 'value' in it:
                                lines.append(f"{it.get('name', it.get('key',''))}: {it.get('value','')}")
                            else:
                                lines.append('; '.join(f'{k}: {v}' for k, v in it.items()))
                        else:
                            lines.append(str(it))
                    hs = '\n'.join(lines)
                else:
                    hs = str(hh)
                body += f'<div class="io"><span class="lbl">HEADERS</span><pre class="code">{_hl_body(hs)}</pre></div>'
            if vb.get('chain'):
                items = ''.join(f'<li>{e(re.sub(r"^\\s*\\d+[.)]\\s*", "", str(s)))}</li>' for s in vb['chain'])
                body += f'<div class="io"><span class="lbl">EXPLOITATION STEPS</span><ol class="steps">{items}</ol></div>'
            if vb.get('request'): body += f'<div class="io"><span class="lbl">REQUEST</span><pre class="code">{hl_http(vb["request"].rstrip())}</pre></div>'
            if vb.get('response'): body += f'<div class="io"><span class="lbl">RESPONSE</span><pre class="code">{hl_http(vb["response"].rstrip())}</pre></div>'
            if vb.get('highlight'):
                hl = vb['highlight']; body += f'<p class="note">Highlight: <code class="nuc">{e(", ".join(hl) if isinstance(hl, list) else str(hl))}</code></p>'
            if vb.get('payloads'):
                body += '<div class="io"><span class="lbl">PAYLOADS</span><div class="payloads">'
                for p in vb['payloads']:
                    if isinstance(p, dict):
                        body += (f'<div class="pl"><div class="pl-h">{e(p.get("name",""))}'
                                 + (f' — <span class="pl-note">{e(p.get("note",""))}</span>' if p.get('note') else '')
                                 + f'</div><pre class="code">{_hl_body(str(p.get("value","")))}</pre></div>')
                    else:
                        body += f'<div class="pl"><pre class="code">{_hl_body(str(p))}</pre></div>'
                body += '</div></div>'
            if isinstance(vb.get('payload_details'), str): body += mll(vb['payload_details'])
            ind = vb.get('indicators') or {}
            if ind.get('success') or ind.get('failure'):
                def ic(arr, c): return ''.join(f'<code class="ind {c}">{e(x)}</code>' for x in (arr or []))
                body += '<div class="io"><span class="lbl">INDICATORS</span><div class="inds">' + ic(ind.get('success'), 'ok') + ic(ind.get('failure'), 'no') + '</div></div>'
            if vb.get('note'): body += f'<p class="note">{e(vb["note"].strip())}</p>'
        if nuclei: body += f'<p class="nucline">Nuclei detection: <code class="nuc">{e(", ".join(nuclei))}</code></p>'
        for pk, pvv in poc.items():
            if pk == 'nuclei': continue
            body += f'<p class="note">{e(pk)}: {e(pvv if isinstance(pvv, str) else json.dumps(pvv))}</p>'
        if body: secs.append(('poc', 'Exploitation & proof of concept', body))  # e() escapes it once

    tl = t.get('disclosure_timeline')
    if tl:
        rows = ''.join(f'<li><span class="tl-date">{e(x.get("date",""))}</span><span class="tl-ev">{e(x.get("event",""))}</span></li>' for x in tl if isinstance(x, dict))
        if rows: secs.append(('timeline', 'Disclosure timeline', f'<ul class="timeline">{rows}</ul>'))

    rem = t.get('remediation') or t.get('remedy')
    if rem:
        body = '<ul class="plain">' + ''.join(f'<li>{e(x)}</li>' for x in rem) + '</ul>' if isinstance(rem, list) else mll(rem)
        secs.append(('remediation', 'Remediation', body))

    pin = t.get('post-install')
    if pin:
        body = '<ul class="plain">' + ''.join(f'<li>{e(x)}</li>' for x in pin) + '</ul>' if isinstance(pin, list) else mll(pin)
        secs.append(('setup', 'Lab setup notes', body))

    md = t.get('metadata')
    if isinstance(md, dict) and md:
        rows = ''.join(f'<div class="srow"><dt>{e(k)}</dt><dd>{e(v if isinstance(v,(str,int,float)) else json.dumps(v))}</dd></div>' for k, v in md.items())
        secs.append(('metadata', 'Metadata', f'<div class="spec meta-inline">{rows}</div>'))

    refs = refs_of(t)
    if refs:
        secs.append(('references', 'References', '<ul class="refs">' + ''.join(f'<li><a href="{e(r)}">{e(r)}</a></li>' for r in refs) + '</ul>'))

    if related:
        items = ''.join(f'<li><a href="../{e(disp_id(o["id"]))}/"><span class="catno">{e(disp_id(o["id"]))}</span>'
                        f'<span class="rel-t">{e(o.get("info", {}).get("name", o["id"]))}</span></a></li>' for o in related)
        secs.append(('related', 'Related labs', f'<ul class="related">{items}</ul>'))

    sections_html = ''
    toc = []
    for i, (anchor, label, body) in enumerate(secs, 1):
        toc.append(f'<a href="#{anchor}">{e(label)}</a>')
        sections_html += (f'<section class="doc" id="{anchor}">'
                          f'<h2>{e(label)}</h2>{body}</section>')

    ogimg = f"{SITE}/og/{tid}.png" if og else f"{SITE}/og-image.png"
    mdesc = meta_desc(desc) or meta_desc(f'{name}: a reproducible vulnerable lab. Run it locally with vt start --id {tid}.')
    out = HEAD.format(title=e(title), desc=e(mdesc), canonical=e(canonical),
                      ogtype='article', css='../assets/app.css', ogimg=e(ogimg),
                      extra=lab_jsonld(t, canonical, ogimg, mdesc))
    out += '<main id="main" class="wrap">'
    out += f'<nav class="crumbs" aria-label="Breadcrumb"><a href="../">Targets</a> / <span aria-current="page">{e(did)}</span></nav>'
    out += '<div class="detail"><div class="main">'
    out += ('<div class="dhero"><canvas id="hero-matrix" aria-hidden="true"></canvas><div class="dhero-in">'
            f'<div class="catno">{e(did)}</div>'
            f'<h1>{e(name)}</h1><div class="chips">{"".join(chips)}</div></div></div>')
    out += (f'<div class="runblock"><h2>Run this lab</h2>{render_run(tid)}'
            f'<p class="runhelp">Lab not starting or behaving wrong? '
            f'<a href="{e(issue_url(t))}" target="_blank" rel="noopener">Report a problem with this lab</a></p></div>')
    out += sections_html
    pager = ''
    for o, rel, cls, key in ((newer, 'prev', 'pg-newer', 'Newer lab'), (older, 'next', 'pg-older', 'Older lab')):
        if o:
            od = disp_id(o['id'])
            pager += (f'<a class="{cls}" rel="{rel}" href="../{e(od)}/"><span class="pg-k">{key}</span>'
                      f'<span class="pg-t"><span class="catno">{e(od)}</span> {e(o.get("info", {}).get("name", o["id"]))}</span></a>')
    if pager:
        out += f'<nav class="pager" aria-label="Browse labs">{pager}</nav>'
    out += '</div>'  # main
    out += f'<aside><div class="spec">{"".join(spec)}</div>'
    out += f'<nav class="toc" aria-labelledby="toc-h"><h2 id="toc-h">On this page</h2>{"".join(toc)}</nav></aside>'
    out += '</div></main>'  # detail, main.wrap
    out += FOOTER.format(root='../', year=YEAR) + MATRIX_JS + COPY_JS + '</body></html>'
    return out

# ---------------- home ----------------
def render_home(ts):
    counts = {}
    def bump(cat, key):
        counts.setdefault(cat, {}); counts[cat][key] = counts[cat].get(key, 0) + 1

    cards = []
    for i, t in enumerate(newest_first(ts)):
        tid = t['id']; did = disp_id(tid); info = t.get('info', {})
        sev = sev_of(t); typ = info.get('type', 'Lab'); diff = info.get('difficulty', '')
        cat = t.get('category', ''); yr = year_of(t)
        bump('type', typ)
        if sev: bump('severity', sev)
        if diff: bump('difficulty', diff)
        if yr: bump('year', yr)
        tags = info.get('tags') or []
        hay = ' '.join([tid, did, info.get('name', ''), info.get('cve', ''), ' '.join(tags), ' '.join(info.get('targets') or [])]).lower()
        accent = f'sev-{sev}' if sev else f'ty-{typ.lower()}'
        chips = (f'<span class="sev sev-{e(sev)}">{e(sev.upper())}</span>' if sev else '') \
            + f'<span class="type">{e(typ)}</span>' \
            + (f'<span class="diff diff-{e(diff)}">{e(diff)}</span>' if diff else '')
        taghtml = ''.join(f'<span class="tag">{e(tg)}</span>' for tg in tags[:3])
        new = '<span class="new">New</span>' if is_new(t) else ''
        cards.append(
            f'<a class="card acc-{accent}" href="{e(did)}/" data-type="{e(typ)}" data-diff="{e(diff)}" '
            f'data-sev="{e(sev)}" data-year="{e(yr)}" data-hay="{e(hay)}" '
            f'data-i="{i}" data-rank="{SEV_RANK.get(sev, 0)}" data-id="{e(did.lower())}">'
            f'<div class="card-top"><span class="catno">{e(did)}</span>{new}<span class="yr">{e(yr or cat)}</span></div>'
            f'<div class="card-title">{e(info.get("name", tid))}</div>'
            f'<div class="card-chips">{chips}</div>'
            f'<div class="card-tags">{taghtml}</div></a>')

    def pills(cat, order=None):
        d = counts.get(cat, {})
        keys = [k for k in (order or sorted(d.keys(), key=lambda k: (-d[k], k))) if k in d]
        return ''.join(f'<button type="button" class="pill" aria-pressed="false" data-facet="{e(cat)}" data-val="{e(k)}">{e(k)}<span class="pc"><span class="sr"> (</span>{d[k]}<span class="sr">)</span></span></button>' for k in keys)
    def group(cat, label, order=None):
        gid = f'pl-{cat}'
        return (f'<div class="pgroup" role="group" aria-labelledby="{gid}">'
                f'<span class="plabel" id="{gid}">{label}</span>{pills(cat, order)}</div>')

    total = len(ts)
    cve_n = counts.get('type', {}).get('CVE', 0)
    bench_n = counts.get('type', {}).get('Benchmark', 0)
    lab_n = counts.get('type', {}).get('Lab', 0)

    out = HEAD.format(title=f'{BRAND} – reproducible vulnerable labs, one command each',
                      desc=e(HOME_DESC), canonical=SITE + '/', ogtype='website', css='assets/app.css',
                      ogimg=SITE + '/og-image.png',
                      extra='<link rel="alternate" type="application/json" href="/labs.json" title="Lab catalog">\n'
                            + jsonld(WEBSITE, ORG))
    out += '<main id="main">'
    out += ('<section class="hero"><canvas id="hero-matrix" aria-hidden="true"></canvas><div class="wrap">'
            '<div class="hero-copy">'
            '<h1>Spin up a vulnerable target from your terminal.</h1>'
            '<p class="lead">Hack and learn on your local machine — reproducible labs, one command each.</p>'
            + render_run('vt-2026-96654') +
            f'<div class="statline">'
            f'<span class="stat"><b>{total}</b><span>labs</span></span>'
            f'<span class="stat"><b>{cve_n}</b><span>CVE repros</span></span>'
            f'<span class="stat"><b>{bench_n}</b><span>benchmarks</span></span>'
            f'<span class="stat"><b>{lab_n}</b><span>app labs</span></span>'
            f'</div></div>'
            '<div class="hero-mark" aria-hidden="true"><svg viewBox="0 0 48 48" fill="none">'
            '<circle class="ok-disc" cx="24" cy="24" r="18"/>'
            '<circle class="ok-ring" cx="24" cy="24" r="13.5" stroke-width="2.3"/>'
            '<circle class="ok-ring" cx="24.6" cy="24.6" r="9" stroke-width="2.1"/>'
            '<circle class="ok-ring" cx="25.2" cy="25.2" r="5" stroke-width="1.9"/>'
            '<circle class="ok-core" cx="25.6" cy="25.6" r="3"/></svg></div>'
            '</div></section>')
    out += '<div class="wrap"><div class="filterbar" role="search"><div class="searchwrap"><span class="si" aria-hidden="true">⌕</span>'
    out += ('<input type="search" id="q" class="bigsearch" aria-label="Search labs" aria-keyshortcuts="/" '
            'placeholder="Search by id, CVE, product or tag…" autocomplete="off">'
            '<kbd class="kbdhint" aria-hidden="true">/</kbd></div>')
    # severity only exists on CVE/advisory labs and level only on benchmarks: say so in the label,
    # otherwise picking one silently hides the other kind
    out += ('<div class="pillrow">'
            + group('type', 'Type')
            + group('severity', 'CVE severity', order=["critical","high","medium","low"])
            + group('difficulty', 'Benchmark level', order=["Easy","Medium","Hard"])
            + '</div></div>')
    out += (f'<div class="rhead"><span class="count" role="status" aria-live="polite" aria-atomic="true"><b id="shown">{total}</b> of {total} labs</span>'
            '<div class="rtools"><label class="sortlab" for="sort">Sort</label>'
            '<select id="sort" class="sortsel"><option value="new">Newest</option>'
            '<option value="sev">Severity</option><option value="id">ID</option></select>'
            f'<button type="button" class="pill clear" id="clear">Clear filters</button></div></div>')
    out += f'<h2 class="sr">Labs</h2><div class="grid" id="grid">{"".join(cards)}</div>'
    # empty result: say what matched nothing and give the two ways forward (clear, or ask for the lab)
    out += ('<div class="empty" id="empty" hidden><p class="empty-t" id="empty-t">No labs match these filters.</p>'
            '<p class="empty-d">Check the ID, or try a product name, CVE or tag. If the lab does not exist yet, ask for it.</p>'
            '<p class="nf-actions"><button type="button" class="btn" id="empty-clear">Clear search and filters</button>'
            f'<a class="btn btn-ghost" id="empty-request" href="{e(ISSUES)}" target="_blank" rel="noopener">Request a lab</a></p></div>')
    out += '<script>var VT_REQ=' + json.dumps({'issues': ISSUES, 'body': SEARCH_REQUEST_BODY}).replace('</', '<\\/') + ';</script>'
    out += '</div></main>'
    out += FOOTER.format(root='./', year=YEAR)
    out += """<script>
(function(){
  var q=document.getElementById('q'), grid=document.getElementById('grid'), sort=document.getElementById('sort'),
      cards=[].slice.call(document.querySelectorAll('.card')),
      shown=document.getElementById('shown'), pills=[].slice.call(document.querySelectorAll('.pill[data-facet]'));
  var map={type:'type',severity:'sev',difficulty:'diff'};
  var param={type:'type',severity:'severity',difficulty:'level'};   // URL names: ?q=&type=&severity=&level=&sort=
  function active(){var a={};pills.forEach(function(p){if(p.classList.contains('on'))(a[p.dataset.facet]=a[p.dataset.facet]||[]).push(p.dataset.val);});return a;}
  function setPill(p,on){p.classList.toggle('on',on);p.setAttribute('aria-pressed',on?'true':'false');}
  // keep the view in the URL so it can be shared and survives Back (replaceState: no history entry per keystroke)
  function sync(){
    var u=new URLSearchParams(), f=active(), t=q.value.trim();
    if(t)u.set('q',t);
    for(var k in f)u.set(param[k],f[k].join(','));
    if(sort.value!=='new')u.set('sort',sort.value);
    var s=u.toString(); history.replaceState(null,'',s?'?'+s:location.pathname);
  }
  function reorder(){
    var list=cards.slice(), by=sort.value;
    if(by==='sev')list.sort(function(a,b){return (b.dataset.rank-a.dataset.rank)||(a.dataset.i-b.dataset.i);});
    else if(by==='id')list.sort(function(a,b){return a.dataset.id.localeCompare(b.dataset.id,'en',{numeric:true});});
    else list.sort(function(a,b){return a.dataset.i-b.dataset.i;});
    list.forEach(function(c){grid.appendChild(c);});
  }
  function apply(){
    var term=(q.value||'').trim().toLowerCase(), f=active(), n=0;
    cards.forEach(function(c){
      var ok=true;
      if(term && c.dataset.hay.indexOf(term)<0) ok=false;
      if(ok) for(var k in f){ if(f[k].indexOf(c.dataset[map[k]])<0){ok=false;break;} }
      c.style.display=ok?'':'none'; if(ok)n++;
    });
    shown.textContent=n; showEmpty(n); sync();
  }
  var em=document.getElementById('empty'), et=document.getElementById('empty-t'), er=document.getElementById('empty-request');
  function showEmpty(n){
    em.hidden=n>0; if(n>0)return;
    var t=q.value.trim(), quoted='\u201c'+t+'\u201d';
    et.textContent=t?'No labs match '+quoted+'.':'No labs match these filters.';
    er.href=VT_REQ.issues+'?'+new URLSearchParams({title:'[Lab request] '+t, body:VT_REQ.body.replace('{q}', t?' for '+quoted:'')});
    er.textContent=t?'Request '+quoted+' as a lab':'Request a lab';
  }
  document.getElementById('empty-clear').addEventListener('click',function(){document.getElementById('clear').click();q.focus();});
  // restore a shared / returning view
  var u=new URLSearchParams(location.search);
  if(u.get('q'))q.value=u.get('q');
  pills.forEach(function(p){if((u.get(param[p.dataset.facet])||'').split(',').indexOf(p.dataset.val)>=0)setPill(p,true);});
  if(u.get('sort')==='sev'||u.get('sort')==='id')sort.value=u.get('sort');
  reorder(); apply();
  q.addEventListener('input',apply);
  sort.addEventListener('change',function(){reorder();sync();});
  pills.forEach(function(p){p.addEventListener('click',function(){setPill(p,!p.classList.contains('on'));apply();});});
  var cl=document.getElementById('clear'); if(cl)cl.addEventListener('click',function(){q.value='';pills.forEach(function(p){setPill(p,false);});apply();});
  // "/" jumps to search from anywhere except a text field
  document.addEventListener('keydown',function(ev){
    var a=document.activeElement;
    if(ev.key!=='/'||ev.metaKey||ev.ctrlKey||ev.altKey||(a&&(/^(INPUT|TEXTAREA|SELECT)$/.test(a.tagName)||a.isContentEditable)))return;
    ev.preventDefault(); q.focus(); q.select();
  });
})();
</script>"""
    out += MATRIX_JS + COPY_JS + '</body></html>'
    return out

# ---------------- 404 + legacy URL redirects ----------------
def render_404():
    out = HEAD.format(title=f'Not found | {BRAND}', desc='This page does not exist.',
                      canonical=SITE + '/404', ogtype='website', css='/assets/app.css',
                      ogimg=SITE + '/og-image.png', extra='<meta name="robots" content="noindex">\n')
    from urllib.parse import urlencode
    request = ISSUES + '?' + urlencode({'title': '[Lab request] ', 'body': LAB_REQUEST_BODY.format(url='')})
    out += ('<main id="main" class="wrap notfound"><p class="catno">404</p>'
            '<h1>This target is not in the registry.</h1>'
            '<p class="lead" id="nf-lead">The link may be old or mistyped. Search the registry by ID, CVE or product, '
            'or ask for the lab to be added.</p>'
            '<p class="nf-actions"><a class="btn" href="/">Go to the registry</a>'
            '<a class="btn btn-ghost" id="nf-search" href="/" hidden>Search the registry</a>'
            f'<a class="btn btn-ghost" id="nf-request" href="{e(request)}" target="_blank" rel="noopener">Request a lab</a></p>'
            '</main>')
    out += FOOTER.format(root='/', year=YEAR) + NOTFOUND_JS + '</body></html>'
    return out

SEARCH_REQUEST_BODY = ('Requested from a registry search with no results{q}.\n\n'
                       '**What should this lab cover?** (CVE / advisory ID, product and affected version)\n\n\n'
                       '**References**\n')

LAB_REQUEST_BODY = ('Requested from a link that does not exist yet{url}.\n\n'
                    '**What should this lab cover?** (CVE / advisory ID, product and affected version)\n\n\n'
                    '**References**\n')

# 404 is one static file served for every missing path: read the path and, when its last segment looks
# like an ID, offer a search for it and prefill the request with it. Without JS the generic links stay.
NOTFOUND_JS = """<script>
(function(){
  var seg=decodeURIComponent(location.pathname).split('/').filter(Boolean).pop()||'';
  if(!/^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$/.test(seg)||/\\.(html?|php|png|jpe?g|svg|css|js|xml|txt|json)$/i.test(seg))return;
  var s=document.getElementById('nf-search'), r=document.getElementById('nf-request'), l=document.getElementById('nf-lead');
  s.href='/?q='+encodeURIComponent(seg); s.textContent='Search the registry for \\u201c'+seg+'\\u201d'; s.hidden=false;
  var u=new URL(r.href); u.searchParams.set('title','[Lab request] '+seg);
  u.searchParams.set('body',u.searchParams.get('body').replace('yet.','yet: '+location.origin+location.pathname+'.'));
  r.href=u.toString(); r.textContent='Request '+seg+' as a lab';
  l.textContent='There is no lab at \\u201c'+seg+'\\u201d yet. It may have a different ID, or it may not exist.';
})();
</script>
"""

def redirect_page(to, canonical):
    """Static redirect for a URL the old site published (keeps shared links alive)."""
    return ('<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">'
            '<meta name="robots" content="noindex">'
            f'<meta http-equiv="refresh" content="0;url={e(to)}">'
            f'<link rel="canonical" href="{e(canonical)}"><title>Redirecting…</title></head>'
            f'<body><p>Moved to <a href="{e(to)}">{e(to)}</a>.</p></body></html>')

# old site: /detail.html?id=<tid>  ->  /VT-YYYY-NNNNN/
LEGACY_DETAIL = """<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="robots" content="noindex">
<title>Redirecting…</title>
<script>(function(){var id=new URLSearchParams(location.search).get('id')||'';
if(/^[A-Za-z0-9._-]+$/.test(id)){location.replace('/'+(id.toLowerCase().indexOf('vt-')===0?'VT-'+id.slice(3):id)+'/'+location.hash);}
else{location.replace('/');}})();</script></head>
<body><p>Moved to the <a href="/">registry</a>.</p></body></html>"""

# ---------------- GEO: machine-readable catalog for AI answer engines ----------------
def lab_catalog(order):
    """/labs.json: one record per lab, the facts an answer engine needs to cite a lab correctly."""
    out = []
    for t in order:
        info = t.get('info', {}); tid = t['id']; did = disp_id(tid); cvss = info.get('cvss') or {}
        rec = {'id': tid, 'vt_id': did, 'url': f'{SITE}/{did}/', 'name': info.get('name', tid),
               'type': info.get('type', 'Lab'), 'cve': info.get('cve') or None, 'ghsa': info.get('ghsa') or None,
               'cwe': info.get('cwe') or None, 'severity': sev_of(t) or None, 'cvss': cvss.get('score'),
               'difficulty': info.get('difficulty') or None, 'targets': info.get('targets') or [],
               'tags': info.get('tags') or [], 'added': iso_date(t.get('added_date')) or None,
               'summary': meta_desc(info.get('description'), 300), 'run': f'vt start --id {tid}'}
        out.append({k: v for k, v in rec.items() if v not in (None, '')})
    return out

def llms_txt(order):
    """/llms.txt (llmstxt.org): what the site is, then every lab as a cited link, grouped by kind."""
    groups = [('CVE reproductions', lambda t: t['info'].get('type') == 'CVE'),
              ('Security advisories (GHSA / GHSL)', lambda t: t['info'].get('type') in ('GHSA', 'GHSL')),
              ('App labs', lambda t: t['info'].get('type') == 'Lab'),
              ('Benchmarks', lambda t: t['info'].get('type') == 'Benchmark')]
    lines = [f'# {BRAND}', '', f'> {HOME_DESC} Maintained by HappyHackingSpace.', '',
             'Each lab page documents the vulnerability (summary, root cause, impact), the exploitation steps with '
             'the HTTP requests involved, remediation and references, plus the command that starts the lab. '
             'Labs are intentionally vulnerable: run them only on your own machine or systems you are authorised to test.', '',
             '## Catalog', '',
             f'- [Lab catalog (JSON)]({SITE}/labs.json): every lab with ID, CVE, CWE, severity, summary, run command and URL',
             f'- [New labs (RSS)]({SITE}/feed.xml): the {FEED_SIZE} most recently added labs',
             f'- [Sitemap]({SITE}/sitemap.xml)', '']
    for title, keep in groups:
        labs = [t for t in order if keep(t)]
        if not labs:
            continue
        lines += [f'## {title}', '']
        for t in labs:
            info = t['info']; did = disp_id(t['id']); ref = ref_id(t)
            label = info.get('name', did) if (not ref or ref in info.get('name', '')) else f"{ref}: {info.get('name', did)}"
            lines.append(f'- [{label}]({SITE}/{did}/): {meta_desc(info.get("description"), 140)}')
        lines.append('')
    lines += ['## Optional', '',
              '- [vt CLI](https://github.com/HappyHackingSpace/vt): the command-line tool that starts the labs',
              '- [Lab templates](https://github.com/HappyHackingSpace/vt-templates): source of every lab', '']
    return '\n'.join(lines)

FEED_SIZE = 50

def rss_feed(order):
    """/feed.xml (RSS 2.0): the newest labs. lastBuildDate is the newest lab's date, not the build time,
    so the several automatic rebuilds a day do not look like changes to feed readers."""
    from email.utils import format_datetime
    from datetime import datetime, timezone
    def rfc822(t):
        d = iso_date(t.get('added_date'))
        return format_datetime(datetime.fromisoformat(d).replace(tzinfo=timezone.utc)) if d else ''
    x = lambda s: html.escape(str(s), quote=False)
    items = []
    for t in order[:FEED_SIZE]:
        info = t.get('info', {}); tid = t['id']; did = disp_id(tid); url = f'{SITE}/{did}/'
        ref = ref_id(t); name = str(info.get('name') or did)
        title = name if (not ref or ref in name) else f'{ref}: {name}'
        body = meta_desc(info.get('description'), 400) or name
        cats = [info.get('type', 'Lab')] + ([sev_of(t)] if sev_of(t) else [])
        items.append('    <item>\n'
                     f'      <title>{x(title)}</title>\n      <link>{x(url)}</link>\n'
                     f'      <guid isPermaLink="true">{x(url)}</guid>\n'
                     + (f'      <pubDate>{rfc822(t)}</pubDate>\n' if rfc822(t) else '')
                     + ''.join(f'      <category>{x(c)}</category>\n' for c in cats)
                     + f'      <description>{x(body + " Run it: vt start --id " + tid)}</description>\n'
                     '    </item>\n')
    newest = next((rfc822(t) for t in order if rfc822(t)), '')
    return ('<?xml version="1.0" encoding="UTF-8"?>\n'
            '<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">\n  <channel>\n'
            f'    <title>{BRAND}: new labs</title>\n    <link>{SITE}/</link>\n'
            f'    <description>{x(HOME_DESC)}</description>\n    <language>en</language>\n'
            + (f'    <lastBuildDate>{newest}</lastBuildDate>\n' if newest else '')
            + f'    <atom:link href="{SITE}/feed.xml" rel="self" type="application/rss+xml"/>\n'
            f'    <image><url>{SITE}/icon-192.png</url><title>{BRAND}: new labs</title><link>{SITE}/</link></image>\n'
            + ''.join(items) + '  </channel>\n</rss>\n')

def write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w') as f:
        f.write(text)

def main():
    src = next((p for p in CANDIDATES if os.path.exists(p)), None)
    if not src:
        print('no templates.json found'); sys.exit(1)
    ts = json.load(open(src))
    print(f'source: {os.path.relpath(src)}  ({len(ts)} templates)')
    if os.path.isdir(DIST): shutil.rmtree(DIST)
    os.makedirs(os.path.join(DIST, 'assets'), exist_ok=True)
    shutil.copy(os.path.join(HERE, 'assets', 'app.css'), os.path.join(DIST, 'assets', 'app.css'))

    # brand: mark masters + brand page at /assets/brand/, web icons + share image at the site root
    brand = os.path.join(HERE, 'assets', 'brand')
    shutil.copytree(brand, os.path.join(DIST, 'assets', 'brand'))
    web = os.path.join(brand, 'web')
    for fn in ('favicon.ico', 'favicon.svg', 'apple-touch-icon.png', 'icon-192.png', 'icon-512.png',
               'maskable-512.png', 'site.webmanifest', 'og-image.png'):
        shutil.copy(os.path.join(web, fn), os.path.join(DIST, fn))
    cname = os.path.join(HERE, 'CNAME')
    if os.path.exists(cname):
        shutil.copy(cname, os.path.join(DIST, 'CNAME'))

    write(os.path.join(DIST, 'index.html'), render_home(ts))
    write(os.path.join(DIST, '404.html'), render_404())
    write(os.path.join(DIST, 'detail.html'), LEGACY_DETAIL)
    urls = [SITE + '/']
    aliases = 0
    order = newest_first(ts)          # same order as the home grid, so Newer/Older match it
    rel = related_index(ts)
    for i, t in enumerate(order):
        tid, did = t['id'], disp_id(t['id'])
        write(os.path.join(DIST, did, 'index.html'),
              render_detail(t, rel[tid], order[i - 1] if i > 0 else None, order[i + 1] if i + 1 < len(order) else None))
        urls.append(f'{SITE}/{did}/')
        # old site also published the lowercase /vt-…/ path. On a case-insensitive disk (macOS)
        # that path IS the real page, so skip; on Linux CI it is a separate redirect page.
        if tid != did and not os.path.exists(os.path.join(DIST, tid)):
            write(os.path.join(DIST, tid, 'index.html'), redirect_page(f'/{did}/', f'{SITE}/{did}/'))
            aliases += 1
        if og:
            info = t.get('info', {})
            og.render_lab(did, tid, info.get('name', tid), sev_of(t), os.path.join(DIST, 'og', f'{tid}.png'))

    dates = {f'{SITE}/{disp_id(t["id"])}/': iso_date(t.get('added_date')) for t in ts}
    dates[SITE + '/'] = max(d for d in dates.values() if d) if any(dates.values()) else ''
    write(os.path.join(DIST, 'sitemap.xml'),
          '<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
          + ''.join(f'  <url><loc>{e(u)}</loc>' + (f'<lastmod>{dates[u]}</lastmod>' if dates.get(u) else '') + '</url>\n'
                    for u in urls) + '</urlset>\n')
    write(os.path.join(DIST, 'labs.json'), json.dumps(lab_catalog(order), ensure_ascii=False, indent=1) + '\n')
    write(os.path.join(DIST, 'llms.txt'), llms_txt(order))
    write(os.path.join(DIST, 'feed.xml'), rss_feed(order))
    write(os.path.join(DIST, 'robots.txt'), f'User-agent: *\nAllow: /\nSitemap: {SITE}/sitemap.xml\n')
    print(f'built {len(ts)} detail pages + home, {aliases} legacy aliases, 404, sitemap'
          f'{", per-lab OG images" if og else " (no Pillow: shared OG image)"} -> {os.path.relpath(DIST)}')

if __name__ == '__main__':
    main()
