# VT template — canonical field schema (fixed)

Two layers. The **CLI-official** layer is what the `vt` Go binary actually parses
(`vt/pkg/template/template.go`) — keep these stable and correctly typed. The
**enrichment** layer is everything else that `templates.json` carries for the
website / detection / docs; the CLI ignores unknown keys, but the redesign site
renders all of it. New templates should populate as much as applies.

## 1. CLI-official (parsed by `vt`, authoritative — do not rename)

| Field | Type | Notes |
|---|---|---|
| `id` | string | `vt-YYYY-NNNNN` |
| `info.name` | string | |
| `info.description` | string | |
| `info.author` | string | package curator (e.g. omarkurt) |
| `info.targets` | []string | |
| `info.type` | string | CVE / Benchmark / Lab / GHSA / GHSL |
| `info.affected_versions` | []string | |
| `info.fixed_version` | string | single string in the struct |
| `info.cwe` | string | |
| `info.cvss.score` | string | struct type is **string** |
| `info.cvss.metrics` | string | vector |
| `info.tags` | []string | |
| `info.references` | []string | |
| `poc` | map | free map (e.g. `{nuclei: [file]}`) |
| `remediation` | []string | |
| `providers.<name>.path` | string | compose path |
| `providers.<name>.image` | string | optional |
| `providers.<name>.ports` | []int | optional |
| `post-install` | []string | |

> Note: `info.cvss.severity` is **not** in the Go struct (CLI derives/ignores it),
> but `templates.json` and the site use it. Keep writing `severity` for the site.

## 2. Enrichment (site / detection / docs — rendered by the redesign)

Top-level: `category` (dir), `added_date` (git), `technical`, `impact`,
`remedy` (alias of remediation), `vulnerabilities` (list|dict), `owasp`,
`disclosure_timeline`, `metadata`.

`info.*` extras: `difficulty` (Easy/Medium/Hard), `cve`, `patched_versions` ([]),
`simulated` (bool), `cvss_v4.{score,severity,metrics}`, `ghsa`, `ghsl`.

`vulnerabilities[]` item: `id`, `name`, `description`, `endpoint`, `method`,
`param`, `authentication.{type,required}` | `auth_required`, `precondition`,
`headers`, `chain` (→ **exploitation steps**), `request`, `response`,
`highlight`, `payloads[].{name,value,note}`, `payload_details`,
`indicators.{success[],failure[]}`, `note`.

## 3. Rendering map (redesign detail page)

- **Spec rail:** type, difficulty, simulated, cve, ghsa, ghsl, cwe, cvss v3.1 (+vector),
  cvss v4 (+vector), affected, fixed, patched, owasp, targets, author, added,
  category, lab provider (+image/ports).
- **Sections (in order):** Summary → Technical detail → Impact →
  Exploitation & proof of concept (per vuln: meta, precondition, headers,
  **exploitation steps**, request, response, highlight, payloads, indicators, note;
  then nuclei) → Disclosure timeline → Remediation → Lab setup notes → Metadata →
  References.

Multi-line `technical`/`impact`/`description` preserve author line structure
(`white-space: pre-wrap`).
