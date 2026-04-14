# Five-10 Incident Reporting

Static GitHub Pages app for incident reporting workflows. Analysts can paste problem statements, upload text-based evidence, run analysis, and export selected report outputs as `.docx`.

## What It Does

- Gives you a public-facing workbench with a stronger visual presentation than a plain form.
- Accepts analyst notes, problem statements, pasted raw logs, and uploaded text-based evidence files.
- Sends the case package either to OpenRouter directly from the browser or to a separate backend API if `config.js` defines `apiBaseUrl`.
- Produces structured incident outputs with emphasis on:
  - Post Incident Report (PIR)
  - Incident Summary
  - Executive Summary
  - Timeline
  - IOC Report
  - Remediation Plan
  - Customer Update
- Exports selected deliverables as `.docx` files in a single `.zip` bundle.

## Backend Mode

If you want the public site to stop handling the OpenRouter key in the browser, set `window.FIVE10_CONFIG.apiBaseUrl` in `config.js` to a deployed backend URL.

The frontend will then post to:

- `/api/analyze`

When backend mode is enabled, the key-entry controls are hidden and the browser sends only the case payload.

## Security Constraint

This is a GitHub Pages site. GitHub Pages is static hosting, so it cannot safely store a private OpenRouter API key.

Because of that, the site is built to:

- import a local key file at runtime, or
- let an analyst paste a key into the browser for the current session.

If you deploy a separate backend, the public site can avoid browser-side key handling entirely.

The key is stored in `sessionStorage`, not embedded into the site.

`api_key_llm.txt` is ignored by Git via `.gitignore` to reduce the chance of accidentally publishing it.

## Supported Evidence Inputs

The browser can read text-based files directly:

- `.txt`
- `.log`
- `.csv`
- `.json`
- `.jsonl`
- `.xml`
- `.md`

Binary formats such as `.evtx`, `.pcap`, `.zip`, or memory images are not parsed client-side in this version. For those, extract relevant text first or add a backend parser later.

## Deploy to GitHub Pages

1. Push this repository to GitHub.
2. In the repository settings, set Pages to use GitHub Actions.
3. The included workflow at `.github/workflows/deploy-pages.yml` will publish the root static site.

## Local Use

Open `index.html` in a browser or serve the folder with any static file server.

If you want to keep using the local key file already in this folder, do not publish it. Use the app's `Import Key File` button to load it locally at runtime.
