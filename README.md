# nik.technology

Nuxt 4 website, generated as static files and hosted on Cloudflare Pages.

## Setup

Use Node 22.23.3 (pinned in `.node-version` and `.nvmrc`) and the committed npm
lockfile. Cloudflare installs dependencies with npm 10:

```bash
npm ci
```

## Development Server

Start the development server on `http://localhost:3000`:

```bash
npm run dev
```

## Production

Cloudflare Pages project `nik-technology` deploys the `master` branch from the
repository root. Its build command is `npm run generate` and its output directory
is `dist`. To reproduce the Cloudflare static build locally:

```bash
CF_PAGES=1 npm run generate
```

Serve the generated files locally:

```bash
python -m http.server 4178 --directory dist
```

Keep `package-lock.json` committed so deployment installs match the verified
dependency versions. The blog index and RSS feed include posts with `draft: false`
or no `draft` field.

## Group trading research

`/group-trading-is-minus-ev/` serves the original standalone HTML report from
`public/group-trading-is-minus-ev/index.html`. Its HTML, CSS, figures, tables and
linked reports are copied from the research workspace. It has no Nuxt page or
website layout wrapper.

To refresh the saved research snapshot from the local research workspace:

```sh
rtk python scripts/publish-group-report.py /home/nik/entryliquidity/analysis/ayugram-token-strategy --large-files-directory /tmp/group-research-release-assets
rtk proxy env CF_PAGES=1 npm run generate
```

`publication-manifest.json` records the source hashes. If a refreshed report
includes files over Cloudflare's 25 MiB limit, the exporter stages them for the
`group-trading-research-2026-10-21` release and creates download redirects.
Upload those staged files before deploying. Keep the report's wording and
original styling intact.
