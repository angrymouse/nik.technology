# nik.technology

Nuxt 4 website, generated as static files and hosted on Cloudflare Pages.

## Setup

Use Node 22 and the committed npm lockfile:

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

`/group-trading-is-minus-ev` is a prerendered research page. Its aggregate data and
SVG figures live in `public/research/group-trading/`. The JSON includes source
hashes; `manifest.json` hashes the public exports. The page does not fetch market
data at runtime.

To refresh the saved research snapshot from the local research workspace:

```sh
rtk python /home/nik/entryliquidity/analysis/ayugram-token-strategy/publish_group_research.py /home/nik/nik.technology
rtk npm run generate
```

The exporter selects aggregate fields and anonymous caller labels explicitly.
Update its snapshot inputs and the article together when publishing new results.
