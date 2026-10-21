# Nuxt 3 Minimal Starter

Look at the [Nuxt 3 documentation](https://nuxt.com/docs/getting-started/introduction) to learn more.

## Setup

Make sure to install the dependencies:

```bash
# npm
npm install

# pnpm
pnpm install

# yarn
yarn install

# bun
bun install
```

## Development Server

Start the development server on `http://localhost:3000`:

```bash
# npm
npm run dev

# pnpm
pnpm run dev

# yarn
yarn dev

# bun
bun run dev
```

## Production

Build the application for production:

```bash
# npm
npm run build

# pnpm
pnpm run build

# yarn
yarn build

# bun
bun run build
```

Locally preview production build:

```bash
# npm
npm run preview

# pnpm
pnpm run preview

# yarn
yarn preview

# bun
bun run preview
```

Check out the [deployment documentation](https://nuxt.com/docs/getting-started/deployment) for more information.

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
