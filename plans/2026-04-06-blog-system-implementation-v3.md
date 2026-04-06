# Blog System for nik.technology

## Objective

Upgrade the existing Nuxt 3.13 personal website to **Nuxt 4**, add a fully functional blog system powered by **@nuxt/content v3**, and deploy as a **fully static site** to **Cloudflare Pages**. No D1 database, no server runtime, no SQLite dependencies -- just static HTML/CSS/JS files. Nuxt Content v3 handles client-side navigation queries via WASM SQLite bundled automatically. The blog supports Markdown + Vue components (MDC syntax), auto-discovery of posts, and features a distinctive visual design: solid black background with sparkles, Bricolage Grotesque font, and a liquid/glassy aesthetic. No vibeslop.

## Project Assessment

### Current Architecture
- **Framework**: Nuxt 3.13 with static generation (`nuxt generate`)
- **Styling**: Tailwind CSS 3.4 with custom Iosevka Web monospace font
- **Pages**: `index.vue` (homepage), `gallery.vue` (image gallery)
- **Components**: Single `header.vue` with navigation (About/Skills/Projects/Contact anchor links)
- **Accent Color**: `--neon-green: #FF885B` (actually an orange, used as brand accent)
- **Background**: `bg-zinc-900` body, `bg-black` header/footer
- **Modules**: `@nuxt/image`
- **Config**: `nuxt.config.js:1-38`, `tailwind.config.js:1-22`, `package.json:1-24`
- **Deployment**: Static files to Cloudflare Pages (stays static)

### Key Design Observations
- The existing site uses a dark zinc/black palette with orange (`#FF885B`) accents
- Monospace font (Iosevka) is the current default
- Cards use `bg-zinc-800` with `border-zinc-950` borders
- The header nav links to anchor sections on the homepage -- this needs to become route-aware for blog pages

## Implementation Plan

### Phase 0: Nuxt 4 Upgrade

- [x] **0.1 Upgrade Nuxt to v4** -- Run `npx nuxt upgrade --dedupe` to update to Nuxt 4.x. Update `package.json` to pin `nuxt` to `^4.0.0`. Remove the pinned `vue` and `vue-router` `latest` entries since Nuxt 4 manages its own Vue version. **Rationale**: Nuxt 4 brings the new `app/` directory structure, improved TypeScript separation, faster CLI, and better data fetching.

- [x] **0.2 Adopt the `app/` directory structure** -- Nuxt 4's primary structural change moves application code into `app/`:
  - `pages/` -> `app/pages/`
  - `components/` -> `app/components/`
  - `assets/` -> `app/assets/`
  - `app.vue` -> `app/app.vue`
  
  Config files (`nuxt.config.ts`, `tailwind.config.js`, `content.config.ts`), `public/`, `server/`, and `content/` stay at root.

- [x] **0.3 Rename `nuxt.config.js` to `nuxt.config.ts`** -- Convert to TypeScript syntax. Update `compatibilityDate` to `'2025-07-15'`. Remove the deprecated `target: 'static'` option (static generation is now controlled by using `nuxi generate`). Remove `generate.fallback` (not needed for static). Keep `ssr: true` and `components: true`.

- [x] **0.4 Run the optional codemod migration** -- Run `npx codemod@latest nuxt/4/migration-recipe` to auto-fix common breaking changes. Then verify the site builds and runs with `npx nuxt dev`.

- [x] **0.5 Update Tailwind content paths** -- In `tailwind.config.js:3-9`, update paths to reflect `app/` structure: `"./app/components/**/*.{js,vue,ts}"`, `"./app/layouts/**/*.vue"`, `"./app/pages/**/*.vue"`, `"./app/plugins/**/*.{js,ts}"`, `"./app/app.vue"`, `"./app/error.vue"`.

### Phase 1: Dependencies & Content Module Setup

- [x] **1.1 Install @nuxt/content v3** -- Run `npm install @nuxt/content`. For static generation, Nuxt Content v3 uses SQLite at **build time only** (during `nuxi generate`) to process content into pre-rendered HTML. At runtime, client-side navigation uses **WASM SQLite bundled automatically** in the browser -- no server, no D1, no `better-sqlite3`. The build machine (local or CI) needs Node.js which has built-in SQLite support since v22.5.0, or the module will prompt for a connector during dev.

- [x] **1.2 Register @nuxt/content in nuxt.config.ts** -- Add `'@nuxt/content'` to the `modules` array. **Do not set any Nitro preset** -- the default works for static generation. Configure the content module with Shiki code highlighting using a dark theme (e.g., `github-dark` or `vitesse-dark`). Add highlight config with relevant languages (js, ts, vue, bash, json, md, css, html, python, go, rust, solidity). Remove the old `build.html.minify` block (Nitro handles this).

- [x] **1.3 Create `content.config.ts`** -- Define a `blog` collection at the project root:
  ```
  import { defineContentConfig, defineCollection } from '@nuxt/content'
  import { z } from 'zod'

  export default defineContentConfig({
    collections: {
      blog: defineCollection({
        type: 'page',
        source: 'blog/*.md',
        schema: z.object({
          title: z.string(),
          description: z.string(),
          date: z.string(),
          tags: z.array(z.string()).optional(),
          image: z.string().optional(),
          draft: z.boolean().optional(),
        })
      })
    }
  })
  ```
  Any `.md` file added to `content/blog/` is automatically picked up, parsed, and queryable. The `type: 'page'` creates a 1-to-1 mapping between content files and routes.

- [x] **1.4 Update build scripts in `package.json`** -- Ensure the `generate` script uses `nuxi generate` (it already does at `package.json:9`). This is the command that produces the static `dist/` directory. All content pages are pre-rendered by Nuxt's internal crawler. No changes needed to the existing script, but verify it works after the Nuxt 4 upgrade.

### Phase 2: Font & Typography Setup

- [x] **2.1 Add Bricolage Grotesque font** -- Download the Bricolage Grotesque variable font from Google Fonts (woff2 format) and place it in `public/fonts/`. Register it via `@font-face` in `app/assets/css/main.css`. Use `font-display: swap`. Include the full variable weight range (200-800).

- [x] **2.2 Update Tailwind font configuration** -- In `tailwind.config.js`, add a new font family entry: `"display": ['Bricolage Grotesque', 'system-ui', 'sans-serif']`. Keep Iosevka as `sans` for the rest of the site. The blog uses `font-display` for headings.

### Phase 3: Blog Pages & Routing

- [x] **3.1 Create `app/pages/blog/index.vue`** -- The blog listing page. Query all blog posts with `queryCollection('blog')`, sorted by date descending, filtering out drafts. Display as a list of post cards. Each card shows: title, date, description, tags. Cards use the liquid glassy design (Phase 4). Solid `#000000` black background with sparkle canvas.

- [x] **3.2 Create `app/pages/blog/[...slug].vue`** -- Individual blog post page using Nuxt's catch-all route. Use `queryCollection('blog').path(route.path).first()` to fetch the post. Render with `<ContentRenderer :value="post" />`. Include: post title in Bricolage Grotesque, date/tags metadata, reading time estimate, back-to-blog link. Apply `useSeoMeta()` for SEO.

- [x] **3.3 Update header.vue navigation** -- Modify `app/components/header.vue` to add `{ label: 'Blog', href: '/blog' }` to `menuItems`. Change existing anchor links from `#about` to `/#about` so they work from any page.

### Phase 4: Visual Design -- Liquid Glass & Sparkles

- [x] **4.1 Create SparkleBackground component** -- `app/components/SparkleBackground.vue`: a full-page canvas behind blog content. Small white/warm-white dots that subtly twinkle (opacity oscillation) on pure `#000000` black. Canvas with `position: fixed; inset: 0; z-index: 0; pointer-events: none`. Generate ~80-120 particles with random positions, sizes (0.5-2px), phase offsets. Animate with `requestAnimationFrame` + `sin()` for gentle opacity pulsing. White or slightly warm-tinted (`rgba(255, 255, 250, opacity)`). **No colors, no trails, no movement** -- just static twinkling. Respect `prefers-reduced-motion`.

- [x] **4.2 Define liquid glass CSS utility classes** -- In `app/assets/css/main.css`:
  - `background: rgba(255, 255, 255, 0.03)`
  - `backdrop-filter: blur(12px)` 
  - `border: 1px solid rgba(255, 255, 255, 0.08)`
  - `border-radius: 16px`
  - Top-edge highlight: `border-top: 1px solid rgba(255, 255, 255, 0.12)`
  - `box-shadow: 0 4px 30px rgba(0, 0, 0, 0.3)`
  - Hover: border opacity `0.12`, background `0.05`
  - **No colored tints, no gradients** -- orange accent (`#FF885B`) for links/interactive only

- [x] **4.3 Style blog post listing cards** -- Liquid glass cards. Vertical stack: title (Bricolage Grotesque, bold, ~1.5rem), date (Iosevka, small, muted), description (2-3 lines, `text-zinc-400`), tags as small glass pills. Single-column mobile, two columns desktop. Max width ~800px centered.

- [x] **4.4 Style blog post content (prose)** -- Custom prose styles for `<ContentRenderer>` output:
  - `h1`: Bricolage Grotesque, 2.5rem, font-weight 700, white
  - `h2`: Bricolage Grotesque, 1.75rem, font-weight 600, bottom border `rgba(255,255,255,0.08)`
  - `h3`: Bricolage Grotesque, 1.35rem, font-weight 600
  - `p`: 1rem, `text-zinc-300`, line-height 1.75
  - `a`: `color: #FF885B`, underline on hover
  - `code` inline: `bg-zinc-800/60`, monospace
  - `pre`: `bg-zinc-900`, border `rgba(255,255,255,0.06)`, border-radius 12px
  - `blockquote`: left border `2px solid #FF885B`, `bg-rgba(255,255,255,0.02)`
  - `img`: border-radius 12px, max-width 100%
  - Content max-width: ~720px, centered

### Phase 5: Blog-Specific Components (MDC)

- [x] **5.1 Create `app/components/content/Diagram.vue`** -- Vue component usable in Markdown via `::diagram`. Styled container for diagrams (centered, padded, glass border). Props: `caption`, `width`.

- [x] **5.2 Create `app/components/content/Callout.vue`** -- Callout component for `::callout{type="info"}`. Types: `info`, `warning`, `tip`. Glass aesthetic with tinted left border.

- [x] **5.3 Create a sample blog post** -- `content/blog/hello-world.md` with frontmatter, various Markdown elements, and `::callout` usage.

### Phase 6: RSS Feed & SEO

- [x] **6.1 Add RSS feed generation** -- Create `server/routes/feed.xml.ts` to generate RSS at `/feed.xml`. During `nuxi generate`, Nuxt pre-renders this server route into a static XML file in `dist/feed.xml`. No runtime server needed.

- [x] **6.2 Add SEO metadata to blog pages** -- `useSeoMeta()` and `useHead()` on each blog post page: title, description, og tags, article:published_time, twitter:card.

- [x] **6.3 Add RSS autodiscovery link** -- In `nuxt.config.ts`, add `<link rel="alternate" type="application/rss+xml">` to head.

### Phase 7: Cloudflare Pages Deployment

- [x] **7.1 Configure Cloudflare Pages project** -- In the Cloudflare dashboard:
  1. Create a Pages project connected to the Git repository
  2. Set build command to `npx nuxi generate`
  3. Set build output directory to `dist/`
  4. **No D1 database needed** -- the site is fully static
  5. No Functions, no Workers -- just static file hosting

- [x] **7.2 Set Node.js version for build** -- Set the `NODE_VERSION` environment variable to `22` in Cloudflare Pages project settings (or add a `.node-version` file with `22`). Node 22.5.0+ has built-in SQLite which Nuxt Content uses at build time to process content into static HTML. This avoids needing `better-sqlite3`.

- [x] **7.3 Verify build and deployment** -- Run `npx nuxi generate` locally. Verify `dist/` contains pre-rendered HTML for all blog posts (check `dist/blog/hello-world/index.html` exists). Push to trigger Cloudflare Pages deployment. Verify all routes work.

## Verification Criteria

- Dropping a new `.md` file into `content/blog/` and running `nuxi generate` produces a static HTML page at `dist/blog/<slug>/index.html`
- Blog listing at `/blog` shows all posts sorted by date, newest first, with working links
- Vue components (like `::callout`) render correctly inside Markdown posts
- Code blocks have syntax highlighting with a dark theme
- Client-side navigation between blog posts works (WASM SQLite handles queries in browser)
- The sparkle background renders without performance issues (smooth 60fps)
- Glass card effects are visible and subtle -- no color gradients, no purple
- Bricolage Grotesque is used for blog headings, Iosevka for body/code
- RSS feed is a static file at `dist/feed.xml` with valid XML
- `npx nuxi generate` succeeds with zero runtime dependencies (no better-sqlite3, no D1)
- Cloudflare Pages serves the static `dist/` output correctly
- The header "Blog" link works from any page on the site
- Mobile responsive: blog listing and posts render well on small screens
- Nuxt 4 `app/` directory structure is properly adopted

## Potential Risks and Mitigations

1. **Nuxt 3 -> 4 migration breaking existing pages**
   Mitigation: Nuxt 4 is a smooth upgrade. The existing `index.vue` and `gallery.vue` use standard Composition API. The `gallery.vue` page uses `import('node:fs/promises')` at `pages/gallery.vue:61` -- this runs at build time during pre-rendering and works fine. Run the codemod to catch subtle API changes.

2. **SQLite connector needed at build time**
   Mitigation: Nuxt Content v3 needs SQLite at build time to index content. Use Node.js 22.5.0+ which has **native SQLite built in** -- no npm package needed. Set `NODE_VERSION=22` in Cloudflare Pages build settings. For local dev, the same applies -- use Node 22+. If stuck on an older Node, the module will prompt to install `better-sqlite3` as a dev dependency for local builds only (it's never deployed).

3. **WASM SQLite bundle size for client-side navigation**
   Mitigation: Nuxt Content v3 automatically bundles a WASM SQLite for client-side queries during SPA navigation. This adds ~500KB-1MB to the initial static assets. Since all pages are pre-rendered as HTML, the first page load doesn't need it -- it only loads on client-side navigation. This is acceptable for a blog.

4. **Canvas sparkle performance on mobile**
   Mitigation: Reduce particle count on mobile. Animation is lightweight (opacity changes only). Add `prefers-reduced-motion` check.

5. **Bricolage Grotesque font loading / FOUT**
   Mitigation: `font-display: swap` in `@font-face`. Preload the font file via `<link rel="preload">` in `nuxt.config.ts` head config. Self-hosted, no CDN dependency.

6. **Existing header navigation breaking for blog pages**
   Mitigation: Change anchor links from `#about` to `/#about` so they route back to homepage sections from any page.

7. **Pre-rendered RSS feed**
   Mitigation: Server routes defined in `server/routes/` are pre-rendered as static files during `nuxi generate`. The RSS endpoint at `server/routes/feed.xml.ts` becomes `dist/feed.xml`. No runtime server needed.

## Alternative Approaches

1. **SSR on Cloudflare Pages with D1**: Could deploy as a server-rendered app with a D1 database. More complex setup, but enables dynamic content without rebuilding. Not needed for a personal blog where content only changes at deploy time.

2. **Use @nuxt/content v2 instead of v3**: v2 doesn't need SQLite at all (pure filesystem). However, v3 is the current recommended version with better TypeScript support and collection-based architecture.

3. **CSS-only sparkle instead of canvas**: Simpler but lacks twinkling animation. Canvas is more elegant for this effect.

4. **Google Fonts CDN instead of self-hosting**: Auto-handles font loading but adds third-party dependency. Self-hosting is better for privacy and reliability.

## File Structure After Implementation

```
nik.technology/
  app/
    assets/
      css/
        main.css                    # Glass utilities, prose styles, font-face
    components/
      header.vue                    # Updated with Blog nav link
      SparkleBackground.vue         # Canvas sparkle effect
      content/
        Diagram.vue                 # MDC diagram component
        Callout.vue                 # MDC callout component
    pages/
      index.vue                     # Existing homepage (moved to app/)
      gallery.vue                   # Existing gallery (moved to app/)
      blog/
        index.vue                   # Blog listing page
        [...slug].vue               # Individual blog post page
    app.vue                         # Main app shell (moved to app/)
  content/
    blog/
      hello-world.md                # Sample post
  server/
    routes/
      feed.xml.ts                   # RSS feed (pre-rendered to static XML)
  public/
    fonts/
      BricolageGrotesque-Variable.woff2
    (existing assets remain)
  content.config.ts                 # Collection definitions
  nuxt.config.ts                    # Nuxt 4, @nuxt/content, no preset (static)
  tailwind.config.js                # Updated with font-display, app/ paths
  package.json                      # nuxt ^4.0.0, @nuxt/content
```

### Build & Deploy Flow
```
npx nuxi generate
  -> Node.js 22 native SQLite indexes content at build time
  -> Nuxt crawler pre-renders all pages to dist/
  -> WASM SQLite database bundled for client-side nav
  -> dist/feed.xml generated from server route
  -> dist/ uploaded to Cloudflare Pages (static files only)
```
