# Blog System for nik.technology

## Objective

Upgrade the existing Nuxt 3.13 personal website to **Nuxt 4**, add a fully functional blog system powered by **@nuxt/content v3**, and deploy to **Cloudflare Pages** with a D1 database. The blog supports Markdown + Vue components (MDC syntax), auto-discovery of posts, and features a distinctive visual design: solid black background with sparkles, Bricolage Grotesque font, and a liquid/glassy aesthetic. No vibeslop.

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
- **Deployment**: Currently static; moving to Cloudflare Pages (server-rendered with D1)

### Key Design Observations
- The existing site uses a dark zinc/black palette with orange (`#FF885B`) accents
- Monospace font (Iosevka) is the current default
- Cards use `bg-zinc-800` with `border-zinc-950` borders
- The header nav links to anchor sections on the homepage -- this needs to become route-aware for blog pages

## Implementation Plan

### Phase 0: Nuxt 4 Upgrade

- [ ] **0.1 Upgrade Nuxt to v4** -- Run `npx nuxt upgrade --dedupe` to update to Nuxt 4.x. This pulls in the latest Nuxt along with its ecosystem dependencies (Nitro, h3, etc.). Update `package.json` to pin `nuxt` to `^4.0.0`. Remove the pinned `vue` and `vue-router` `latest` entries since Nuxt 4 manages its own Vue version. **Rationale**: Nuxt 4 brings the new `app/` directory structure, improved TypeScript separation, faster CLI, and better data fetching -- all beneficial for a content-heavy site.

- [ ] **0.2 Adopt the `app/` directory structure** -- Nuxt 4's primary structural change is moving application code into an `app/` directory. Move the following:
  - `pages/` -> `app/pages/`
  - `components/` -> `app/components/`
  - `assets/` -> `app/assets/`
  - `app.vue` -> `app/app.vue`
  
  Nuxt 4 auto-detects the old structure and works without migration, but adopting the new layout is recommended for new development. The `public/`, `server/`, `content/`, and config files (`nuxt.config.ts`, `tailwind.config.js`, `content.config.ts`) stay at root.

- [ ] **0.3 Rename `nuxt.config.js` to `nuxt.config.ts`** -- Nuxt 4 emphasizes TypeScript-first configuration. Rename the config file and convert to TypeScript syntax. Update the `compatibilityDate` to `'2025-07-15'` (Nuxt 4 release date). Remove the deprecated `target: 'static'` option (replaced by Nitro preset configuration). Remove `generate.fallback` (not applicable for Cloudflare Pages deployment). Keep `ssr: true` and `components: true`.

- [ ] **0.4 Run the optional codemod migration** -- Run `npx codemod@latest nuxt/4/migration-recipe` to auto-fix common breaking changes (import paths, composable API changes, etc.). Then verify the site builds and runs correctly with `npx nuxt dev`.

- [ ] **0.5 Update Tailwind content paths** -- In `tailwind.config.js:3-9`, update the content paths to reflect the new `app/` directory structure: `"./app/components/**/*.{js,vue,ts}"`, `"./app/layouts/**/*.vue"`, `"./app/pages/**/*.vue"`, `"./app/plugins/**/*.{js,ts}"`, `"./app/app.vue"`, `"./app/error.vue"`. This ensures Tailwind scans the correct directories for class usage.

### Phase 1: Dependencies & Content Module Setup

- [ ] **1.1 Install @nuxt/content v3** -- Run `npm install @nuxt/content`. Nuxt Content v3 uses SQLite internally for content indexing and querying. On Cloudflare Pages, this is handled by Cloudflare D1 (a serverless SQLite database), so **no `better-sqlite3` or `sqlite3` package is needed** -- D1 is the database connector at runtime. During local development (`nuxt dev`), the module uses a local SQLite file automatically.

- [ ] **1.2 Register @nuxt/content and configure Nitro for Cloudflare Pages** -- Update `nuxt.config.ts`:
  - Add `'@nuxt/content'` to the `modules` array
  - Set `nitro.preset` to `'cloudflare_pages'`
  - Configure content module with Shiki code highlighting using a dark theme (e.g., `github-dark` or `vitesse-dark`). Add highlight config with relevant languages (js, ts, vue, bash, json, md, css, html, python, go, rust, solidity)
  - Remove the old `build.html.minify` block (Nitro handles this)
  - Remove `postcss` config block if Nuxt 4 + Tailwind 4 handles it automatically, or keep if still on Tailwind 3

- [ ] **1.3 Create `content.config.ts`** -- Define a `blog` collection at the project root:
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
  This makes posts auto-discoverable: any `.md` file added to `content/blog/` is automatically picked up, parsed, and queryable. The `type: 'page'` creates a 1-to-1 mapping between content files and routes.

- [ ] **1.4 Create `wrangler.jsonc` for local preview** -- Add a Wrangler config at project root to enable `nuxt preview` locally with a D1 binding:
  ```jsonc
  {
    "d1_databases": [
      {
        "binding": "DB",
        "database_name": "nik-technology-content",
        "database_id": "local-dev-id"
      }
    ]
  }
  ```
  This is only needed for `nuxt preview` (testing the production build locally). `nuxt dev` works without it.

### Phase 2: Font & Typography Setup

- [ ] **2.1 Add Bricolage Grotesque font** -- Download the Bricolage Grotesque variable font from Google Fonts (woff2 format) and place it in `public/fonts/`. Register it via `@font-face` in `app/assets/css/main.css`. Include weights 400 (regular) and 700 (bold) at minimum, or use the variable font file for full weight range. Use `font-display: swap`.

- [ ] **2.2 Update Tailwind font configuration** -- In `tailwind.config.js`, add a new font family entry: `"display": ['Bricolage Grotesque', 'system-ui', 'sans-serif']`. Keep Iosevka as `sans` (the existing monospace default) for the rest of the site. The blog will use `font-display` for headings and `font-sans` for body text, giving the blog a distinct typographic identity while preserving the existing site feel.

### Phase 3: Blog Pages & Routing

- [ ] **3.1 Create `app/pages/blog/index.vue`** -- The blog listing page. Query all blog posts with `queryCollection('blog')`, sorted by date descending, filtering out drafts. Display as a grid/list of post cards. Each card shows: title, date, description, tags, and an optional cover image. Cards use the liquid glassy design (see Phase 4). The page has a solid `#000000` black background with the sparkle canvas effect.

- [ ] **3.2 Create `app/pages/blog/[...slug].vue`** -- The individual blog post page using Nuxt's catch-all route. Use `queryCollection('blog').path(route.path).first()` to fetch the post. Render with `<ContentRenderer :value="post" />`. Include: post title in Bricolage Grotesque, date/tags metadata, reading time estimate, and a back-to-blog link. Apply `useSeoMeta()` with the post's title and description for proper SEO/social sharing.

- [ ] **3.3 Update header.vue navigation** -- Modify `app/components/header.vue` to add a "Blog" link to the `menuItems` array: `{ label: 'Blog', href: '/blog' }`. Also change existing anchor links from `#about` to `/#about` so they work from any page (not just the homepage). This makes blog accessible from the site-wide navigation.

### Phase 4: Visual Design -- Liquid Glass & Sparkles

- [ ] **4.1 Create SparkleBackground component** -- An `app/components/SparkleBackground.vue` component that renders a full-page canvas behind blog content. The effect: small white/warm-white dots that subtly twinkle (opacity oscillation) on a pure `#000000` black background. Implementation: use a `<canvas>` element with `position: fixed; inset: 0; z-index: 0; pointer-events: none`. On mount, generate ~80-120 particles with random positions, sizes (0.5-2px), and phase offsets. Animate with `requestAnimationFrame`, using `sin()` for gentle opacity pulsing. Particles should be white or very slightly warm-tinted (`rgba(255, 255, 250, opacity)`). **No colors, no trails, no movement** -- just static twinkling points, like a night sky. Keep it understated. Respect `prefers-reduced-motion`.

- [ ] **4.2 Define liquid glass CSS utility classes** -- In `app/assets/css/main.css`, create reusable classes for the glassy card effect:
  - `background: rgba(255, 255, 255, 0.03)` (very subtle white tint on black)
  - `backdrop-filter: blur(12px)` 
  - `border: 1px solid rgba(255, 255, 255, 0.08)` (faint white border)
  - `border-radius: 16px`
  - A subtle top-edge highlight: `border-top: 1px solid rgba(255, 255, 255, 0.12)` to simulate light refraction
  - `box-shadow: 0 4px 30px rgba(0, 0, 0, 0.3)` for depth
  - On hover: slightly increase the border opacity to `0.12` and background to `0.05`
  - **No colored tints, no gradients** -- purely monochrome with the orange accent (`#FF885B`) reserved for links and interactive elements only

- [ ] **4.3 Style blog post listing cards** -- Each card on `/blog` uses the liquid glass treatment. Layout: a clean vertical stack -- title (Bricolage Grotesque, bold, ~1.5rem), date in monospace (Iosevka, small, muted), description (2-3 lines, `text-zinc-400`), and tags as small glass pills. Cards arranged in a single-column layout on mobile, two columns on larger screens. Max width ~800px centered.

- [ ] **4.4 Style blog post content (prose)** -- Create custom prose/typography styles for the rendered Markdown content on individual post pages. Target the `<ContentRenderer>` output:
  - `h1`: Bricolage Grotesque, 2.5rem, font-weight 700, white, generous top margin
  - `h2`: Bricolage Grotesque, 1.75rem, font-weight 600, white, `border-bottom: 1px solid rgba(255,255,255,0.08)`, padding-bottom
  - `h3`: Bricolage Grotesque, 1.35rem, font-weight 600
  - `p`: Iosevka/system font, 1rem, `text-zinc-300`, line-height 1.75
  - `a`: `color: #FF885B` (the existing accent), underline on hover
  - `code` (inline): `bg-zinc-800/60`, `text-zinc-200`, small border-radius, monospace
  - `pre` (code blocks): `bg-zinc-900`, border `1px solid rgba(255,255,255,0.06)`, border-radius 12px, padding
  - `blockquote`: left border `2px solid #FF885B`, `bg-rgba(255,255,255,0.02)`, italic, padding
  - `ul/ol`: standard spacing, `text-zinc-300`, custom bullet color
  - `img`: border-radius 12px, subtle border, max-width 100%
  - `hr`: `border-color: rgba(255,255,255,0.08)`
  - `table`: glass-style borders, alternating row subtle backgrounds
  - Overall content max-width: ~720px, centered, with comfortable padding

### Phase 5: Blog-Specific Components (MDC)

- [ ] **5.1 Create `app/components/content/Diagram.vue`** -- A reusable Vue component usable inside Markdown via MDC syntax (e.g., `::diagram`). This wraps content in a styled container suitable for diagrams (centered, padded, glass border). Accepts props like `caption` and `width`.

- [ ] **5.2 Create `app/components/content/Callout.vue`** -- A callout/note component for use in blog posts (e.g., `::callout{type="info"}`). Supports types: `info`, `warning`, `tip`. Styled with the glass aesthetic and a subtle left border tinted with the appropriate color (info = blue-ish white, warning = amber, tip = accent orange).

- [ ] **5.3 Create a sample blog post** -- Add `content/blog/hello-world.md` as a template/example post demonstrating the system works. Include frontmatter (title, description, date, tags), various Markdown elements (headings, code blocks, links, lists, blockquote), and usage of the custom `::callout` component. This serves as both a test and a template for future posts.

### Phase 6: RSS Feed & SEO

- [ ] **6.1 Add RSS/Atom feed generation** -- Create `server/routes/feed.xml.ts` to generate an RSS feed at `/feed.xml`. Query all published blog posts, format as RSS 2.0 XML. Include title, link, description, pubDate for each item. This makes the blog discoverable by RSS readers. This server route runs on Cloudflare Pages Functions.

- [ ] **6.2 Add SEO metadata to blog pages** -- Ensure each blog post page uses `useSeoMeta()` and `useHead()` to set:
  - `title`: Post title + site name
  - `description`: Post description
  - `og:title`, `og:description`, `og:image` (if cover image exists)
  - `og:type`: "article"
  - `article:published_time`: Post date
  - `twitter:card`: "summary_large_image"
  
  The blog listing page should also have its own meta tags.

- [ ] **6.3 Add `<link rel="alternate" type="application/rss+xml">` to head** -- In `nuxt.config.ts`, add the RSS autodiscovery link so browsers/readers can find the feed automatically.

### Phase 7: Cloudflare Pages Deployment Setup

- [ ] **7.1 Configure Cloudflare Pages project** -- In the Cloudflare dashboard:
  1. Create a new Pages project connected to the Git repository
  2. Set build command to `npx nuxt build` (Nitro preset `cloudflare_pages` is already set in config)
  3. Set build output directory to `dist/`
  4. Create a D1 database (e.g., `nik-technology-content`)
  5. Bind the D1 database to the Pages project with binding name `DB` (the default Nuxt Content expects)

- [ ] **7.2 Add `.node-version` or environment variable** -- Ensure the Cloudflare Pages build environment uses Node.js 20+ (required by Nuxt 4). Set the `NODE_VERSION` environment variable to `20` in the Cloudflare Pages project settings, or add a `.node-version` file with `20` at the project root.

- [ ] **7.3 Verify build and deployment** -- Run `npx nuxt build` locally to verify the Cloudflare Pages preset produces correct output. Test locally with `npx nuxt preview` (requires `wrangler.jsonc` from step 1.4). Then push to trigger a Cloudflare Pages deployment. Verify the D1 database is populated with content and all blog routes work.

## Verification Criteria

- Dropping a new `.md` file into `content/blog/` with proper frontmatter automatically creates a new blog post accessible at `/blog/<slug>` with no additional configuration
- Blog listing at `/blog` shows all posts sorted by date, newest first, with working links
- Vue components (like `::callout`) render correctly inside Markdown posts
- Code blocks have syntax highlighting with a dark theme
- The sparkle background renders on blog pages without performance issues (smooth 60fps)
- Glass card effects are visible and subtle -- no color gradients, no purple
- Bricolage Grotesque is used for blog headings, Iosevka for body/code
- RSS feed is accessible at `/feed.xml` with valid XML
- `npx nuxt build` succeeds with the `cloudflare_pages` preset
- The site deploys to Cloudflare Pages and the D1 database serves content correctly
- The header "Blog" link works from any page on the site
- Mobile responsive: blog listing and posts render well on small screens
- The Nuxt 4 `app/` directory structure is properly adopted

## Potential Risks and Mitigations

1. **Nuxt 3 -> 4 migration breaking existing pages**
   Mitigation: Nuxt 4 is designed as a smooth upgrade from Nuxt 3. The existing `index.vue` and `gallery.vue` use standard Composition API patterns that are fully compatible. The main risk is the `gallery.vue` page which uses `import('node:fs/promises')` for reading gallery files at `pages/gallery.vue:61` -- this server-side file read pattern works with SSR and will continue to work on Cloudflare Pages since it runs at build/request time in the Nitro server context. Run the codemod to catch any subtle API changes.

2. **Cloudflare D1 database binding at deploy time**
   Mitigation: The D1 database must be created and bound to the Pages project **before** the first deployment that includes Nuxt Content. If the binding is missing, content queries will fail at runtime. The `wrangler.jsonc` file handles this for local preview. For production, this is a manual one-time setup in the Cloudflare dashboard.

3. **No `better-sqlite3` needed for Cloudflare Pages**
   Mitigation: Unlike Node.js deployments that require `better-sqlite3` or native SQLite, Cloudflare Pages uses D1 as the database backend. Nuxt Content v3 auto-detects the Cloudflare environment and uses D1. Do **not** install `better-sqlite3` -- it contains native bindings that won't work in the Cloudflare Workers runtime. If local dev requires a SQLite connector, Nuxt Content handles it transparently.

4. **Canvas sparkle performance on mobile**
   Mitigation: Reduce particle count on mobile (detect via viewport width). The animation is lightweight (just opacity changes, no particle movement), so performance should be fine. Add a `prefers-reduced-motion` media query check to disable animation for accessibility.

5. **Bricolage Grotesque font loading / FOUT**
   Mitigation: Use `font-display: swap` in the `@font-face` declaration. Preload the font file with `<link rel="preload">` in `nuxt.config.ts` head configuration. Self-hosted for reliability (no third-party CDN dependency).

6. **Existing header navigation breaking for blog pages**
   Mitigation: Change anchor links from `#about` to `/#about` format so they navigate back to the homepage section when clicked from `/blog` or any other page.

7. **Cloudflare Pages build size / function limits**
   Mitigation: Cloudflare Pages Functions have a 25MB compressed limit. A Nuxt site with Content is well within this. The D1 database has a 10GB limit on the free tier, which is more than sufficient for blog content.

## Alternative Approaches

1. **Static generation (`nuxt generate`) instead of Cloudflare Pages SSR**: Could use `nuxt generate` to produce a fully static site deployed to Cloudflare Pages without D1. However, Nuxt Content v3 requires a database for its query engine, so D1 is the correct approach for Cloudflare. Pre-rendering specific routes is still possible alongside D1.

2. **Cloudflare Workers instead of Cloudflare Pages**: Workers offer more control but Pages provides a simpler deployment flow with Git integration, preview deployments, and automatic builds. Pages is the better choice for a personal blog site.

3. **Use @nuxt/content v2 instead of v3**: v2 uses the filesystem directly without SQLite/D1. However, v3 is the current recommended version, works natively with Cloudflare D1, and provides the collection-based architecture with schema validation.

4. **CSS-only sparkle effect instead of canvas**: Could use CSS `background-image` with radial gradients to simulate stars. Simpler, no JS overhead. But lacks the subtle twinkling animation. Canvas is more elegant for this specific effect.

## File Structure After Implementation

```
nik.technology/
  app/
    assets/
      css/
        main.css                    # Updated with glass utilities, prose styles, font-face
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
      feed.xml.ts                   # RSS feed endpoint
  public/
    fonts/
      BricolageGrotesque-Variable.woff2  # Self-hosted font
    (existing assets remain)
  content.config.ts                 # Collection definitions
  nuxt.config.ts                    # Updated: Nuxt 4, @nuxt/content, Cloudflare preset
  tailwind.config.js                # Updated with font-display family, app/ paths
  wrangler.jsonc                    # D1 binding for local preview
  package.json                      # Updated: nuxt ^4.0.0, @nuxt/content
```
