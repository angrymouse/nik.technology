# Blog System for nik.technology

## Objective

Add a fully functional blog system to the existing Nuxt 3 personal website at nik.technology. The blog must support Markdown + Vue components (MDC syntax), auto-discovery of posts, and feature a distinctive visual design: solid black background with sparkles, Bricolage Grotesque font, and a liquid/glassy aesthetic. The design must be tasteful and intentional -- absolutely no "vibeslop" (no purple gradients, no generic AI-generated aesthetic).

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

### Key Design Observations
- The existing site uses a dark zinc/black palette with orange (`#FF885B`) accents
- Monospace font (Iosevka) is the current default
- Cards use `bg-zinc-800` with `border-zinc-950` borders
- The header nav links to anchor sections on the homepage -- this needs to become route-aware for blog pages

## Implementation Plan

### Phase 1: Dependencies & Module Setup

- [ ] **1.1 Install @nuxt/content v3** -- This is the official Nuxt module that enables file-based Markdown+Vue content. It provides the `queryCollection` API, `ContentRenderer` component, MDC syntax support (Vue components in Markdown), and automatic content discovery from the `content/` directory. Run: `npm install @nuxt/content`

- [ ] **1.2 Register @nuxt/content in nuxt.config.js** -- Add `'@nuxt/content'` to the `modules` array in `nuxt.config.js:13`. Also configure the content module with Shiki code highlighting using a dark theme (e.g., `vitesse-dark` or `github-dark`) that fits the black background aesthetic. Add highlight configuration with relevant languages (js, ts, vue, bash, json, markdown, css, html, python, go, rust, solidity).

- [ ] **1.3 Create content.config.ts** -- Define a `blog` collection at the project root:
  ```
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
  ```
  This makes posts auto-discoverable: any `.md` file added to `content/blog/` is automatically picked up, parsed, and queryable. The `type: 'page'` creates a 1-to-1 mapping between content files and routes.

### Phase 2: Font & Typography Setup

- [ ] **2.1 Add Bricolage Grotesque font** -- Download the Bricolage Grotesque variable font from Google Fonts (woff2 format) and place it in `public/fonts/`. Register it via `@font-face` in `assets/css/main.css`. Include weights 400 (regular) and 700 (bold) at minimum, or use the variable font file for full weight range.

- [ ] **2.2 Update Tailwind font configuration** -- In `tailwind.config.js:13-14`, add a new font family entry: `"display": ['Bricolage Grotesque', 'system-ui', 'sans-serif']`. Keep Iosevka as `sans` (the existing monospace default) for the rest of the site. The blog will use `font-display` for headings and `font-sans` for body text, giving the blog a distinct typographic identity while preserving the existing site feel.

### Phase 3: Blog Pages & Routing

- [ ] **3.1 Create `pages/blog/index.vue`** -- The blog listing page. Query all blog posts with `queryCollection('blog')`, sorted by date descending, filtering out drafts. Display as a grid/list of post cards. Each card shows: title, date, description, tags, and an optional cover image. Cards use the liquid glassy design (see Phase 4). The page has a solid `#000000` black background with the sparkle canvas effect.

- [ ] **3.2 Create `pages/blog/[...slug].vue`** -- The individual blog post page using Nuxt's catch-all route. Use `queryCollection('blog').path(route.path).first()` to fetch the post. Render with `<ContentRenderer :value="post" />`. Include: post title in Bricolage Grotesque, date/tags metadata, reading time estimate, and a back-to-blog link. Apply `useSeoMeta()` with the post's title and description for proper SEO/social sharing.

- [ ] **3.3 Update header.vue navigation** -- Modify `components/header.vue:47-52` to add a "Blog" link to the `menuItems` array. Since the existing links are anchor links (`#about`, `#skills`, etc.) which only work on the homepage, the Blog link should be `{ label: 'Blog', href: '/blog' }`. This makes blog accessible from the site-wide navigation.

### Phase 4: Visual Design -- Liquid Glass & Sparkles

- [ ] **4.1 Create SparkleBackground component** -- A `components/SparkleBackground.vue` component that renders a full-page canvas behind blog content. The effect: small white/warm-white dots that subtly twinkle (opacity oscillation) on a pure `#000000` black background. Implementation: use a `<canvas>` element with `position: fixed; inset: 0; z-index: 0; pointer-events: none`. On mount, generate ~80-120 particles with random positions, sizes (0.5-2px), and phase offsets. Animate with `requestAnimationFrame`, using `sin()` for gentle opacity pulsing. Particles should be white or very slightly warm-tinted (`rgba(255, 255, 250, opacity)`). **No colors, no trails, no movement** -- just static twinkling points, like a night sky. Keep it understated.

- [ ] **4.2 Define liquid glass CSS utility classes** -- In `assets/css/main.css`, create reusable classes for the glassy card effect. The "liquid glass" look is achieved with:
  - `background: rgba(255, 255, 255, 0.03)` (very subtle white tint on black)
  - `backdrop-filter: blur(12px)` 
  - `border: 1px solid rgba(255, 255, 255, 0.08)` (faint white border)
  - `border-radius: 16px`
  - A subtle top-edge highlight: `border-top: 1px solid rgba(255, 255, 255, 0.12)` to simulate light refraction
  - `box-shadow: 0 4px 30px rgba(0, 0, 0, 0.3)` for depth
  - On hover: slightly increase the border opacity to `0.12` and background to `0.05`
  - **No colored tints, no gradients** -- purely monochrome with the orange accent (`#FF885B`) reserved for links and interactive elements only

- [ ] **4.3 Style blog post listing cards** -- Each card on `/blog` uses the liquid glass treatment. Layout: a clean vertical stack -- title (Bricolage Grotesque, bold, ~1.5rem), date in monospace (Iosevka, small, muted), description (2-3 lines, `text-zinc-400`), and tags as small glass pills. Cards arranged in a single-column layout on mobile, two columns on larger screens. Max width ~800px centered.

- [ ] **4.4 Style blog post content (prose)** -- Create custom prose/typography styles for the rendered Markdown content on individual post pages. Target the `<ContentRenderer>` output. Styles should include:
  - `h1`: Bricolage Grotesque, 2.5rem, font-weight 700, white, with generous top margin
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

- [ ] **5.1 Create `components/content/Diagram.vue`** -- A reusable Vue component usable inside Markdown via MDC syntax (e.g., `::diagram`). This wraps content in a styled container suitable for diagrams (centered, padded, glass border). Could accept props like `caption` and `width`. This is a starting point -- more components can be added later.

- [ ] **5.2 Create `components/content/Callout.vue`** -- A callout/note component for use in blog posts (e.g., `::callout{type="info"}`). Supports types: `info`, `warning`, `tip`. Styled with the glass aesthetic and a subtle left border tinted with the appropriate color (info = blue-ish white, warning = amber, tip = accent orange).

- [ ] **5.3 Create a sample blog post** -- Add `content/blog/hello-world.md` as a template/example post demonstrating the system works. Include frontmatter (title, description, date, tags), various Markdown elements (headings, code blocks, links, lists, blockquote), and usage of the custom `::callout` component. This serves as both a test and a template for future posts.

### Phase 6: RSS Feed & SEO

- [ ] **6.1 Add RSS/Atom feed generation** -- Create `server/routes/feed.xml.ts` (or use a Nuxt Content hook) to generate an RSS feed at `/feed.xml`. Query all published blog posts, format as RSS 2.0 XML. Include title, link, description, pubDate for each item. This makes the blog discoverable by RSS readers.

- [ ] **6.2 Add SEO metadata to blog pages** -- Ensure each blog post page uses `useSeoMeta()` and `useHead()` to set:
  - `title`: Post title + site name
  - `description`: Post description
  - `og:title`, `og:description`, `og:image` (if cover image exists)
  - `og:type`: "article"
  - `article:published_time`: Post date
  - `twitter:card`: "summary_large_image"
  
  The blog listing page should also have its own meta tags.

- [ ] **6.3 Add `<link rel="alternate" type="application/rss+xml">` to head** -- In `nuxt.config.js`, add the RSS autodiscovery link so browsers/readers can find the feed automatically.

## Verification Criteria

- Dropping a new `.md` file into `content/blog/` with proper frontmatter automatically creates a new blog post accessible at `/blog/<slug>` with no additional configuration
- Blog listing at `/blog` shows all posts sorted by date, newest first, with working links
- Vue components (like `::callout`) render correctly inside Markdown posts
- Code blocks have syntax highlighting with a dark theme
- The sparkle background renders on blog pages without performance issues (smooth 60fps)
- Glass card effects are visible and subtle -- no color gradients, no purple
- Bricolage Grotesque is used for blog headings, Iosevka for body/code
- RSS feed is accessible at `/feed.xml` with valid XML
- `nuxt generate` succeeds and produces static HTML for all blog routes
- The header "Blog" link works from any page on the site
- Mobile responsive: blog listing and posts render well on small screens

## Potential Risks and Mitigations

1. **Nuxt Content v3 compatibility with existing Nuxt 3.13**
   Mitigation: Nuxt Content v3 requires Nuxt 3.x and is compatible. If any version conflicts arise, pin `@nuxt/content` to a known compatible version. The existing `@nuxt/image` module has no known conflicts with Content.

2. **Static generation with Nuxt Content**
   Mitigation: Nuxt Content v3 works with `nuxt generate`. Ensure `ssr: true` stays enabled (it is already at `nuxt.config.js:20`). Content routes will be pre-rendered at build time. The SQLite requirement for Content v3 may require `better-sqlite3` -- install it as a dev dependency if needed.

3. **Canvas sparkle performance on mobile**
   Mitigation: Reduce particle count on mobile (detect via viewport width). Use `will-change: transform` sparingly. The animation is lightweight (just opacity changes, no particle movement), so performance should be fine. Add a `prefers-reduced-motion` media query check to disable animation for accessibility.

4. **Bricolage Grotesque font loading / FOUT**
   Mitigation: Use `font-display: swap` in the `@font-face` declaration. Preload the font file with `<link rel="preload">` in `nuxt.config.js` head configuration. The font is loaded locally (not from Google Fonts CDN) for reliability and performance.

5. **Existing header navigation breaking for blog pages**
   Mitigation: The current nav items are anchor links (`#about`, etc.) that only work on the homepage. When navigating to `/blog`, these will need to either: (a) become full links like `/#about` to route back to the homepage section, or (b) remain as-is since they're contextual. Recommend changing them to `/#about` format so they work from any page.

## Alternative Approaches

1. **Use @nuxt/content v2 instead of v3**: v2 is more established and uses a different query API (`queryContent()` instead of `queryCollection()`). However, v3 is the current recommended version with collection-based architecture and better TypeScript support. v3 is the better choice for a new project.

2. **Use a separate static blog generator (e.g., Astro, 11ty) alongside Nuxt**: This would avoid adding complexity to the existing Nuxt project but would create a disjointed experience (different build systems, different styling). Not recommended since Nuxt Content integrates natively.

3. **CSS-only sparkle effect instead of canvas**: Could use CSS `background-image` with radial gradients to simulate stars, avoiding JavaScript entirely. Pros: simpler, no JS overhead. Cons: less dynamic, no twinkling animation (unless using CSS animations on pseudo-elements, which gets complex at scale). Canvas is the more elegant solution for this specific effect.

4. **Use @nuxtjs/google-fonts module for Bricolage Grotesque**: This would auto-handle font loading from Google Fonts CDN. However, self-hosting the font (as planned) gives better privacy, performance (no third-party requests), and reliability. The trade-off is a larger initial download, but woff2 fonts are small (~30-50KB).

## File Structure After Implementation

```
nik.technology/
  content/
    blog/
      hello-world.md              # Sample post
  content.config.ts               # Collection definitions
  components/
    header.vue                    # Updated with Blog nav link
    SparkleBackground.vue         # Canvas sparkle effect
    content/
      Diagram.vue                 # MDC diagram component
      Callout.vue                 # MDC callout component
  pages/
    index.vue                     # Existing homepage (unchanged)
    gallery.vue                   # Existing gallery (unchanged)
    blog/
      index.vue                   # Blog listing page
      [...slug].vue               # Individual blog post page
  server/
    routes/
      feed.xml.ts                 # RSS feed endpoint
  assets/
    css/
      main.css                    # Updated with glass utilities, prose styles, font-face
  public/
    fonts/
      BricolageGrotesque-Variable.woff2  # Self-hosted font
  nuxt.config.js                  # Updated with @nuxt/content, head config
  tailwind.config.js              # Updated with font-display family
  package.json                    # Updated with @nuxt/content dependency
```
