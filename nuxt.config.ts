export default defineNuxtConfig({
  devtools: { enabled: true },
  css: ['~/assets/css/main.css'],

  app: {
    head: {
      link: [
        {
          rel: 'alternate',
          type: 'application/rss+xml',
          title: 'Nik Rykov - Blog',
          href: '/feed.xml',
        },
        {
          rel: 'preload',
          href: '/fonts/BricolageGrotesque-latin.woff2',
          as: 'font',
          type: 'font/woff2',
          crossorigin: 'anonymous',
        },
      ],
    },
  },

  postcss: {
    plugins: {
      tailwindcss: {},
      autoprefixer: {},
    },
  },

  compatibilityDate: '2025-07-15',
  modules: ['@nuxt/image', '@nuxt/content'],

  content: {
    experimental: {
      sqliteConnector: 'native',
    },
    build: {
      markdown: {
        highlight: {
          theme: 'github-dark',
          langs: [
            'js', 'ts', 'vue', 'bash', 'json', 'md',
            'css', 'html', 'python', 'go', 'rust', 'solidity',
            'yaml', 'toml', 'sql', 'diff',
          ],
        },
      },
    },
  },

  ssr: true,
  components: true,

  nitro: {
    prerender: {
      routes: ['/feed.xml'],
    },
  },
})
