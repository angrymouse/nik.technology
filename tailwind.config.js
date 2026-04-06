/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./app/components/**/*.{js,vue,ts}",
    "./app/layouts/**/*.vue",
    "./app/pages/**/*.vue",
    "./app/plugins/**/*.{js,ts}",
    "./app/app.vue",
    "./app/error.vue",
  ],
  theme: {
    extend: {
      fontFamily:{
        "sans":['Iosevka Web', 'ui-monospace'],
        "display":['Bricolage Grotesque', 'system-ui', 'sans-serif']
      },
      colors: {
        'neon-green': 'var(--neon-green)',
      },
    },
  },
  plugins: [],
}