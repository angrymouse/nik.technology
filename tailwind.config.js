/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./components/**/*.{js,vue,ts}",
    "./layouts/**/*.vue",
    "./pages/**/*.vue",
    "./plugins/**/*.{js,ts}",
    "./app.vue",
    "./error.vue",
  ],
  theme: {
    extend: {
      fontFamily:{
        "sans":['Iosevka Web', 'ui-monospace']
      },
      colors: {
        'neon-green': 'var(--neon-green)',
      },
    },
  },
  plugins: [],
}