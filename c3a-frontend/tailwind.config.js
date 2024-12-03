module.exports = {
  mode: "all",
  content: [
    "./src/**/*.{rs,html,css}",
    "../data/**/*.fragment.html",
    "../dist/**/*.html",
  ],
  theme: {
    extend: {
      keyframes: {
        slide_in: {
          "0%": { opacity: 0, transform: "translateX(100%)" },
          "100%": { opacity: 1, transform: "translateX(0)" }
        }
      },
      animation: {
        slide_in: "slide_in .25s ease-in-out forwards 1"
      }
    },
    fontFamily: {
      'sans': ['Roboto']
    }
  },
  plugins: [],
}
