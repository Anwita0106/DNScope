/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        ink: { 950: "#08111F", 900: "#0B1628", 800: "#132238", 700: "#1B2E4A", 600: "#2B4163" },
        muted: "#B6C3D4",
      },
      fontFamily: { sans: ["Inter", "Segoe UI", "Arial", "sans-serif"], mono: ["JetBrains Mono", "Consolas", "monospace"] },
    },
  },
  plugins: [],
};
