/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        graphite: {
          950: '#0E0E10',
          900: '#141417',
          850: '#1A1A1E',
          800: '#222227',
          700: '#2E2E35',
        },
      },
    },
  },
  plugins: [],
};
