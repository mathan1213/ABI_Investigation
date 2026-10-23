/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        navy: {
          950: '#070C15',
          900: '#0B1220', // Background
          850: '#0E1629',
          800: '#111A2E', // Cards
          750: '#15213B',
          700: '#1A2744',
          600: '#26375E',
          500: '#3B4F80',
        },
        cyan: {
          300: '#67E8F9',
          400: '#22D3EE', // Primary accent
          500: '#06B6D4',
          600: '#0891B2',
        },
        risk: {
          low: '#10B981',      // Green
          medium: '#EAB308',   // Yellow
          high: '#F97316',     // Orange
          critical: '#EF4444', // Red
        }
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'BlinkMacSystemFont', 'Segoe UI', 'Roboto', 'sans-serif'],
        mono: ['JetBrains Mono', 'monospace'],
      },
      boxShadow: {
        glow: '0 0 25px -5px rgba(34, 211, 238, 0.15)',
        'glow-lg': '0 0 35px -5px rgba(34, 211, 238, 0.25)',
        'glow-red': '0 0 25px -5px rgba(239, 68, 68, 0.2)',
        'glow-orange': '0 0 25px -5px rgba(249, 115, 22, 0.2)',
        'glow-yellow': '0 0 25px -5px rgba(234, 179, 8, 0.2)',
        'glow-green': '0 0 25px -5px rgba(16, 185, 129, 0.2)',
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'spin-slow': 'spin 12s linear infinite',
      }
    },
  },
  plugins: [],
}
