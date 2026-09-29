import type { Config } from "tailwindcss";

const config: Config = {
  content: ["./src/**/*.{js,ts,jsx,tsx,mdx}"],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        // Core palette (from Stitch DESIGN.md)
        background: "#fefffc",
        paper: "#ffffff",
        linen: "#f9faf7",
        "ink-black": "#171717",
        graphite: "#2c2c2c",
        charcoal: "#444141",
        ash: "#646464",
        fog: "#b4b8b4",
        mist: "#dee2de",
        twilight: "#282834",
        dusk: "#1f1f29",
        "signal-blue": "#41a1cf",
        cerulean: "#0081c0",
        // Surface hierarchy
        surface: "#f9faf7",
        "surface-dim": "#d9dad8",
        "surface-bright": "#f9faf7",
        "surface-container-lowest": "#ffffff",
        "surface-container-low": "#f3f4f1",
        "surface-container": "#edeeeb",
        "surface-container-high": "#e7e8e6",
        "surface-container-highest": "#e2e3e0",
        "surface-variant": "#e2e3e0",
        // On-surface
        "on-surface": "#191c1b",
        "on-surface-variant": "#47464b",
        "inverse-surface": "#2e312f",
        "inverse-on-surface": "#f0f1ee",
        // Primary / secondary / tertiary
        primary: "#070710",
        "on-primary": "#ffffff",
        "primary-container": "#1f1f29",
        "on-primary-container": "#878693",
        "inverse-primary": "#c7c5d3",
        "primary-fixed": "#e3e1ef",
        "primary-fixed-dim": "#c7c5d3",
        "on-primary-fixed": "#1b1b25",
        "on-primary-fixed-variant": "#464651",
        secondary: "#5e5d6b",
        "on-secondary": "#ffffff",
        "secondary-container": "#e0deee",
        "on-secondary-container": "#62616f",
        "secondary-fixed": "#e3e1f1",
        "secondary-fixed-dim": "#c7c5d5",
        "on-secondary-fixed": "#1a1b26",
        "on-secondary-fixed-variant": "#464653",
        tertiary: "#000911",
        "on-tertiary": "#ffffff",
        "tertiary-container": "#002332",
        "on-tertiary-container": "#2a91be",
        "tertiary-fixed": "#c3e7ff",
        "tertiary-fixed-dim": "#7bd0ff",
        "on-tertiary-fixed": "#001e2c",
        "on-tertiary-fixed-variant": "#004c69",
        // Outline
        outline: "#78767c",
        "outline-variant": "#c8c5cc",
        "surface-tint": "#5e5d69",
        // Error
        error: "#ba1a1a",
        "on-error": "#ffffff",
        "error-container": "#ffdad6",
        "on-error-container": "#93000a",
        // NETRA semantic status
        "status-live": "#2a7a4f",
        "status-warn": "#8a6000",
        "status-error": "#8a2a2a",
        // NETRA confidence
        "confidence-high": "#1a5c3a",
        "confidence-med": "#5c4a00",
        "confidence-low": "#646464",
        // NETRA severity
        "severity-critical": "#8a1a1a",
        "severity-high": "#8a4a00",
        "severity-medium": "#5c4a00",
        "severity-low": "#3a5c2a",
      },
      fontFamily: {
        // Fraunces = display serif (ppmondwest substitute)
        "headline-hero": ["Fraunces", "serif"],
        "headline-xl": ["Fraunces", "serif"],
        "headline-lg": ["Fraunces", "serif"],
        "headline-sub": ["Inter", "sans-serif"],
        "body-default": ["Inter", "sans-serif"],
        "body-reading": ["Inter", "sans-serif"],
        "body-emphasis": ["Inter", "sans-serif"],
        "body-caption": ["Inter", "sans-serif"],
        "label-ui": ["Inter", "sans-serif"],
        "label-uppercase": ["Inter", "sans-serif"],
        "code-default": ["JetBrains Mono", "monospace"],
        "code-compact": ["JetBrains Mono", "monospace"],
      },
      fontSize: {
        "headline-hero": ["54px", { lineHeight: "60px", letterSpacing: "-0.02em", fontWeight: "400" }],
        "headline-xl": ["40px", { lineHeight: "44px", letterSpacing: "-0.02em", fontWeight: "500" }],
        "headline-lg": ["27px", { lineHeight: "40px", letterSpacing: "-0.04em", fontWeight: "400" }],
        "headline-sub": ["18px", { lineHeight: "24px", letterSpacing: "-0.01em", fontWeight: "500" }],
        "body-default": ["15px", { lineHeight: "21px", letterSpacing: "-0.01em", fontWeight: "500" }],
        "body-reading": ["16px", { lineHeight: "24px", letterSpacing: "0", fontWeight: "400" }],
        "body-emphasis": ["15px", { lineHeight: "21px", letterSpacing: "-0.01em", fontWeight: "700" }],
        "body-caption": ["13px", { lineHeight: "20px", letterSpacing: "0", fontWeight: "400" }],
        "label-ui": ["13px", { lineHeight: "18px", letterSpacing: "-0.01em", fontWeight: "500" }],
        "label-uppercase": ["11px", { lineHeight: "14px", letterSpacing: "0.08em", fontWeight: "600" }],
        "code-default": ["13px", { lineHeight: "18px", letterSpacing: "0", fontWeight: "400" }],
        "code-compact": ["11px", { lineHeight: "15px", letterSpacing: "0", fontWeight: "400" }],
      },
      boxShadow: {
        editorial: "0px 1px 1px 0px rgba(0,0,0,0.08), 0px 4px 5px 0px rgba(0,0,0,0.08)",
        diagram: "0px 1px 8px 0px rgba(0,0,0,0.05)",
        card: "0px 1px 1px 0px rgba(0,0,0,0.08), 0px 4px 5px 0px rgba(0,0,0,0.08)",
      },
      borderRadius: {
        DEFAULT: "0.25rem",
        lg: "0.5rem",    // buttons
        xl: "0.75rem",   // cards
        "2xl": "1rem",
        "3xl": "1.5rem", // modals / large surfaces
        full: "9999px",  // pills
      },
      spacing: {
        "space-xs": "0.25rem",
        "space-sm": "0.5rem",
        "space-md": "1rem",
        "space-lg": "1.5rem",
        "space-xl": "2rem",
      },
    },
  },
  plugins: [],
};

export default config;
