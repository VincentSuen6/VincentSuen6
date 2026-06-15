import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "SOC Operator — HITL Dashboard",
  description: "Real-time Human-in-the-Loop dashboard for the agentic SOAR engine",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <head>
        <style>{`
          *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
          body {
            font-family: "Courier New", Courier, monospace;
            background: #0d1117;
            color: #c9d1d9;
            min-height: 100vh;
          }
          a { color: #58a6ff; text-decoration: none; }
        `}</style>
      </head>
      <body>{children}</body>
    </html>
  );
}
