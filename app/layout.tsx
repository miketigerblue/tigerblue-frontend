import "./globals.css";
import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "TigerBlue",
  description: "OSINT + CTI frontend for TigerBlue / Threat Kitty",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en-GB">
      <body>{children}</body>
    </html>
  );
}
