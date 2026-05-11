import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Vulnerability Intelligence",
  description:
    "Search CVEs, packages, products, versions, and advisories with fixes, exploitability signals, and source records in one view.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
