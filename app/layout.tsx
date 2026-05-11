import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Vulnerability Intelligence",
  description:
    "Search by software name or version to see what may be unsafe, what has been fixed, and where the information came from.",
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
