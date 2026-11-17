import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "RiskShare Control Room",
  description: "Risk-adaptive threshold key management research prototype",
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return <html lang="en"><body>{children}</body></html>;
}
