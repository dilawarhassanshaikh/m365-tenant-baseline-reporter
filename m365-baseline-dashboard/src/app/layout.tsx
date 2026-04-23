import type { Metadata } from "next";
import { Providers } from "./providers";

export const metadata: Metadata = {
  title: "M365 Tenant Baseline Dashboard",
  description: "Security baseline reporting for Microsoft 365",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body style={{ margin: 0, padding: 0 }}>
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}
