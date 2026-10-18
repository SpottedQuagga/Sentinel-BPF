import './globals.css';
import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'SentinelBPF - eBPF Host Intrusion Detection System',
  description: 'Real-time Linux host intrusion detection dashboard powered by eBPF and kernel telemetry',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
