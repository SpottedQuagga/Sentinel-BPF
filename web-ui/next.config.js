/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  output: 'standalone',
  env: {
    NEXT_PUBLIC_WS_URL: process.env.NEXT_PUBLIC_WS_URL || 'ws://127.0.0.1:8080/ws',
    NEXT_PUBLIC_SENTINEL_TOKEN: process.env.NEXT_PUBLIC_SENTINEL_TOKEN || '',
  },
};

module.exports = nextConfig;
