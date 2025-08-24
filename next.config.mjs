// next.config.mjs
/** @type {import('next').NextConfig} */
const nextConfig = {
  eslint: {
    // don't fail the Vercel build on ESLint errors
    ignoreDuringBuilds: true,
  },
  typescript: {
    // don't fail the Vercel build on TS errors
    ignoreBuildErrors: true,
  },
};

export default nextConfig;