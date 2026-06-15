/** @type {import('next').NextConfig} */
const nextConfig = {
  async rewrites() {
    return [
      {
        source: "/soar-api/:path*",
        destination: `${process.env.SOAR_API_URL || "http://localhost:8000"}/:path*`,
      },
    ];
  },
};

module.exports = nextConfig;
