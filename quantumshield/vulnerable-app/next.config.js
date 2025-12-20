/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: false,
  // Disable security headers for testing vulnerabilities
  async headers() {
    return []
  }
}

module.exports = nextConfig

