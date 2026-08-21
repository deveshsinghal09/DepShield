import type { NextConfig } from "next";
const nextConfig: NextConfig = { output: "standalone", serverExternalPackages: ["better-sqlite3"], experimental: { serverMinification: false } };
export default nextConfig;
