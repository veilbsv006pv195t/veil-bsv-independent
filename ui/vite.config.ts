import { defineConfig } from 'vite'
import path from 'node:path'
import { nodePolyfills } from 'vite-plugin-node-polyfills'

export default defineConfig({
    root: path.resolve(__dirname),
    cacheDir: path.resolve(__dirname, '../build/recipient/vite-cache'),
    // Relative URLs allow the same static build to run from GitHub Pages,
    // an extracted release folder, or any other subdirectory.
    base: './',
    plugins: [
        nodePolyfills({
            globals: { Buffer: true, global: true, process: true },
            protocolImports: true,
        }),
    ],
    build: {
        outDir: path.resolve(__dirname, '../dist-ui'),
        emptyOutDir: true,
    },
})
