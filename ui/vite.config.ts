import { defineConfig } from 'vite'
import path from 'node:path'

export default defineConfig({
    root: path.resolve(__dirname),
    // Relative URLs allow the same static build to run from GitHub Pages,
    // an extracted release folder, or any other subdirectory.
    base: './',
    build: {
        outDir: path.resolve(__dirname, '../dist-ui'),
        emptyOutDir: true,
    },
})
