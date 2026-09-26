export const MAX_BACKUP_FILE_BYTES = 64_000_000
export const MAX_BACKUP_CLEAR_BYTES = 64_000_000
export function toBase64(bytes: Uint8Array): string {
    const parts: string[] = []
    for (let i = 0; i < bytes.length; i += 32768) parts.push(String.fromCharCode(...bytes.subarray(i, i + 32768)))
    return btoa(parts.join(''))
}
export function fromBase64(value: string): Uint8Array {
    if (value.length % 4 || /[^A-Za-z0-9+/=]/.test(value)) throw new Error('Invalid backup encoding')
    const bytes = Uint8Array.from(atob(value), c => c.charCodeAt(0))
    if (toBase64(bytes) !== value) throw new Error('Invalid backup encoding')
    return bytes
}
/** Bound output while streaming, before allocating a complete decompressed buffer. */
export async function gzipBytes(input: Uint8Array, decompress = false, limit = MAX_BACKUP_CLEAR_BYTES): Promise<Uint8Array> {
    if (typeof CompressionStream === 'undefined' || typeof DecompressionStream === 'undefined') throw new Error('This browser does not support compact backups. Keep this wallet tab open.')
    const stream = new Blob([input]).stream().pipeThrough(decompress ? new DecompressionStream('gzip') : new CompressionStream('gzip'))
    const reader = stream.getReader()
    const chunks: Uint8Array[] = []
    let size = 0
    try {
        while (true) {
            const { value, done } = await reader.read()
            if (done) break
            size += value.byteLength
            if (size > limit) { value.fill(0); await reader.cancel(); throw new Error('Backup exceeds safe decompression/size limit') }
            chunks.push(value)
        }
        const result = new Uint8Array(size)
        let offset = 0
        for (const chunk of chunks) { result.set(chunk, offset); offset += chunk.length }
        return result
    } finally { for (const chunk of chunks) chunk.fill(0); reader.releaseLock() }
}
