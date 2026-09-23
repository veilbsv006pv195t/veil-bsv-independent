import { readFileSync } from 'node:fs'
import { createHash } from 'node:crypto'
import { bsv } from 'scrypt-ts'

const deployment = JSON.parse(
    readFileSync('.private/testnet-optimized-v3-deployment-signed.json', 'utf8')
) as { transactionHex: string }
const tx = new bsv.Transaction(deployment.transactionHex)
const script = tx.outputs[0].script

function encodedChunkBytes(chunk: { buf?: Buffer }): number {
    if (!chunk.buf) return 1
    const length = chunk.buf.length
    if (length <= 75) return 1 + length
    if (length <= 0xff) return 2 + length
    if (length <= 0xffff) return 3 + length
    return 5 + length
}

const pushes = script.chunks.filter((chunk) => chunk.buf)
const opcodes = script.chunks.filter((chunk) => !chunk.buf)
const pushBytes = pushes.reduce((sum, chunk) => sum + encodedChunkBytes(chunk), 0)
const opcodeBytes = opcodes.length
const byPayloadLength = new Map<number, { count: number; encodedBytes: number }>()
const duplicatePayloads = new Map<string, { length: number; count: number; hex: string }>()

for (const chunk of pushes) {
    const length = chunk.buf!.length
    const current = byPayloadLength.get(length) ?? { count: 0, encodedBytes: 0 }
    current.count += 1
    current.encodedBytes += encodedChunkBytes(chunk)
    byPayloadLength.set(length, current)
    const digest = createHash('sha256').update(chunk.buf!).digest('hex')
    const duplicate = duplicatePayloads.get(digest) ?? {
        length,
        count: 0,
        hex: chunk.buf!.toString('hex'),
    }
    duplicate.count += 1
    duplicatePayloads.set(digest, duplicate)
}

const largestGroups = [...byPayloadLength.entries()]
    .map(([payloadBytes, values]) => ({ payloadBytes, ...values }))
    .sort((left, right) => right.encodedBytes - left.encodedBytes)
    .slice(0, 20)
const repeated = [...duplicatePayloads.values()]
    .filter((value) => value.count > 1)
    .map((value) => ({ ...value, repeatedBytes: value.length * (value.count - 1) }))
    .sort((left, right) => right.repeatedBytes - left.repeatedBytes)
    .slice(0, 20)

console.log(JSON.stringify({
    scriptBytes: script.toBuffer().length,
    chunkCount: script.chunks.length,
    pushCount: pushes.length,
    opcodeCount: opcodes.length,
    pushBytes,
    opcodeBytes,
    largestPayloadGroups: largestGroups,
    largestRepeatedPayloads: repeated,
}, null, 2))
