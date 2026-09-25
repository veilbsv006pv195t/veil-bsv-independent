import { groth16 } from 'snarkjs'
import { FIELD, HashFn, PoolState } from '../../src/crypto'

export type ProofAction = 'shield' | 'send' | 'lock' | 'withdraw'

export interface ProofResult {
    publicSignal: string
    elapsedMs: number
}

export type ProofProgress = (percent: number | null, label: string) => void

const proofAsset = (name: string): string => `${import.meta.env.BASE_URL}zk/${name}`

let wasmBytes: Uint8Array | undefined
let provingKeyBytes: Uint8Array | undefined

async function downloadProofAsset(
    name: string,
    startPercent: number,
    endPercent: number,
    onProgress: ProofProgress
): Promise<Uint8Array> {
    const response = await fetch(proofAsset(name))
    if (!response.ok) throw new Error(`${name} is unavailable`)

    const total = Number(response.headers.get('content-length'))
    if (!response.body || !Number.isFinite(total) || total <= 0) {
        const bytes = new Uint8Array(await response.arrayBuffer())
        onProgress(endPercent, 'Proof data downloaded')
        return bytes
    }

    const reader = response.body.getReader()
    // Content-Length can describe the compressed transfer size while the
    // Fetch stream yields decompressed bytes (notably in Tor/WebKit shells).
    // Grow the buffer when needed instead of rejecting a valid response.
    let bytes = new Uint8Array(total)
    let received = 0
    while (true) {
        const { done, value } = await reader.read()
        if (done) break
        if (received + value.byteLength > bytes.byteLength) {
            const expanded = new Uint8Array(
                Math.max(received + value.byteLength, bytes.byteLength * 2)
            )
            expanded.set(bytes.subarray(0, received))
            bytes = expanded
        }
        bytes.set(value, received)
        received += value.byteLength
        const fraction = Math.min(received / total, 1)
        const percent = Math.min(
            endPercent,
            startPercent + Math.floor(fraction * (endPercent - startPercent))
        )
        onProgress(percent, 'Downloading private proof data')
    }
    onProgress(endPercent, 'Proof data downloaded')
    return bytes.slice(0, received)
}

async function loadProofAssets(onProgress: ProofProgress): Promise<{
    wasm: Uint8Array
    provingKey: Uint8Array
}> {
    if (!wasmBytes) {
        wasmBytes = await downloadProofAsset('shielded_pool.wasm', 2, 6, onProgress)
    } else {
        onProgress(6, 'Circuit ready')
    }
    if (!provingKeyBytes) {
        provingKeyBytes = await downloadProofAsset(
            'shielded_pool_final.zkey',
            6,
            84,
            onProgress
        )
    } else {
        onProgress(84, 'Proof data ready')
    }
    return { wasm: wasmBytes, provingKey: provingKeyBytes }
}

const hashPromise: Promise<HashFn> = fetch(proofAsset('mimc_constants.json'))
    .then((response) => {
        if (!response.ok) throw new Error('MiMC parameters are unavailable')
        return response.json() as Promise<string[]>
    })
    .then((serialized) => {
        const constants = serialized.map(BigInt)
        return (left: bigint, right: bigint): bigint => {
            let result = 0n
            for (let round = 0; round < constants.length; round++) {
                const t =
                    round === 0
                        ? left + right
                        : result + right + constants[round]
                const t2 = (t * t) % FIELD
                const t4 = (t2 * t2) % FIELD
                result = (((t4 * t2) % FIELD) * t) % FIELD
            }
            return (result + right) % FIELD
        }
    })
let verificationKeyPromise: Promise<unknown> | undefined

function verificationKey(): Promise<unknown> {
    verificationKeyPromise ??= fetch(proofAsset('verification_key.json')).then((response) => {
        if (!response.ok) throw new Error('verification key is unavailable')
        return response.json()
    })
    return verificationKeyPromise
}

async function textField(value: string, bytes?: number): Promise<bigint> {
    const digest = new Uint8Array(
        await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value))
    )
    const selected = bytes ? digest.slice(digest.length - bytes) : digest
    const hex = Array.from(selected, (item) => item.toString(16).padStart(2, '0')).join('')
    return BigInt(`0x${hex}`) % FIELD
}

export async function proveAction(
    action: ProofAction,
    amount: bigint,
    privateBalance: bigint,
    recipient: string,
    unlockHeight = 0n,
    currentHeight = 0n,
    onProgress: ProofProgress = () => undefined
): Promise<ProofResult> {
    onProgress(1, 'Preparing private proof')
    const hash = await hashPromise
    const pool = new PoolState(hash)
    const owner = await textField('veil-demo-owner')
    const recipientKey = await textField(recipient || 'veil-demo-recipient')
    let transition

    if (action === 'shield') {
        transition = pool.build({
            mode: 0,
            publicIn: amount,
            outputs: [{ amount, ownerKey: owner, rho: 10_001n + amount }],
        })
    } else {
        const initial = pool.build({
            mode: 0,
            publicIn: privateBalance,
            outputs: [
                { amount: privateBalance, ownerKey: owner, rho: 10_001n + privateBalance },
            ],
        })
        const change = privateBalance - amount
        if (action === 'send') {
            if (change <= 0n) throw new Error('Leave at least 1 sat as private change')
            transition = pool.build({
                mode: 1,
                spend: { note: initial.outputNotes[0] },
                currentHeight,
                outputs: [
                    { amount, ownerKey: recipientKey, rho: 20_001n + amount },
                    { amount: change, ownerKey: owner, rho: 20_002n + change },
                ],
            })
        } else if (action === 'lock') {
            transition = pool.build({
                mode: 1,
                spend: { note: initial.outputNotes[0] },
                currentHeight,
                outputs: [
                    {
                        amount,
                        ownerKey: owner,
                        rho: 25_001n + amount + unlockHeight,
                        lockHeight: unlockHeight,
                    },
                    ...(change > 0n
                        ? [
                              {
                                  amount: change,
                                  ownerKey: owner,
                                  rho: 25_002n + change,
                              },
                          ]
                        : []),
                ],
            })
        } else {
            transition = pool.build({
                mode: 2,
                spend: { note: initial.outputNotes[0] },
                currentHeight,
                publicOut: amount,
                recipient: await textField(recipient, 20),
                outputs:
                    change > 0n
                        ? [{ amount: change, ownerKey: owner, rho: 30_001n + change }]
                        : [],
            })
        }
    }

    const { wasm, provingKey } = await loadProofAssets(onProgress)
    onProgress(null, 'Generating Groth16 proof…')
    const started = performance.now()
    const { proof, publicSignals } = await groth16.fullProve(
        transition.circuitInput,
        wasm,
        provingKey
    )
    onProgress(97, 'Verifying proof locally')
    if (!(await groth16.verify(await verificationKey(), publicSignals, proof))) {
        throw new Error('The generated zero-knowledge proof did not verify')
    }
    onProgress(100, 'Private proof verified')
    return { publicSignal: publicSignals[0], elapsedMs: performance.now() - started }
}
