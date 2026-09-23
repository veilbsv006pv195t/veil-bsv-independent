import { groth16 } from 'snarkjs'
import { FIELD, HashFn, PoolState } from '../../src/crypto'

export type ProofAction = 'shield' | 'send' | 'lock' | 'withdraw'

export interface ProofResult {
    publicSignal: string
    elapsedMs: number
}

const hashPromise: Promise<HashFn> = fetch('/zk/mimc_constants.json')
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
    verificationKeyPromise ??= fetch('/zk/verification_key.json').then((response) => {
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
    currentHeight = 0n
): Promise<ProofResult> {
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

    const started = performance.now()
    const { proof, publicSignals } = await groth16.fullProve(
        transition.circuitInput,
        '/zk/shielded_pool.wasm',
        '/zk/shielded_pool_final.zkey'
    )
    if (!(await groth16.verify(await verificationKey(), publicSignals, proof))) {
        throw new Error('The generated zero-knowledge proof did not verify')
    }
    return { publicSignal: publicSignals[0], elapsedMs: performance.now() - started }
}
