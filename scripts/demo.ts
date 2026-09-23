import { readFile } from 'node:fs/promises'
import path from 'node:path'
import { groth16 } from 'snarkjs'
import { OptimizedG16BN256 } from '../src/optimizedGroth16'
import { PoolState, createHash } from '../src/crypto'
import {
    SnarkProof,
    SnarkVerificationKey,
    toScryptProof,
} from '../src/groth16'
import { toPreparedVerifyingKey } from '../src/optimizedGroth16Data'
import { buildPairingResidueWitness } from '../src/pairingResidue'

const WASM = path.resolve('build/shielded_pool_js/shielded_pool.wasm')
const ZKEY = path.resolve('build/shielded_pool_final.zkey')
const VKEY = path.resolve('build/verification_key.json')

function short(value: bigint | string): string {
    const text = value.toString()
    return `${text.slice(0, 10)}…${text.slice(-8)}`
}

async function main(): Promise<void> {
    const hash = await createHash()
    const pool = new PoolState(hash)
    const sender = 101n
    const receiver = 202n
    const recipient = 0x00112233445566778899aabbccddeeff00112233n
    const vkey = JSON.parse(await readFile(VKEY, 'utf8')) as SnarkVerificationKey

    const transitions = []
    const shield = pool.build({
        mode: 0,
        publicIn: 1_000n,
        outputs: [
            { amount: 1_000n, ownerKey: sender, rho: 10_001n, lockHeight: 900_000n },
        ],
    })
    transitions.push(['shield', shield] as const)

    let prematureRejected = false
    try {
        pool.build({
            mode: 2,
            spend: { note: shield.outputNotes[0] },
            currentHeight: 899_999n,
            publicOut: 1_000n,
            recipient,
            outputs: [],
        })
    } catch (error) {
        prematureRejected =
            error instanceof Error && error.message.includes('locked until block 900000')
    }
    if (!prematureRejected) throw new Error('premature locked-note spend was not rejected')
    console.log('✓ height lock rejected a spend before block 900,000')

    const transfer = pool.build({
        mode: 1,
        spend: { note: shield.outputNotes[0] },
        currentHeight: 900_000n,
        outputs: [
            { amount: 600n, ownerKey: receiver, rho: 20_001n, lockHeight: 900_100n },
            { amount: 400n, ownerKey: sender, rho: 20_002n },
        ],
    })
    transitions.push(['private transfer', transfer] as const)

    const unshield = pool.build({
        mode: 2,
        spend: { note: transfer.outputNotes[0] },
        currentHeight: 900_100n,
        publicOut: 500n,
        recipient,
        outputs: [{ amount: 100n, ownerKey: receiver, rho: 30_001n }],
    })
    transitions.push(['unshield', unshield] as const)

    console.log('Veil BSV — replaying shield → private transfer → unshield\n')
    let finalProof: SnarkProof | undefined
    let finalSignals: string[] | undefined
    for (const [name, transition] of transitions) {
        const started = performance.now()
        const { proof, publicSignals } = await groth16.fullProve(
            transition.circuitInput,
            WASM,
            ZKEY
        )
        const valid = await groth16.verify(vkey, publicSignals, proof)
        if (!valid) throw new Error(`${name} proof did not verify`)
        const elapsed = ((performance.now() - started) / 1000).toFixed(2)
        console.log(
            `✓ ${name.padEnd(16)} proof=${short(publicSignals[0])} nullifier=${short(transition.public.nullifier)} (${elapsed}s)`
        )
        finalProof = proof as SnarkProof
        finalSignals = publicSignals
    }

    if (!finalProof || !finalSignals) throw new Error('demo produced no proof')
    const tampered = [(BigInt(finalSignals[0]) + 1n).toString()]
    if (await groth16.verify(vkey, tampered, finalProof)) {
        throw new Error('tampered public signal unexpectedly verified')
    }
    console.log('✓ tampered statement rejected')

    console.log('\nConverting the same proof to the on-chain sCrypt BN254 representation…')
    const scryptProof = toScryptProof(finalProof)
    const scryptVkey = toPreparedVerifyingKey(vkey)
    const residueWitness = buildPairingResidueWitness(
        BigInt(finalSignals[0]),
        scryptProof,
        scryptVkey
    )
    const onChainMathValid = OptimizedG16BN256.verify(
        BigInt(finalSignals[0]),
        scryptProof,
        residueWitness,
        scryptVkey
    )
    if (!onChainMathValid) throw new Error('sCrypt Groth16 verifier rejected the proof')
    console.log('✓ sCrypt verifier accepted the Groth16 proof')
    console.log(
        '\nReplay complete: 1,000 locked to block 900,000 → 600 locked to 900,100 + 400 private → 500 out + 100 private.'
    )
}

main().then(
    () => process.exit(0),
    (error: unknown) => {
        console.error(error)
        process.exit(1)
    }
)
