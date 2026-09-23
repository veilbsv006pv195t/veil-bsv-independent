import { readFile } from 'node:fs/promises'
import path from 'node:path'
import { groth16 } from 'snarkjs'
import { PoolState, PUBLIC_FIELD_ORDER, createHash } from '../src/crypto'
import { PairingBenchmark } from '../src/contracts/pairingBenchmark'
import { OptimizedPairingBenchmark } from '../src/contracts/optimizedPairingBenchmark'
import { StatementHashBenchmark } from '../src/contracts/statementHashBenchmark'
import { toPreparedVerifyingKey } from '../src/optimizedGroth16Data'
import { buildPairingResidueWitness } from '../src/pairingResidue'
import {
    SnarkProof,
    SnarkVerificationKey,
    toScryptProof,
    toScryptVerifyingKey,
} from '../src/groth16'

const WASM = path.resolve('build/shielded_pool_js/shielded_pool.wasm')
const ZKEY = path.resolve('build/shielded_pool_final.zkey')
const VKEY = path.resolve('build/verification_key.json')

function run(name: string, verify: () => void): void {
    const started = performance.now()
    verify()
    console.log(`${name}: ${((performance.now() - started) / 1000).toFixed(3)}s`)
}

async function main(): Promise<void> {
    const optimizedOnly = process.argv.includes('--optimized-only')
    const hash = await createHash()
    const state = new PoolState(hash)
    const transition = state.build({
        mode: 0,
        publicIn: 1_000n,
        outputs: [{ amount: 1_000n, ownerKey: 101n, rho: 10_001n }],
    })
    const vkey = JSON.parse(await readFile(VKEY, 'utf8')) as SnarkVerificationKey
    const { proof } = await groth16.fullProve(transition.circuitInput, WASM, ZKEY)
    const scryptProof = toScryptProof(proof as SnarkProof)
    const scryptVkey = toScryptVerifyingKey(vkey)
    const prepareStarted = performance.now()
    const preparedVkey = toPreparedVerifyingKey(vkey)
    const residueWitness = buildPairingResidueWitness(
        transition.statement,
        scryptProof,
        preparedVkey
    )
    if (optimizedOnly) {
        console.log(`prepared VK: ${((performance.now() - prepareStarted) / 1000).toFixed(3)}s`)
    }

    const values = PUBLIC_FIELD_ORDER.map((key) => transition.public[key]) as [
        bigint, bigint, bigint, bigint, bigint,
        bigint, bigint, bigint, bigint, bigint,
        bigint, bigint, bigint, bigint, bigint,
    ]
    let hashContract: StatementHashBenchmark | undefined
    let pairingContract: PairingBenchmark | undefined
    if (!optimizedOnly) {
        StatementHashBenchmark.loadArtifact('artifacts/statementHashBenchmark.json')
        hashContract = new StatementHashBenchmark()
        run('15 MiMC hashes', () => {
            const result = hashContract!.verify((self) => {
                self.check(values, transition.statement)
            })
            if (result instanceof Promise || !result.success) {
                throw new Error(result instanceof Promise ? 'unexpected promise' : result.error)
            }
        })

        PairingBenchmark.loadArtifact('artifacts/pairingBenchmark.json')
        pairingContract = new PairingBenchmark(scryptVkey)
        run('Groth16 pairing verifier', () => {
            const result = pairingContract!.verify((self) => {
                self.check(scryptProof, transition.statement)
            })
            if (result instanceof Promise || !result.success) {
                throw new Error(result instanceof Promise ? 'unexpected promise' : result.error)
            }
        })
    }

    OptimizedPairingBenchmark.loadArtifact('artifacts/optimizedPairingBenchmark.json')
    const constructStarted = performance.now()
    const optimizedContract = new OptimizedPairingBenchmark(preparedVkey)
    if (optimizedOnly) {
        console.log(`constructed contract: ${((performance.now() - constructStarted) / 1000).toFixed(3)}s`)
    }
    run('Optimized Groth16 pairing verifier', () => {
        const result = optimizedContract.verify((self) => {
            self.check(scryptProof, transition.statement, residueWitness)
        })
        if (result instanceof Promise || !result.success) {
            throw new Error(result instanceof Promise ? 'unexpected promise' : result.error)
        }
    })

    if (hashContract && pairingContract) {
        console.log(`hash script: ${hashContract.scriptSize.toLocaleString()} bytes`)
        console.log(`pairing script: ${pairingContract.scriptSize.toLocaleString()} bytes`)
    }
    console.log(`optimized pairing script: ${optimizedContract.scriptSize.toLocaleString()} bytes`)
}

main().then(
    () => process.exit(0),
    (error: unknown) => {
        console.error(error)
        process.exit(1)
    }
)
