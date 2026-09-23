import assert from 'node:assert/strict'
import { setMaxListeners } from 'node:events'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'
import test from 'node:test'
import { wtns } from 'snarkjs'
import {
    MerkleTree,
    Note,
    PoolState,
    createHash,
    noteCommitment,
    noteNullifier,
    statementHash,
} from '../src/crypto'

setMaxListeners(50, process.stdout, process.stderr)

const WASM = path.resolve('build/shielded_pool_js/shielded_pool.wasm')
const R1CS = path.resolve('build/shielded_pool.r1cs')

test('note commitments, nullifiers, and Merkle paths are deterministic', async () => {
    const hash = await createHash()
    const commitment = noteCommitment(hash, 1_000n, 101n, 10_001n)
    const tree = new MerkleTree(hash)
    const emptyRoot = tree.root()
    tree.set(0, commitment)

    assert.notEqual(tree.root(), emptyRoot)
    assert.equal(tree.path(0).length, 4)
    assert.equal(noteNullifier(hash, commitment, 101n), noteNullifier(hash, commitment, 101n))
    assert.notEqual(
        commitment,
        noteCommitment(hash, 1_000n, 101n, 10_001n, 900_000n),
        'lock height must be committed into the note'
    )
})

test('a height-locked note cannot be spent early and unlocks at its block', async () => {
    const hash = await createHash()
    const pool = new PoolState(hash)
    const shield = pool.build({
        mode: 0,
        publicIn: 10n,
        outputs: [
            { amount: 10n, ownerKey: 7n, rho: 8n, lockHeight: 900_100n },
        ],
    })
    const note = shield.outputNotes[0]

    assert.throws(
        () =>
            pool.build({
                mode: 2,
                spend: { note },
                currentHeight: 900_099n,
                publicOut: 10n,
                recipient: 1n,
                outputs: [],
            }),
        /locked until block 900100/
    )

    const exit = pool.build({
        mode: 2,
        spend: { note },
        currentHeight: 900_100n,
        publicOut: 10n,
        recipient: 1n,
        outputs: [],
    })
    const directory = await mkdtemp(path.join(tmpdir(), 'veil-bsv-lock-test-'))
    try {
        const witness = path.join(directory, 'mature-unshield.wtns')
        await wtns.calculate(exit.circuitInput, WASM, witness)
        assert.equal(await wtns.check(R1CS, witness), true)
    } finally {
        await rm(directory, { recursive: true, force: true })
    }
})

test('shield -> transfer -> unshield all satisfy the Groth16 relation', async () => {
    const hash = await createHash()
    const pool = new PoolState(hash)
    const senderKey = 101n
    const receiverKey = 202n

    const shield = pool.build({
        mode: 0,
        publicIn: 1_000n,
        outputs: [{ amount: 1_000n, ownerKey: senderKey, rho: 10_001n }],
    })
    const senderDeposit = shield.outputNotes[0]

    const transfer = pool.build({
        mode: 1,
        spend: { note: senderDeposit },
        outputs: [
            { amount: 600n, ownerKey: receiverKey, rho: 20_001n },
            { amount: 400n, ownerKey: senderKey, rho: 20_002n },
        ],
    })
    const receiverNote = transfer.outputNotes[0]

    const unshield = pool.build({
        mode: 2,
        spend: { note: receiverNote },
        publicOut: 500n,
        recipient: 0x00112233445566778899aabbccddeeff00112233n,
        outputs: [{ amount: 100n, ownerKey: receiverKey, rho: 30_001n }],
    })

    assert.equal(shield.public.publicIn, 1_000n)
    assert.equal(transfer.public.publicIn, 0n)
    assert.equal(transfer.public.publicOut, 0n)
    assert.equal(unshield.public.publicOut, 500n)
    assert.notEqual(transfer.public.nullifier, 0n)
    assert.notEqual(unshield.public.nullifier, 0n)
    assert.equal(shield.statement, statementHash(hash, shield.public))

    const directory = await mkdtemp(path.join(tmpdir(), 'veil-bsv-test-'))
    try {
        for (const [name, transition] of [
            ['shield', shield],
            ['transfer', transfer],
            ['unshield', unshield],
        ] as const) {
            const witness = path.join(directory, `${name}.wtns`)
            await wtns.calculate(transition.circuitInput, WASM, witness)
            assert.equal(await wtns.check(R1CS, witness), true, `${name} witness failed`)
        }
    } finally {
        await rm(directory, { recursive: true, force: true })
    }
})

test('a spent note is rejected before proof generation', async () => {
    const hash = await createHash()
    const pool = new PoolState(hash)
    const shield = pool.build({
        mode: 0,
        publicIn: 10n,
        outputs: [{ amount: 10n, ownerKey: 7n, rho: 8n }],
    })
    const note = shield.outputNotes[0]
    pool.build({
        mode: 2,
        spend: { note },
        publicOut: 10n,
        recipient: 1n,
        outputs: [],
    })

    assert.throws(
        () =>
            pool.build({
                mode: 2,
                spend: { note },
                publicOut: 10n,
                recipient: 1n,
                outputs: [],
            }),
        /already spent/
    )
})

test('a private transfer requires both recipient and change notes', async () => {
    const hash = await createHash()
    const pool = new PoolState(hash)
    const shield = pool.build({
        mode: 0,
        publicIn: 10n,
        outputs: [{ amount: 10n, ownerKey: 7n, rho: 8n }],
    })

    assert.throws(
        () =>
            pool.build({
                mode: 1,
                spend: { note: shield.outputNotes[0] },
                outputs: [{ amount: 10n, ownerKey: 9n, rho: 10n }],
            }),
        /recipient note and a change note/
    )
})

test('a full note tree can still be unshielded with no change note', async () => {
    const hash = await createHash()
    const pool = new PoolState(hash)
    let firstNote: Note | undefined
    for (let index = 0; index < 16; index++) {
        const shield = pool.build({
            mode: 0,
            publicIn: 1n,
            outputs: [
                {
                    amount: 1n,
                    ownerKey: BigInt(index + 1),
                    rho: BigInt(1_000 + index),
                },
            ],
        })
        firstNote ??= shield.outputNotes[0]
    }
    assert.equal(pool.nextIndex, 16)

    const exit = pool.build({
        mode: 2,
        spend: { note: firstNote! },
        publicOut: 1n,
        recipient: 1n,
        outputs: [],
    })
    const directory = await mkdtemp(path.join(tmpdir(), 'veil-bsv-full-tree-'))
    try {
        const witness = path.join(directory, 'full-tree-unshield.wtns')
        await wtns.calculate(exit.circuitInput, WASM, witness)
        assert.equal(await wtns.check(R1CS, witness), true)
    } finally {
        await rm(directory, { recursive: true, force: true })
    }
})
