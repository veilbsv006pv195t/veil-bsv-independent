import { sha256 } from '@noble/hashes/sha2'

export const TREE_DEPTH = 4
export const TREE_CAPACITY = 1 << TREE_DEPTH
export const FIELD =
    21888242871839275222246405745257275088548364400416034343698204186575808495617n
export const STATEMENT_DOMAIN = 1447381314n
export const MAX_BLOCK_HEIGHT = 499_999_999n
// Domain separation for recipient-owned notes; the original circuit is retained
// for historical replay only. This public identifier is not a spending secret.
export const RECIPIENT_KEY_DOMAIN = 1447381298n
export function recipientOwner(hash: HashFn, spendingKey: bigint): bigint {
    if (spendingKey <= 0n || spendingKey >= FIELD) throw new Error('Invalid recipient spending key')
    // MiMC7 is a keyed permutation. The secret MUST be the key (right slot):
    // hash(secret, publicDomain) is invertible under the known public key.
    return hash(RECIPIENT_KEY_DOMAIN, spendingKey)
}

export type HashFn = (left: bigint, right: bigint) => bigint

export async function createHash(): Promise<HashFn> {
    const { buildMimc7 } = await import('circomlibjs')
    const mimc = await buildMimc7()
    return (left: bigint, right: bigint): bigint =>
        BigInt(mimc.F.toString(mimc.hash(left, right)))
}

export function noteCommitment(
    hash: HashFn,
    amount: bigint,
    ownerKey: bigint,
    rho: bigint,
    lockHeight = 0n
): bigint {
    return hash(hash(hash(amount, ownerKey), lockHeight), rho)
}

export function noteNullifier(
    hash: HashFn,
    commitment: bigint,
    ownerKey: bigint
): bigint {
    return hash(commitment, ownerKey)
}

export class MerkleTree {
    readonly depth: number
    readonly leaves: bigint[]
    private readonly hash: HashFn

    constructor(hash: HashFn, depth = TREE_DEPTH, leaves?: readonly bigint[]) {
        this.hash = hash
        this.depth = depth
        this.leaves = Array.from(
            { length: 1 << depth },
            (_, i) => leaves?.[i] ?? 0n
        )
    }

    clone(): MerkleTree {
        return new MerkleTree(this.hash, this.depth, this.leaves)
    }

    set(index: number, value: bigint): void {
        if (!Number.isInteger(index) || index < 0 || index >= this.leaves.length) {
            throw new Error(`leaf index ${index} is outside the tree`)
        }
        this.leaves[index] = value
    }

    root(): bigint {
        return this.layers().at(-1)![0]
    }

    path(index: number): bigint[] {
        if (!Number.isInteger(index) || index < 0 || index >= this.leaves.length) {
            throw new Error(`leaf index ${index} is outside the tree`)
        }
        const layers = this.layers()
        const siblings: bigint[] = []
        let cursor = index
        for (let level = 0; level < this.depth; level++) {
            siblings.push(layers[level][cursor ^ 1])
            cursor >>= 1
        }
        return siblings
    }

    private layers(): bigint[][] {
        const layers = [this.leaves.slice()]
        for (let level = 0; level < this.depth; level++) {
            const previous = layers[level]
            const next: bigint[] = []
            for (let i = 0; i < previous.length; i += 2) {
                next.push(this.hash(previous[i], previous[i + 1]))
            }
            layers.push(next)
        }
        return layers
    }
}

export interface PublicTransition {
    mode: bigint
    outCount: bigint
    oldNoteRoot: bigint
    newNoteRoot: bigint
    oldNullifierRoot: bigint
    newNullifierRoot: bigint
    oldNextIndex: bigint
    newNextIndex: bigint
    nullifier: bigint
    outputCommitment0: bigint
    outputCommitment1: bigint
    publicIn: bigint
    publicOut: bigint
    recipient: bigint
    currentHeight: bigint
}

export const PUBLIC_FIELD_ORDER: readonly (keyof PublicTransition)[] = [
    'mode',
    'outCount',
    'oldNoteRoot',
    'newNoteRoot',
    'oldNullifierRoot',
    'newNullifierRoot',
    'oldNextIndex',
    'newNextIndex',
    'nullifier',
    'outputCommitment0',
    'outputCommitment1',
    'publicIn',
    'publicOut',
    'recipient',
    'currentHeight',
]

export function statementHash(hash: HashFn, transition: PublicTransition): bigint {
    void hash
    const widths = [1, 1, 32, 32, 32, 32, 1, 1, 32, 32, 32, 8, 8, 20, 4] as const
    const encode = (value: bigint, bytes: number) => {
        if (value < 0n) throw new Error('statement fields must be nonnegative')
        const output = new Uint8Array(bytes)
        let remaining = value
        for (let i = 0; i < bytes; i++) {
            output[i] = Number(remaining & 0xffn)
            remaining >>= 8n
        }
        if (remaining !== 0n) throw new Error(`statement field exceeds ${bytes} bytes`)
        return output
    }
    const encoded = [
        encode(STATEMENT_DOMAIN, 4),
        ...PUBLIC_FIELD_ORDER.map((key, index) =>
            encode(transition[key], widths[index])
        ),
    ]
    const serializedLength = encoded.reduce((total, value) => total + value.length, 0)
    const serialized = new Uint8Array(serializedLength)
    let offset = 0
    for (const value of encoded) {
        serialized.set(value, offset)
        offset += value.length
    }
    const digest = sha256(serialized)
    let statement = 0n
    for (let i = 30; i >= 0; i--) {
        statement = (statement << 8n) + BigInt(digest[i])
    }
    return statement
}

export interface Note {
    amount: bigint
    ownerKey: bigint
    rho: bigint
    lockHeight: bigint
    index: number
    commitment: bigint
}

export interface OutputNoteData {
    amount: bigint
    ownerKey: bigint
    rho: bigint
    lockHeight?: bigint
}

export interface SpendData {
    note: Note
    spendingKey?: bigint
}

export interface TransitionRequest {
    mode: 0 | 1 | 2
    spend?: SpendData
    outputs: readonly OutputNoteData[]
    publicIn?: bigint
    publicOut?: bigint
    recipient?: bigint
    currentHeight?: bigint
}

export interface BuiltTransition {
    public: PublicTransition
    statement: bigint
    circuitInput: Record<string, string | string[]>
    outputNotes: Note[]
}

function decimal(value: bigint | number): string {
    return BigInt(value).toString()
}

function decimals(values: readonly bigint[]): string[] {
    return values.map(decimal)
}

export class PoolState {
    readonly noteTree: MerkleTree
    readonly nullifierTree: MerkleTree
    nextIndex: number
    private readonly hash: HashFn

    constructor(hash: HashFn, readonly recipientOwned = false) {
        this.hash = hash
        this.noteTree = new MerkleTree(hash)
        this.nullifierTree = new MerkleTree(hash)
        this.nextIndex = 0
    }

    build(request: TransitionRequest): BuiltTransition {
        const publicIn = request.publicIn ?? 0n
        const publicOut = request.publicOut ?? 0n
        const currentHeight = request.currentHeight ?? 0n
        const expectedOutputs = request.mode === 0 ? 1 : undefined
        if (expectedOutputs !== undefined && request.outputs.length !== expectedOutputs) {
            throw new Error(`mode ${request.mode} requires ${expectedOutputs} output note(s)`)
        }
        if (request.mode === 1 && request.outputs.length !== 2) {
            throw new Error('private transfer requires a recipient note and a change note')
        }
        if (request.mode === 2 && request.outputs.length > 1) {
            throw new Error('unshield supports at most one change note')
        }
        if (request.mode === 0 && request.spend) {
            throw new Error('shield cannot spend a private note')
        }
        if (request.mode !== 0 && !request.spend) {
            throw new Error('transfer and unshield require a private input note')
        }
        if (request.mode === 0 && (publicIn <= 0n || publicOut !== 0n)) {
            throw new Error('shield requires a positive public input and no public output')
        }
        if (request.mode === 0 && currentHeight !== 0n) {
            throw new Error('shield does not use a spending height')
        }
        if (request.mode === 1 && (publicIn !== 0n || publicOut !== 0n)) {
            throw new Error('private transfer cannot cross the public boundary')
        }
        if (request.mode === 2 && (publicIn !== 0n || publicOut <= 0n)) {
            throw new Error('unshield requires a positive public output and no public input')
        }
        if (request.outputs.some((output) => output.amount <= 0n)) {
            throw new Error('enabled output notes must have a positive value')
        }
        if (currentHeight < 0n || currentHeight > MAX_BLOCK_HEIGHT) {
            throw new Error('current height must be a valid block height')
        }
        if (
            request.outputs.some(
                (output) =>
                    (output.lockHeight ?? 0n) < 0n ||
                    (output.lockHeight ?? 0n) > MAX_BLOCK_HEIGHT
            )
        ) {
            throw new Error('note lock height must be below 500,000,000')
        }
        const inputAmount = request.spend?.note.amount ?? 0n
        const outputAmount = request.outputs.reduce((total, output) => total + output.amount, 0n)
        if (inputAmount + publicIn !== outputAmount + publicOut) {
            throw new Error('transition does not conserve value')
        }
        if (this.nextIndex + request.outputs.length > TREE_CAPACITY) {
            throw new Error('note tree is full')
        }

        const oldNoteRoot = this.noteTree.root()
        const oldNullifierRoot = this.nullifierTree.root()
        const oldNextIndex = this.nextIndex
        const spend = request.spend?.note
        const inputIndex = spend?.index ?? 0
        const inputNoteSiblings = this.noteTree.path(inputIndex)
        const inputNullifierSiblings = this.nullifierTree.path(inputIndex)

        if (spend) {
            if (this.recipientOwned && (
                request.spend?.spendingKey === undefined ||
                recipientOwner(this.hash, request.spend.spendingKey) !== spend.ownerKey
            )) throw new Error('Recipient spending key does not own this note')
            if (this.noteTree.leaves[spend.index] !== spend.commitment) {
                throw new Error('input note is not in the current note tree')
            }
            if (this.nullifierTree.leaves[spend.index] !== 0n) {
                throw new Error('input note is already spent')
            }
            if (currentHeight < spend.lockHeight) {
                throw new Error(
                    `note is locked until block ${spend.lockHeight.toString()}`
                )
            }
        }

        const nullifier = spend
            ? noteNullifier(this.hash, spend.commitment, this.recipientOwned ? request.spend!.spendingKey! : spend.ownerKey)
            : 0n
        if (spend) this.nullifierTree.set(spend.index, nullifier)

        const append0Siblings =
            oldNextIndex < TREE_CAPACITY
                ? this.noteTree.path(oldNextIndex)
                : Array.from({ length: TREE_DEPTH }, () => 0n)
        const outputNotes: Note[] = []
        for (const output of request.outputs) {
            const commitment = noteCommitment(
                this.hash,
                output.amount,
                output.ownerKey,
                output.rho,
                output.lockHeight ?? 0n
            )
            const note: Note = {
                amount: output.amount,
                ownerKey: output.ownerKey,
                rho: output.rho,
                lockHeight: output.lockHeight ?? 0n,
                index: this.nextIndex,
                commitment,
            }
            this.noteTree.set(this.nextIndex, commitment)
            this.nextIndex++
            outputNotes.push(note)
        }
        const append1Index = oldNextIndex + 1
        const append1Siblings =
            append1Index < TREE_CAPACITY
                ? (() => {
                      // For two outputs this must describe the tree after output zero.
                      // For fewer outputs the path is unused by the constraints.
                      const beforeSecond = this.noteTree.clone()
                      for (let i = oldNextIndex + request.outputs.length; i < TREE_CAPACITY; i++) {
                          beforeSecond.set(i, this.noteTree.leaves[i])
                      }
                      return beforeSecond.path(append1Index)
                  })()
                : Array.from({ length: TREE_DEPTH }, () => 0n)

        // append1Siblings must be captured immediately after output zero, not after output one.
        if (request.outputs.length === 2) {
            const afterFirst = new MerkleTree(this.hash, TREE_DEPTH)
            afterFirst.leaves.splice(0, afterFirst.leaves.length, ...this.noteTree.leaves)
            afterFirst.set(oldNextIndex + 1, 0n)
            append1Siblings.splice(0, append1Siblings.length, ...afterFirst.path(oldNextIndex + 1))
        }

        const recipient = request.recipient ?? 0n
        const output0 = request.outputs[0] ?? {
            amount: 0n,
            ownerKey: 0n,
            rho: 0n,
            lockHeight: 0n,
        }
        const output1 = request.outputs[1] ?? {
            amount: 0n,
            ownerKey: 0n,
            rho: 0n,
            lockHeight: 0n,
        }

        const transition: PublicTransition = {
            mode: BigInt(request.mode),
            outCount: BigInt(request.outputs.length),
            oldNoteRoot,
            newNoteRoot: this.noteTree.root(),
            oldNullifierRoot,
            newNullifierRoot: this.nullifierTree.root(),
            oldNextIndex: BigInt(oldNextIndex),
            newNextIndex: BigInt(this.nextIndex),
            nullifier,
            outputCommitment0: outputNotes[0]?.commitment ?? 0n,
            outputCommitment1: outputNotes[1]?.commitment ?? 0n,
            publicIn,
            publicOut,
            recipient,
            currentHeight,
        }
        const statement = statementHash(this.hash, transition)

        return {
            public: transition,
            statement,
            outputNotes,
            circuitInput: {
                statement: decimal(statement),
                ...Object.fromEntries(
                    PUBLIC_FIELD_ORDER.map((key) => [key, decimal(transition[key])])
                ),
                inputAmount: decimal(spend?.amount ?? 0n),
                inputOwnerKey: decimal(spend?.ownerKey ?? 0n),
                ...(this.recipientOwned ? { inputSpendingKey: decimal(request.spend?.spendingKey ?? 0n) } : {}),
                inputLockHeight: decimal(spend?.lockHeight ?? 0n),
                inputRho: decimal(spend?.rho ?? 0n),
                inputIndex: decimal(inputIndex),
                inputNoteSiblings: decimals(inputNoteSiblings),
                inputNullifierSiblings: decimals(inputNullifierSiblings),
                output0Amount: decimal(output0.amount),
                output0OwnerKey: decimal(output0.ownerKey),
                output0LockHeight: decimal(output0.lockHeight ?? 0n),
                output0Rho: decimal(output0.rho),
                output1Amount: decimal(output1.amount),
                output1OwnerKey: decimal(output1.ownerKey),
                output1LockHeight: decimal(output1.lockHeight ?? 0n),
                output1Rho: decimal(output1.rho),
                append0Siblings: decimals(append0Siblings),
                append1Siblings: decimals(append1Siblings),
            },
        }
    }
}
