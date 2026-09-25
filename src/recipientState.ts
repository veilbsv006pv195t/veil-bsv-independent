import { FIELD, HashFn, Note, PoolState, TREE_CAPACITY, noteCommitment } from './crypto'
import { RECIPIENT_PROTOCOL } from './recipient'

export interface PoolSnapshot {
    protocol: typeof RECIPIENT_PROTOCOL
    poolId: string
    rawPoolTx: string
    previousPoolTxid: string
    chain: string[]
    nextIndex: number
    leaves: string[]
    nullifiers: string[]
}
export type EncodedNote = { amount: string; ownerKey: string; rho: string; lockHeight: string; index: number; commitment: string }
export function field(value: unknown): bigint {
    if (typeof value !== 'string' || !/^(0|[1-9][0-9]{0,77})$/.test(value)) throw new Error('Invalid field encoding')
    const n = BigInt(value)
    if (n >= FIELD) throw new Error('Field element out of range')
    return n
}
export function encodeNote(note: Note): EncodedNote {
    return { amount: note.amount.toString(), ownerKey: note.ownerKey.toString(), rho: note.rho.toString(), lockHeight: note.lockHeight.toString(), index: note.index, commitment: note.commitment.toString() }
}
export function decodeNote(value: EncodedNote, state: PoolState, owner: bigint, hash: HashFn): Note {
    if (!value || !Number.isSafeInteger(value.index) || value.index < 0 || value.index >= state.nextIndex) throw new Error('Invalid private note index')
    const note: Note = { amount: field(value.amount), ownerKey: field(value.ownerKey), rho: field(value.rho), lockHeight: field(value.lockHeight), index: value.index, commitment: field(value.commitment) }
    if (note.amount <= 0n || note.amount > BigInt(Number.MAX_SAFE_INTEGER) || note.lockHeight >= 500_000_000n || note.ownerKey !== owner ||
        noteCommitment(hash, note.amount, note.ownerKey, note.rho, note.lockHeight) !== note.commitment ||
        state.noteTree.leaves[note.index] !== note.commitment || state.nullifierTree.leaves[note.index] !== 0n) {
        throw new Error('Payment note is invalid, spent, or owned by another wallet')
    }
    return note
}
export function restorePool(value: PoolSnapshot, hash: HashFn): PoolState {
    if (!value || value.protocol !== RECIPIENT_PROTOCOL || !/^[0-9a-f]{64}$/.test(value.poolId) ||
        !Number.isSafeInteger(value.nextIndex) || value.nextIndex < 0 || value.nextIndex > TREE_CAPACITY ||
        !Array.isArray(value.leaves) || value.leaves.length !== TREE_CAPACITY ||
        !Array.isArray(value.nullifiers) || value.nullifiers.length !== TREE_CAPACITY ||
        !Array.isArray(value.chain) || value.chain.length !== 7 ||
        !/^[0-9a-f]{64}$/.test(value.previousPoolTxid)) throw new Error('Invalid recipient-owned pool snapshot')
    const pool = new PoolState(hash, true)
    value.leaves.forEach((v, i) => pool.noteTree.set(i, field(v)))
    value.nullifiers.forEach((v, i) => pool.nullifierTree.set(i, field(v)))
    pool.nextIndex = value.nextIndex
    for (let i = value.nextIndex; i < TREE_CAPACITY; i++) {
        if (pool.noteTree.leaves[i] !== 0n || pool.nullifierTree.leaves[i] !== 0n) throw new Error('Nonempty unused tree slot')
    }
    return pool
}
export function assertMonotonic(previous: PoolState, next: PoolState): void {
    if (next.nextIndex < previous.nextIndex) throw new Error('Stale pool snapshot')
    for (let i = 0; i < previous.nextIndex; i++) {
        if (previous.noteTree.leaves[i] !== next.noteTree.leaves[i] ||
            (previous.nullifierTree.leaves[i] !== 0n && previous.nullifierTree.leaves[i] !== next.nullifierTree.leaves[i])) {
            throw new Error('Pool snapshot rewrites known history')
        }
    }
}
