import { UnsignedEncoding } from '../unsignedEncoding'
import {
    assert,
    byteString2Int,
    ByteString,
    hash256,
    int2ByteString,
    method,
    prop,
    PubKeyHash,
    sha256,
    slice,
    SmartContract,
    toByteString,
    Utils,
} from 'scrypt-ts'
import {
    Proof,
} from 'scrypt-ts-lib/dist/zk/g16bn256'
import {
    OptimizedG16BN256,
    PairingResidueWitness,
    PreparedVerifyingKey,
} from '../optimizedGroth16'

const STATEMENT_DOMAIN = 1447381314n

/**
 * Stateful shielded-pool covenant using the generated bounded verifier.
 *
 * The UTXO's satoshi value is the public pool balance plus a one-satoshi
 * state anchor. The Groth16 statement authorizes the root transition; the
 * covenant binds that transition to the exact successor UTXO and, for an
 * unshield, the exact transparent P2PKH output.
 */
export class ShieldedPool extends SmartContract {
    @prop(true)
    noteRoot: bigint

    @prop(true)
    nullifierRoot: bigint

    @prop(true)
    nextIndex: bigint

    @prop()
    readonly vk: PreparedVerifyingKey

    constructor(
        noteRoot: bigint,
        nullifierRoot: bigint,
        nextIndex: bigint,
        vk: PreparedVerifyingKey
    ) {
        super(...arguments)
        this.noteRoot = noteRoot
        this.nullifierRoot = nullifierRoot
        this.nextIndex = nextIndex
        this.vk = vk
    }

    @method()
    public transit(
        proof: Proof,
        residueWitness: PairingResidueWitness,
        mode: bigint,
        outCount: bigint,
        newNoteRoot: bigint,
        newNullifierRoot: bigint,
        newNextIndex: bigint,
        nullifier: bigint,
        outputCommitment0: bigint,
        outputCommitment1: bigint,
        publicIn: bigint,
        publicOut: bigint,
        recipientField: bigint,
        currentHeight: bigint,
        recipientPkh: PubKeyHash
    ) {
        let statementBytes = int2ByteString(STATEMENT_DOMAIN, 4n)
        statementBytes += int2ByteString(mode, 1n)
        statementBytes += int2ByteString(outCount, 1n)
        statementBytes += int2ByteString(this.noteRoot, 32n)
        statementBytes += int2ByteString(newNoteRoot, 32n)
        statementBytes += int2ByteString(this.nullifierRoot, 32n)
        statementBytes += int2ByteString(newNullifierRoot, 32n)
        statementBytes += int2ByteString(this.nextIndex, 1n)
        statementBytes += int2ByteString(newNextIndex, 1n)
        statementBytes += int2ByteString(nullifier, 32n)
        statementBytes += int2ByteString(outputCommitment0, 32n)
        statementBytes += int2ByteString(outputCommitment1, 32n)
        statementBytes += int2ByteString(publicIn, 8n)
        statementBytes += int2ByteString(publicOut, 8n)
        statementBytes += UnsignedEncoding.uint160(recipientField)
        statementBytes += int2ByteString(currentHeight, 4n)
        const digest = sha256(statementBytes)
        const statement = byteString2Int(
            slice(digest, 0n, 31n) + toByteString('00')
        )

        // For transfers and withdrawals, bind the proof's public height to
        // Bitcoin's transaction-level nLockTime and require non-final sequence.
        // The circuit privately proves the input note's lock height has matured.
        if (mode > 0n) {
            assert(currentHeight < 500000000n, 'lock must use a block height')
            assert(this.timeLock(currentHeight), 'input note is still height-locked')
        }

        assert(
            OptimizedG16BN256.verify(statement, proof, residueWitness, this.vk),
            'invalid Groth16 proof'
        )

        // A 20-byte recipient is interpreted as the same little-endian field
        // element inside the circuit statement.
        if (publicOut > 0n) {
            assert(
                recipientPkh == UnsignedEncoding.uint160(recipientField),
                'recipient does not match the proof'
            )
        } else {
            assert(recipientField == 0n, 'private transitions have no recipient')
        }

        const nextPoolValue = this.ctx.utxo.value + publicIn - publicOut
        assert(nextPoolValue >= 1n, 'the one-satoshi state anchor must remain')

        this.noteRoot = newNoteRoot
        this.nullifierRoot = newNullifierRoot
        this.nextIndex = newNextIndex

        let outputs: ByteString = this.buildStateOutput(nextPoolValue)
        if (publicOut > 0n) {
            outputs += Utils.buildPublicKeyHashOutput(recipientPkh, publicOut)
        }
        outputs += this.buildChangeOutput()
        assert(hash256(outputs) == this.ctx.hashOutputs, 'unexpected transaction outputs')
    }
}
