import {
    ByteString,
    int2ByteString,
    method,
    PubKeyHash,
    sha256,
    Sha256,
    SmartContractLib,
    toByteString,
    VarIntWriter,
} from 'scrypt-ts'
import {
    CurvePoint,
    FQ2,
    FQ12,
    TwistPoint,
} from 'scrypt-ts-lib/dist/ec/bn256'
import { Proof } from 'scrypt-ts-lib/dist/zk/g16bn256'

export type V4Context = {
    transitionHash: Sha256
    poolCodeHash: Sha256
    lockedValue: bigint
    abortHeight: bigint
}

export type V4PreparationState = {
    signal: bigint
    proof: Proof
    residue: FQ12
    residueInverse: FQ12
    scale: bigint
    context: V4Context
}

export type V4MillerState = {
    q: TwistPoint
    p0: CurvePoint
    p1: CurvePoint
    p2: CurvePoint
    r: TwistPoint
    acc: FQ12
    residue: FQ12
    residueInverse: FQ12
    scale: bigint
    context: V4Context
}

export type V4Transition = {
    oldNoteRoot: bigint
    oldNullifierRoot: bigint
    oldNextIndex: bigint
    mode: bigint
    outCount: bigint
    newNoteRoot: bigint
    newNullifierRoot: bigint
    newNextIndex: bigint
    nullifier: bigint
    outputCommitment0: bigint
    outputCommitment1: bigint
    publicIn: bigint
    publicOut: bigint
    recipientField: bigint
    currentHeight: bigint
    recipientPkh: PubKeyHash
}

/** Canonical hashes carried by the small mutable state suffix of every stage. */
export class V4State extends SmartContractLib {
    @method()
    static writeInt(value: bigint): ByteString {
        return VarIntWriter.writeInt(value)
    }

    @method()
    static writeFQ2(value: FQ2): ByteString {
        return V4State.writeInt(value.x) + V4State.writeInt(value.y)
    }

    @method()
    static writeFQ12(value: FQ12): ByteString {
        let out = V4State.writeFQ2(value.x.x)
        out += V4State.writeFQ2(value.x.y)
        out += V4State.writeFQ2(value.x.z)
        out += V4State.writeFQ2(value.y.x)
        out += V4State.writeFQ2(value.y.y)
        out += V4State.writeFQ2(value.y.z)
        return out
    }

    @method()
    static writeCurve(value: CurvePoint): ByteString {
        let out = V4State.writeInt(value.x)
        out += V4State.writeInt(value.y)
        out += V4State.writeInt(value.z)
        out += V4State.writeInt(value.t)
        return out
    }

    @method()
    static writeTwist(value: TwistPoint): ByteString {
        let out = V4State.writeFQ2(value.x)
        out += V4State.writeFQ2(value.y)
        out += V4State.writeFQ2(value.z)
        out += V4State.writeFQ2(value.t)
        return out
    }

    @method()
    static writeContext(value: V4Context): ByteString {
        let out: ByteString = value.transitionHash
        out += value.poolCodeHash
        out += V4State.writeInt(value.lockedValue)
        out += V4State.writeInt(value.abortHeight)
        return out
    }

    @method()
    static hashPreparation(value: V4PreparationState): Sha256 {
        let out = toByteString('5645494c2d56342d50524550')
        out += V4State.writeInt(value.signal)
        out += V4State.writeInt(value.proof.a.x)
        out += V4State.writeInt(value.proof.a.y)
        out += V4State.writeFQ2(value.proof.b.x)
        out += V4State.writeFQ2(value.proof.b.y)
        out += V4State.writeInt(value.proof.c.x)
        out += V4State.writeInt(value.proof.c.y)
        out += V4State.writeFQ12(value.residue)
        out += V4State.writeFQ12(value.residueInverse)
        out += V4State.writeInt(value.scale)
        out += V4State.writeContext(value.context)
        return sha256(out)
    }

    @method()
    static hashMiller(value: V4MillerState): Sha256 {
        let out = toByteString('5645494c2d56342d4d494c4c4552')
        out += V4State.writeTwist(value.q)
        out += V4State.writeCurve(value.p0)
        out += V4State.writeCurve(value.p1)
        out += V4State.writeCurve(value.p2)
        out += V4State.writeTwist(value.r)
        out += V4State.writeFQ12(value.acc)
        out += V4State.writeFQ12(value.residue)
        out += V4State.writeFQ12(value.residueInverse)
        out += V4State.writeInt(value.scale)
        out += V4State.writeContext(value.context)
        return sha256(out)
    }

    @method()
    static hashTransition(value: V4Transition): Sha256 {
        let out = toByteString('5645494c2d56342d5452414e534954494f4e')
        out += V4State.writeInt(value.oldNoteRoot)
        out += V4State.writeInt(value.oldNullifierRoot)
        out += V4State.writeInt(value.oldNextIndex)
        out += V4State.writeInt(value.mode)
        out += V4State.writeInt(value.outCount)
        out += V4State.writeInt(value.newNoteRoot)
        out += V4State.writeInt(value.newNullifierRoot)
        out += V4State.writeInt(value.newNextIndex)
        out += V4State.writeInt(value.nullifier)
        out += V4State.writeInt(value.outputCommitment0)
        out += V4State.writeInt(value.outputCommitment1)
        out += V4State.writeInt(value.publicIn)
        out += V4State.writeInt(value.publicOut)
        out += V4State.writeInt(value.recipientField)
        out += V4State.writeInt(value.currentHeight)
        out += value.recipientPkh
        return sha256(out)
    }

    @method()
    static stateScript(codePart: ByteString, stateHash: Sha256): ByteString {
        const stateBytes =
            toByteString('00') + VarIntWriter.writeBytes(stateHash)
        return codePart + VarIntWriter.serializeState(stateBytes)
    }

    @method()
    static poolStateScript(
        codePart: ByteString,
        noteRoot: bigint,
        nullifierRoot: bigint,
        nextIndex: bigint
    ): ByteString {
        let stateBytes = toByteString('00')
        stateBytes += VarIntWriter.writeInt(noteRoot)
        stateBytes += VarIntWriter.writeInt(nullifierRoot)
        stateBytes += VarIntWriter.writeInt(nextIndex)
        return codePart + VarIntWriter.serializeState(stateBytes)
    }

    @method()
    static int32(value: bigint): ByteString {
        return int2ByteString(value, 4n)
    }
}
