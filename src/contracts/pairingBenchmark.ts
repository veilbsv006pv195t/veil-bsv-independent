import { assert, FixedArray, method, prop, SmartContract } from 'scrypt-ts'
import {
    G16BN256,
    Proof,
    VerifyingKey,
} from 'scrypt-ts-lib/dist/zk/g16bn256'

export class PairingBenchmark extends SmartContract {
    @prop()
    readonly vk: VerifyingKey

    constructor(vk: VerifyingKey) {
        super(...arguments)
        this.vk = vk
    }

    @method()
    public check(proof: Proof, signal: bigint) {
        const signals: FixedArray<bigint, 1> = [signal]
        assert(G16BN256.verify(signals, proof, this.vk))
    }
}
