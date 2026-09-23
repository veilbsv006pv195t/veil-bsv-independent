import { assert, method, prop, SmartContract } from 'scrypt-ts'
import { Proof } from 'scrypt-ts-lib/dist/zk/g16bn256'
import {
    OptimizedG16BN256,
    PairingResidueWitness,
    PreparedVerifyingKey,
} from '../optimizedGroth16'

export class OptimizedPairingBenchmark extends SmartContract {
    @prop()
    readonly vk: PreparedVerifyingKey

    constructor(vk: PreparedVerifyingKey) {
        super(...arguments)
        this.vk = vk
    }

    @method()
    public check(
        proof: Proof,
        signal: bigint,
        residueWitness: PairingResidueWitness
    ) {
        assert(OptimizedG16BN256.verify(signal, proof, residueWitness, this.vk))
    }
}
