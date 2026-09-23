import { assert, FixedArray, method, SmartContract } from 'scrypt-ts'
import { Mimc7 } from 'scrypt-ts-lib/dist/hash/mimc7'

const STATEMENT_DOMAIN = 1447381314n

export class StatementHashBenchmark extends SmartContract {
    @method()
    public check(
        values: FixedArray<bigint, 15>,
        expected: bigint
    ) {
        let digest = STATEMENT_DOMAIN
        for (let i = 0; i < 15; i++) {
            digest = Mimc7.hash(values[i], digest)
        }
        assert(digest == expected)
    }
}
