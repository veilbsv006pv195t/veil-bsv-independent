import { assert, ByteString, int2ByteString, method, slice, SmartContractLib } from 'scrypt-ts'

/** Canonical little-endian bytes matching the circuit's unsigned HASH160 field. */
export class UnsignedEncoding extends SmartContractLib {
    @method()
    static uint160(value: bigint): ByteString {
        // Script numbers are signed. Reserve a sign byte, then remove it only
        // after checking the range; otherwise distinct fields could alias.
        assert(value >= 0n && value < 1461501637330902918203684832716283019655932542976n,
            'recipient must be an unsigned 160-bit integer')
        return slice(int2ByteString(value, 21n), 0n, 20n)
    }
}
