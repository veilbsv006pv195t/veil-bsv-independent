import assert from 'node:assert/strict'
import { test } from 'node:test'
import { bsv, int2ByteString } from 'scrypt-ts'
import { UnsignedEncoding } from '../src/unsignedEncoding'

test('recipient encoding covers the entire unsigned HASH160 range', () => {
    for (const value of [0n, 1n, (1n << 159n) - 1n, 1n << 159n, (1n << 160n) - 1n]) {
        const expected = Buffer.from(value.toString(16).padStart(40, '0'), 'hex').reverse().toString('hex')
        assert.equal(UnsignedEncoding.uint160(value), expected)
        assert.equal(UnsignedEncoding.uint160(value).length, 40)
        if (value < (1n << 159n)) assert.equal(UnsignedEncoding.uint160(value), int2ByteString(value, 20n))
    }
})

test('the previously failing testnet recipient round-trips without losing the high bit', () => {
    const address = bsv.Address.fromString('mhjvr8VZSfeJqgqRYgUzZMjAftzZ5A1uSu', bsv.Networks.testnet)
    const bytes = address.hashBuffer
    const field = BigInt(`0x${Buffer.from(bytes).reverse().toString('hex')}`)
    assert.ok(field >= (1n << 159n))
    assert.equal(UnsignedEncoding.uint160(field), bytes.toString('hex'))
})

test('out-of-range recipient fields are rejected, never truncated into another recipient', () => {
    for (const value of [-1n, -(1n << 159n), 1n << 160n, (1n << 160n) + 1n]) {
        assert.throws(() => UnsignedEncoding.uint160(value), /unsigned 160-bit/)
    }
})
