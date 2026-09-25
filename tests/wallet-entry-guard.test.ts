import { test } from 'node:test'
import assert from 'node:assert/strict'
import { canUnlockOriginalWallet, type WalletEntryState } from '../ui/src/wallet-entry-guard'

const idle: WalletEntryState = {
    busy: false, unlocking: false, hasWallet: false, pendingPlan: false,
    checkingHandoff: false, restoreRequired: false,
}

test('first-time unlock is available only before a wallet operation or restore', () => {
    assert.equal(canUnlockOriginalWallet(idle), true)
    for (const flag of Object.keys(idle) as (keyof WalletEntryState)[]) {
        assert.equal(canUnlockOriginalWallet({ ...idle, [flag]: true }), false, flag)
    }
})
test('restoration never re-enables original-wallet unlock on completion', () => {
    assert.equal(canUnlockOriginalWallet({ ...idle, busy: true }), false)
    assert.equal(canUnlockOriginalWallet({ ...idle, hasWallet: true }), false)
    assert.equal(canUnlockOriginalWallet({ ...idle, hasWallet: true, restoreRequired: true }), false)
    assert.equal(canUnlockOriginalWallet({ ...idle, restoreRequired: true }), false, 'lock/clear still requires guided backup restoration')
})
