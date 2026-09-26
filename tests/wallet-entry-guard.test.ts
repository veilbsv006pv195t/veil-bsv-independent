import { test } from 'node:test'
import assert from 'node:assert/strict'
import { canUnlockOriginalWallet, canCreateGuidedRecipient, type WalletEntryState } from '../ui/src/wallet-entry-guard'
import { readFileSync } from 'node:fs'

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

test('a shared marker requires both single-wallet restoration and explicit new-recipient consent', () => {
    assert.equal(canCreateGuidedRecipient(false, false, false), true)
    assert.equal(canCreateGuidedRecipient(true, false, false), false)
    assert.equal(canCreateGuidedRecipient(true, false, true), false)
    assert.equal(canCreateGuidedRecipient(true, true, false), false)
    assert.equal(canCreateGuidedRecipient(true, true, true), true)
})

test('single-wallet restore retains validation but does not consult the global marker or generate keys', () => {
    const source = readFileSync('ui/src/main.ts', 'utf8')
    const restore = source.slice(source.indexOf('async function restoreWallet('), source.indexOf("window.addEventListener('beforeunload'"))
    assert.match(restore, /decryptBackup\(envelope, password\)/)
    assert.match(restore, /payload\?\.protocol !== RECIPIENT_PROTOCOL/)
    assert.match(restore, /validateReceivingWallet\(payload.wallet\)/)
    assert.match(restore, /LiveVeilSession.restoreBackup\(payload, updateProofProgress\)/)
    assert.doesNotMatch(restore, /hasGuidedMarker|enableGuided|GuidedDemo\.create|localStorage\.removeItem/)
    assert.match(restore, /state.restoredSingle = true/)
})
test('restoration never re-enables original-wallet unlock on completion', () => {
    assert.equal(canUnlockOriginalWallet({ ...idle, busy: true }), false)
    assert.equal(canUnlockOriginalWallet({ ...idle, hasWallet: true }), false)
    assert.equal(canUnlockOriginalWallet({ ...idle, hasWallet: true, restoreRequired: true }), false)
    assert.equal(canUnlockOriginalWallet({ ...idle, restoreRequired: true }), false, 'lock/clear still requires guided backup restoration')
})
