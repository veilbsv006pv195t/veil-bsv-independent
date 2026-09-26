import test from 'node:test'
import assert from 'node:assert/strict'
import { AutoBackup, backupChoice } from '../ui/src/auto-backup'
import { encryptBackup, decryptBackup } from '../src/walletBackup'
import { encodeBackupFile, decodeBackupFile } from '../src/backupFile'
const password = 'synthetic-test-passphrase-only-123'
test('setup choices are exclusive, but active automatic mode allows an on-demand download', () => {
    const manual = backupChoice(false, false, false)
    assert.equal(manual.manualDisabled, false); assert.equal(manual.autoDisabled, true)
    const selected = backupChoice(true, false, false)
    assert.equal(selected.checked, true); assert.equal(selected.manualDisabled, true); assert.equal(selected.autoDisabled, false)
    assert.match(selected.hint, /not enabled yet/)
    const active = backupChoice(false, true, false)
    assert.equal(active.checked, true); assert.equal(active.consentDisabled, true); assert.equal(active.manualDisabled, false)
    assert.equal(backupChoice(true, true, false).manualDisabled, false)
    assert.equal(active.autoLabel, 'Update automatic-backup passphrase')
    for (const enabled of [false, true]) {
        const busy = backupChoice(true, enabled, true)
        assert.equal(busy.manualDisabled, true); assert.equal(busy.autoDisabled, true)
    }
    assert.equal(backupChoice(false, false, false).checked, false)
})
test('on-demand export retains automatic mode and its passphrase for the next wallet change', async () => {
    const backups = new AutoBackup()
    backups.enable(password)
    const files: Uint8Array[] = []
    let payload = { format: 'synthetic two-wallet fixture', wallets: ['sender', 'recipient'], revision: 1 }
    const build = async (secret: string) => {
        assert.equal(secret, password)
        return encodeBackupFile(await encryptBackup(payload, secret))
    }
    const offer = (file: Uint8Array) => { files.push(file) }
    await backups.request(build, offer)
    assert.equal(backups.confirm(), true)
    await backups.request(build, offer) // Explicit on-demand request; no new password.
    assert.equal(backups.enabled, true)
    assert.equal(backups.dirty, false)
    payload = { ...payload, revision: 2 }
    backups.changed()
    assert.equal(backups.due, true)
    await backups.request(build, offer)
    assert.equal(backups.enabled, true)
    assert.equal(backups.dirty, true)
    assert.equal(backups.canConfirm, true)
    assert.deepEqual(await decryptBackup(decodeBackupFile(files[2]), password), payload)
    assert.equal(files.length, 3)
})
test('opt-in, download request, explicit receipt and changed wallet are distinct', async () => {
    const b = new AutoBackup()
    b.changed(); assert.equal(b.due, false)
    b.enable(password); assert.equal(b.due, true)
    let offers = 0
    await b.request(async p => { assert.equal(p, password); return 'encrypted' }, () => offers++)
    assert.equal(offers, 1); assert.equal(b.dirty, true); assert.equal(b.due, false)
    assert.equal(b.confirm(), true); assert.equal(b.dirty, false)
    assert.equal(b.canConfirm, false)
    b.changed(); assert.equal(b.confirm(), false); assert.equal(b.due, true)
})
test('auto request produces a restorable authenticated compact file; another mutation produces a fresh encrypted revision', async () => {
    const b = new AutoBackup(); b.enable(password)
    let content = { fixture: 'synthetic unfunded state only', notes: ['pending'] }
    const files: Uint8Array[] = []
    const build = async (p: string) => {
        const file = encodeBackupFile(await encryptBackup(content, p))
        assert.deepEqual(await decryptBackup(decodeBackupFile(file), p), content)
        return file
    }
    await b.request(build, file => files.push(file))
    assert.equal(b.dirty, true)
    b.confirm(); content = { ...content, notes: ['synchronized'] }; b.changed()
    await b.request(build, file => files.push(file))
    assert.equal(files.length, 2)
    assert.notDeepEqual(files[0], files[1])
    assert.deepEqual(await decryptBackup(decodeBackupFile(files[1]), password), content)
    assert.equal(b.dirty, true)
    b.disable(); assert.equal(b.enabled, false)
})
test('in-flight stale snapshot cannot confirm newer state and is requeued', async () => {
    const b = new AutoBackup(); b.enable(password)
    let release!: () => void
    const wait = new Promise<void>(resolve => { release = resolve })
    let offers = 0
    const running = b.request(async () => { await wait; return 1 }, () => offers++)
    b.changed(); release(); await running
    assert.equal(offers, 0); assert.equal(b.confirm(), false); assert.equal(b.due, true)
})
test('restore/disable cancels offers; failures do not create retry storms or receipts', async () => {
    const b = new AutoBackup(); b.enable(password)
    await assert.rejects(b.request(async () => { throw Error('secret must not reach UI') }, () => assert.fail()))
    assert.equal(b.due, false); assert.equal(b.confirm(), false); assert.equal(b.dirty, true)
    await b.request(async () => { b.restored(); return 1 }, () => assert.fail())
    assert.equal(b.enabled, false); assert.equal(b.dirty, false); assert.equal(b.canConfirm, false)
    b.changed()
    await b.request(async p => { assert.equal(p, password); return 1 }, () => {}, password)
    assert.equal(b.enabled, false); assert.equal(b.dirty, true); assert.equal(b.confirm(), true)
})
