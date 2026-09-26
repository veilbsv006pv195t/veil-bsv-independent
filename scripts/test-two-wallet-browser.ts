import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import path from 'node:path'
import { bsv } from 'scrypt-ts'
import { LiveVeilSession, PreparedLiveAction } from '../ui/src/live-builder'
import { createReceivingWallet, LiveWallet } from '../ui/src/live-wallet'
import { encryptBackup, decryptBackup } from '../src/walletBackup'
import { GuidedDemo } from '../ui/src/guided-demo'
import { encodeBackupFile, decodeBackupFile } from '../src/backupFile'

// Integration rehearsal: real proofs, signatures and Script execution; zero
// network access. MINED responses below are explicitly synthetic fixtures.
const mined = new Set<string>()
let height = 1_760_000
;(globalThis as any).document = { baseURI: 'https://veil.invalid/' }
globalThis.fetch = async (input, init) => {
    assert.ok(!init?.method || init.method === 'GET', 'This test must never broadcast')
    const url = new URL(String(input))
    if (url.origin === 'https://veil.invalid' && url.pathname.startsWith('/zk/')) {
        const asset = path.resolve('ui/public', '.' + url.pathname)
        assert.ok(asset.startsWith(path.resolve('ui/public/zk') + path.sep))
        return new Response(await readFile(asset))
    }
    if (url.href === 'https://testnet.arcade.gorillapool.io/health') return Response.json({ blockHeight: height })
    if (url.href === 'https://testnet.arcade.gorillapool.io/policy') return Response.json({ policy: { miningFee: { satoshis: 100, bytes: 1000 }, maxtxsizepolicy: 10_485_760, maxscriptsizepolicy: 500_000 } })
    if (url.origin === 'https://testnet.arc.gorillapool.io' && url.pathname.startsWith('/v1/tx/')) {
        const txid = url.pathname.slice('/v1/tx/'.length)
        return mined.has(txid) ? Response.json({ txid, txStatus: 'MINED' }) : new Response('', { status: 404 })
    }
    throw new Error('Unexpected network request in offline rehearsal')
}
const progress = (_percent: number | null, _label: string) => {}
function accept(session: LiveVeilSession, plan: PreparedLiveAction) {
    plan.transactions.forEach(tx => { assert.equal(new bsv.Transaction(tx.rawHex).id, tx.txid); mined.add(tx.txid) })
    session.commit(plan)
}
async function main() {
    const aliceWallet: LiveWallet = createReceivingWallet()
    aliceWallet.funding = { txid: '11'.repeat(32), vout: 0, satoshis: 10_000_000 }
    const alice = await LiveVeilSession.create(aliceWallet, progress)
    let guided = await GuidedDemo.create(aliceWallet, alice)
    const bobWallet = guided.slots.recipient.wallet
    const bobAddress = guided.defaultRecipient()
    const shield = await alice.prepare('shield', 100_000, '', 0, progress)
    accept(alice, shield)
    guided.accepted(shield)
    assert.equal(await guided.poll(progress), true)
    assert.equal(alice.privateBalance(), 100_000)
    await assert.rejects(alice.prepare('withdraw', 1, bsv.Address.fromScriptHash(Buffer.alloc(20, 1), bsv.Networks.testnet).toString(), 0, progress), /P2PKH/)
    console.log('PASS: Alice shield, exact signatures and all seven covenant stages')

    const send = await alice.prepare('send', 20_000, bobAddress, 0, progress)
    assert.ok(send.payment)
    assert.equal(send.recipient, bobAddress)
    await assert.rejects(LiveVeilSession.receive(bobWallet, send.payment!, progress), /MINED/)
    accept(alice, send)
    guided.accepted(send)
    // Recover both keys AND the unprocessed encrypted handoff from one backup.
    const pairBackup = await encryptBackup(guided.backupPayload(), 'synthetic combined backup phrase 12345')
    console.log('BACKUP SIZE pending handoff:', encodeBackupFile(pairBackup).length, 'bytes; legacy hex estimate:', JSON.stringify(guided.backupPayload()).length * 2, 'bytes')
    guided = await GuidedDemo.restore(await decryptBackup(decodeBackupFile(encodeBackupFile(pairBackup)), 'synthetic combined backup phrase 12345'), progress)
    assert.equal(guided.defaultRecipient(), bobAddress)
    assert.equal(guided.slots.recipient.session, null)
    assert.ok(guided.pending)
    assert.equal(await guided.poll(progress), true)
    assert.equal(alice.privateBalance(), 80_000, 'Recipient amount must leave the sender balance')
    const bob = guided.slots.recipient.session!
    assert.equal(bob.privateBalance(), 20_000)
    assert.notEqual(alice.receivingAddress(), bob.receivingAddress())
    await assert.rejects(bob.importPayment(send.payment!), /already been imported/)
    await assert.rejects(alice.importPayment(send.payment!), /different wallet/)
    console.log('PASS: independent encrypted receive, wrong-wallet and replay rejection')

    const backup = await encryptBackup(bob.backupPayload(), 'synthetic test backup phrase only 12345')
    const restored = await LiveVeilSession.restoreBackup(await decryptBackup(backup, 'synthetic test backup phrase only 12345'), progress)
    assert.equal(restored.privateBalance(), 20_000)
    assert.equal(restored.receivingAddress(), bob.receivingAddress())
    await assert.rejects(decryptBackup(backup, 'wrong'), /authentication/)
    console.log('PASS: encrypted wallet backup restores recipient-owned note')

    const funding = new bsv.Transaction().from({ txId: '22'.repeat(32), outputIndex: 0, script: bsv.Script.buildPublicKeyHashOut(bobWallet.address).toHex(), satoshis: 1_001_000 })
    funding.addOutput(new bsv.Transaction.Output({ script: bsv.Script.buildPublicKeyHashOut(bobWallet.address), satoshis: 1_000_000 }))
    funding.sign(bsv.PrivateKey.fromWIF(bobWallet.wif))
    mined.add(funding.id)
    await restored.bindFunding(funding.toString(), 0)
    guided.slots.recipient.session = restored
    guided.slots.sender.session = alice
    guided.active = 'recipient'
    const returnPayment = await restored.prepare('send', 1_000, guided.defaultRecipient(), 0, progress)
    accept(restored, returnPayment)
    guided.accepted(returnPayment)
    const reverseBackup = await encryptBackup(guided.backupPayload(), 'synthetic combined backup phrase 12345')
    const reverseRestored = await GuidedDemo.restore(await decryptBackup(reverseBackup, 'synthetic combined backup phrase 12345'), progress)
    assert.equal(await reverseRestored.poll(progress), true)
    assert.equal(reverseRestored.slots.sender.session!.privateBalance(), 81_000)
    assert.equal(await guided.poll(progress), true)
    const synchronizedBackup = await encryptBackup(guided.backupPayload(), 'synthetic combined backup phrase 12345')
    console.log('BACKUP SIZE synchronized:', encodeBackupFile(synchronizedBackup).length, 'bytes; legacy hex estimate:', JSON.stringify(guided.backupPayload()).length * 2, 'bytes')
    await GuidedDemo.restore(await decryptBackup(decodeBackupFile(encodeBackupFile(synchronizedBackup)), 'synthetic combined backup phrase 12345'), progress)
    console.log('PASS: reverse Send and both pending/synchronized combined backups')
    const withdrawal = await restored.prepare('withdraw', 19_000, bobWallet.address, 0, progress)
    assert.equal(withdrawal.newPrivateBalance, 0)
    const final = new bsv.Transaction(withdrawal.transactions.at(-1)!.rawHex)
    assert.equal(final.outputs[1].satoshis, 19_000)
    assert.equal(final.outputs[1].script.toHex(), bsv.Script.buildPublicKeyHashOut(bobWallet.address).toHex())
    accept(restored, withdrawal)
    guided.slots.recipient.session = restored
    guided.slots.sender.session = alice
    guided.active = 'recipient'
    guided.accepted(withdrawal)
    assert.equal(await guided.poll(progress), true)
    assert.equal(alice.privateBalance(), 81_000)
    await assert.rejects(alice.importPoolSnapshot(shield.snapshot), /missing intermediate|stale/)
    console.log('PASS: Bob withdrawal pays his address; Alice synchronizes public state')

    await assert.rejects(alice.prepare('lock', 75_000, '', String(height - 1), progress), /above/)
    const lock = await alice.prepare('lock', 75_000, '', '+2', progress)
    assert.equal(lock.unlockHeight, height + 2)
    assert.equal(lock.unlockHeight - lock.startHeight, 2)
    accept(alice, lock)
    guided.active = 'sender'
    guided.accepted(lock)
    assert.equal(await guided.poll(progress), true)
    assert.equal(alice.lockedBalance(height), 75_000)
    await assert.rejects(alice.prepare('withdraw', 10_000, aliceWallet.address, 0, progress), /No mature/)
    height += 2
    const mature = await alice.prepare('withdraw', 75_000, aliceWallet.address, 0, progress)
    accept(alice, mature)
    guided.accepted(mature)
    assert.equal(await guided.poll(progress), true)
    assert.equal(alice.privateBalance(), 6_000)
    assert.equal(alice.lockedBalance(height), 0)
    console.log('PASS: lock rejects early spend; mature withdrawal audited through all stages')
    console.log('PASS: guided handoff, combined backup restore and both-direction pool synchronization')
    console.log('ALL TWO-WALLET OFFLINE REHEARSAL CHECKS PASSED — no broadcasts or external requests')
}
main().then(() => process.exit(0), error => { console.error(error instanceof Error ? error.message : 'Rehearsal failed'); process.exit(1) })
