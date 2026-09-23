import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import {
    ArcTransactionResponse,
    DeploymentPlan,
    makeBroadcastReceipt,
    validateArcResponse,
    validateMinedArcResponse,
} from '../scripts/testnet-deploy'

const txid = 'ab'.repeat(32)

const plan: DeploymentPlan = {
    network: 'testnet',
    broadcast: false,
    fundingOutpoint: `${'11'.repeat(32)}:0`,
    fundingSatoshis: 3_000_000,
    deploymentTxid: txid,
    transactionBytes: 2_072_089,
    lockingScriptBytes: 2_071_884,
    lockingScriptSha256: 'cd'.repeat(32),
    feeRateSatsPerKb: 101,
    feeSatoshis: 210_362,
    poolOutputIndex: 0,
    poolOutputSatoshis: 1,
    changeSatoshis: 2_789_637,
    initialState: {
        noteRoot: '1',
        nullifierRoot: '1',
        nextNoteIndex: '0',
    },
}

const accepted: ArcTransactionResponse = {
    status: 200,
    timestamp: '2026-09-21T22:30:00.000Z',
    title: 'OK',
    txStatus: 'SEEN_ON_NETWORK',
    txid,
}

describe('testnet deployment broadcast safeguards', () => {
    it('accepts an ARC success response only for the signed transaction', () => {
        assert.deepEqual(validateArcResponse(accepted, txid), accepted)
    })

    it('rejects a response for a different transaction', () => {
        assert.throws(
            () => validateArcResponse({ ...accepted, txid: 'ef'.repeat(32) }, txid),
            /does not match/
        )
    })

    it('rejects error and unsafe ARC transaction states', () => {
        assert.throws(
            () => validateArcResponse({ ...accepted, status: 463 }, txid),
            /rejected/
        )
        assert.throws(
            () => validateArcResponse({ ...accepted, txStatus: 'REJECTED' }, txid),
            /non-success/
        )
        assert.throws(
            () => validateArcResponse({ ...accepted, txStatus: 'DOUBLE_SPEND_ATTEMPTED' }, txid),
            /non-success/
        )
    })

    it('creates a sanitized public receipt', () => {
        const receipt = makeBroadcastReceipt(plan, accepted, '2026-09-21T22:31:00.000Z')
        const serialized = JSON.stringify(receipt)

        assert.equal(receipt.broadcast, true)
        assert.equal(receipt.deploymentTxid, txid)
        assert.equal(receipt.arcResponse.txid, txid)
        assert.equal('transactionHex' in receipt, false)
        assert.equal(serialized.includes('wif'), false)
        assert.equal(serialized.includes('privateKey'), false)
        assert.equal(serialized.includes('seed'), false)
    })

    it('accepts complete mined inclusion evidence and rejects incomplete evidence', () => {
        const mined = {
            txid,
            txStatus: 'MINED',
            blockHeight: 1_759_469,
            blockHash: '01'.repeat(32),
            merklePath: 'abcd',
        }
        assert.deepEqual(validateMinedArcResponse(mined, txid), mined)
        assert.throws(
            () => validateMinedArcResponse({ ...mined, merklePath: '' }, txid),
            /mined inclusion evidence/
        )
    })
})
