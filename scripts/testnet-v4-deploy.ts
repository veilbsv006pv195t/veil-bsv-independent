import { spawnSync } from 'node:child_process'
import {
    chmodSync,
    existsSync,
    mkdirSync,
    readFileSync,
    writeFileSync,
} from 'node:fs'
import path from 'node:path'
import { bsv, hash256, Sha256, toByteString } from 'scrypt-ts'
import { PoolState, createHash } from '../src/crypto'
import { SnarkVerificationKey } from '../src/groth16'
import { toPreparedVerifyingKey } from '../src/optimizedGroth16Data'
import { ShieldedPoolV4 } from '../src/v4/shieldedPoolV4'
import { VeilV4Finalizer } from '../src/v4/veilV4Finalizer'
import { VeilV4Miller0 } from '../src/v4/veilV4Miller0'
import { VeilV4Miller1 } from '../src/v4/veilV4Miller1'
import { VeilV4Miller2 } from '../src/v4/veilV4Miller2'
import { VeilV4Miller3 } from '../src/v4/veilV4Miller3'
import { VeilV4Preparation } from '../src/v4/veilV4Preparation'

const ROOT = path.resolve(__dirname, '..')
const PRIVATE_DIR = path.join(ROOT, '.private')
const WALLET_FILE = path.join(PRIVATE_DIR, 'testnet-deployment-wallet.json')
const DRY_RUN_FILE = path.join(PRIVATE_DIR, 'testnet-v4-deployment-dry-run.json')
const SIGNED_FILE = path.join(PRIVATE_DIR, 'testnet-v4-deployment-signed.json')
const RECEIPT_FILE = path.join(PRIVATE_DIR, 'testnet-v4-deployment-receipt.json')
const CONFIRMATION_FILE = path.join(
    PRIVATE_DIR,
    'testnet-v4-deployment-confirmation.json'
)
const PENDING_V3_FILE = path.join(
    PRIVATE_DIR,
    'testnet-optimized-v3-shield-signed.json'
)
const VKEY = path.join(ROOT, 'build', 'verification_key.json')
const SOCKS = '127.0.0.1:19050'
const LEGACY_ARC = 'https://testnet.arc.gorillapool.io'
const ARCADE = 'https://testnet.arcade.gorillapool.io'
const ZERO_HASH = Sha256(toByteString('00'.repeat(32)))
const POLICY_TARGET = 500_000
const STATE_ANCHOR_SATS = 1
const CHANGE_DUST_SATS = 546
const FEE_SAFETY_SATS = 1_000
const FAKE_FUNDING_SATS = 50_000

interface WalletFile {
    network: 'testnet'
    address: string
    wif: string
}

interface Funding {
    txid: string
    vout: number
    satoshis: number
    blockheight: number
}

interface Policy {
    miningFee: { satoshis: number; bytes: number }
    maxtxsizepolicy: number
    maxscriptsizepolicy: number
}

interface ContractInfo {
    lockingScriptBytes: number
    codePartHash256: string
}

interface V4Plan {
    format: 'veil-v4-testnet-deployment-plan-v1'
    network: 'testnet'
    torOnly: true
    broadcast: false
    broadcastBlocked: boolean
    conflictReason: string | null
    conflictsWithPendingTxid: string | null
    fundingOutpoint: string
    fundingSatoshis: number
    deploymentTxid: string
    transactionBytes: number
    feeRateSatsPerKb: number
    feeSatoshis: number
    poolOutputIndex: 0
    poolOutputSatoshis: 1
    changeSatoshis: number
    initialState: {
        noteRoot: string
        nullifierRoot: string
        nextNoteIndex: '0'
    }
    policy: {
        maxScriptBytes: number
        maxTransactionBytes: number
    }
    contracts: Record<string, ContractInfo>
}

interface SignedV4Deployment extends V4Plan {
    createdAt: string
    transactionHex: string
}

interface ArcStatus {
    txid?: string
    txStatus?: string
    blockHash?: string
    blockHeight?: number
    extraInfo?: string
    merklePath?: string
}

function writePrivate(file: string, value: unknown, exclusive = false): void {
    mkdirSync(PRIVATE_DIR, { recursive: true, mode: 0o700 })
    chmodSync(PRIVATE_DIR, 0o700)
    writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`, {
        flag: exclusive ? 'wx' : 'w',
        mode: 0o600,
    })
    chmodSync(file, 0o600)
}

function loadWallet(): WalletFile {
    const wallet = JSON.parse(readFileSync(WALLET_FILE, 'utf8')) as WalletFile
    const key = bsv.PrivateKey.fromWIF(wallet.wif)
    if (
        wallet.network !== 'testnet' ||
        key.network.name !== 'testnet' ||
        key.toAddress(bsv.Networks.testnet).toString() !== wallet.address
    ) {
        throw new Error('Refusing invalid or non-testnet deployment wallet')
    }
    return wallet
}

function torJson(url: string): unknown {
    if (!url.startsWith(`${LEGACY_ARC}/`) && !url.startsWith(`${ARCADE}/`)) {
        throw new Error('Remote URL is outside the testnet allowlist')
    }
    const result = spawnSync(
        'curl',
        [
            '--silent',
            '--show-error',
            '--fail-with-body',
            '--socks5-hostname',
            SOCKS,
            '--noproxy',
            '',
            '--proto',
            '=https',
            '--connect-timeout',
            '20',
            '--max-time',
            '60',
            url,
        ],
        {
            encoding: 'utf8',
            env: {
                ...process.env,
                HTTP_PROXY: '',
                HTTPS_PROXY: '',
                ALL_PROXY: '',
                http_proxy: '',
                https_proxy: '',
                all_proxy: '',
                NO_PROXY: '',
                no_proxy: '',
            },
        }
    )
    if (result.error || result.status !== 0) {
        throw new Error(
            `Tor-only request failed: ${(result.stderr || result.error?.message || '').trim()}`
        )
    }
    return JSON.parse(result.stdout) as unknown
}

function torPostTransaction(rawHex: string): { httpStatus: number; response: unknown } {
    const marker = '__VEIL_HTTP__:'
    const result = spawnSync(
        'curl',
        [
            '--silent',
            '--show-error',
            '--socks5-hostname',
            SOCKS,
            '--noproxy',
            '',
            '--proto',
            '=https',
            '--connect-timeout',
            '20',
            '--max-time',
            '180',
            '--request',
            'POST',
            '--header',
            'Content-Type: text/plain',
            '--header',
            'X-WaitForStatus: SEEN_ON_NETWORK',
            '--data-binary',
            '@-',
            '--write-out',
            `\n${marker}%{http_code}`,
            `${LEGACY_ARC}/v1/tx`,
        ],
        {
            input: rawHex,
            encoding: 'utf8',
            maxBuffer: 16 * 1024 * 1024,
            env: {
                ...process.env,
                HTTP_PROXY: '',
                HTTPS_PROXY: '',
                ALL_PROXY: '',
                http_proxy: '',
                https_proxy: '',
                all_proxy: '',
                NO_PROXY: '',
                no_proxy: '',
            },
        }
    )
    if (result.error || result.status !== 0) {
        throw new Error(
            `Tor-only submission failed: ${(result.stderr || result.error?.message || '').trim()}`
        )
    }
    const split = result.stdout.lastIndexOf(`\n${marker}`)
    if (split < 0) throw new Error('ARC response omitted its HTTP status')
    const httpStatus = Number(result.stdout.slice(split + marker.length + 1))
    const text = result.stdout.slice(0, split)
    let response: unknown = text
    try {
        response = JSON.parse(text)
    } catch {
        // Preserve a non-JSON rejection body in the private receipt.
    }
    return { httpStatus, response }
}

function replacementApproval(): string | null {
    const arg = process.argv.find((value) => value.startsWith('--replace-pending-v3='))
    if (!arg) return null
    const txid = arg.slice('--replace-pending-v3='.length)
    if (!/^[0-9a-f]{64}$/i.test(txid)) {
        throw new Error('Replacement approval must contain the exact pending v3 TXID')
    }
    return txid.toLowerCase()
}

function getPolicy(): Policy {
    const value = torJson(`${ARCADE}/policy`) as { policy?: Partial<Policy> }
    const policy = value.policy
    if (
        !policy ||
        !policy.miningFee ||
        !Number.isSafeInteger(policy.miningFee.satoshis) ||
        !Number.isSafeInteger(policy.miningFee.bytes) ||
        !Number.isSafeInteger(policy.maxscriptsizepolicy) ||
        !Number.isSafeInteger(policy.maxtxsizepolicy)
    ) {
        throw new Error('Arcade returned an invalid policy')
    }
    return policy as Policy
}

function fundingOverride(): Funding | null {
    const arg = process.argv.find((value) => value.startsWith('--funding='))
    if (!arg) return null
    const [txid, voutText, satoshisText, heightText] = arg.slice(10).split(':')
    const funding = {
        txid,
        vout: Number(voutText),
        satoshis: Number(satoshisText),
        blockheight: Number(heightText),
    }
    if (
        !/^[0-9a-f]{64}$/i.test(funding.txid) ||
        !Number.isSafeInteger(funding.vout) ||
        funding.vout < 0 ||
        !Number.isSafeInteger(funding.satoshis) ||
        funding.satoshis <= 0 ||
        !Number.isSafeInteger(funding.blockheight) ||
        funding.blockheight <= 0
    ) {
        throw new Error('Funding must be txid:vout:satoshis:confirmedBlockHeight')
    }
    return funding
}

function validateFunding(funding: Funding): void {
    const value = torJson(`${LEGACY_ARC}/v1/tx/${funding.txid}`) as {
        txid?: string
        txStatus?: string
        blockHeight?: number
    }
    if (
        value.txid?.toLowerCase() !== funding.txid.toLowerCase() ||
        value.txStatus !== 'MINED' ||
        value.blockHeight !== funding.blockheight
    ) {
        throw new Error('ARC did not confirm the funding transaction at the supplied height')
    }
}

function pendingConflict(funding: Funding): string | null {
    if (!existsSync(PENDING_V3_FILE)) return null
    const saved = JSON.parse(readFileSync(PENDING_V3_FILE, 'utf8')) as {
        txid?: string
        rawHex?: string
    }
    if (!saved.rawHex || !saved.txid) return null
    const tx = new bsv.Transaction(saved.rawHex)
    const spendsFunding = tx.inputs.some(
        (input) =>
            input.prevTxId.toString('hex') === funding.txid &&
            input.outputIndex === funding.vout
    )
    return spendsFunding ? saved.txid : null
}

function codeHash(codePart: string): Sha256 {
    return hash256(codePart)
}

function info(instance: { lockingScript: { toBuffer(): Buffer }; codePart: string }): ContractInfo {
    return {
        lockingScriptBytes: instance.lockingScript.toBuffer().length,
        codePartHash256: codeHash(instance.codePart),
    }
}

function buildContractChain(
    noteRoot: bigint,
    nullifierRoot: bigint
): { pool: ShieldedPoolV4; contracts: Record<string, ContractInfo> } {
    ShieldedPoolV4.loadArtifact('artifacts/src/v4/shieldedPoolV4.json')
    VeilV4Preparation.loadArtifact('artifacts/src/v4/veilV4Preparation.json')
    VeilV4Miller0.loadArtifact('artifacts/src/v4/veilV4Miller0.json')
    VeilV4Miller1.loadArtifact('artifacts/src/v4/veilV4Miller1.json')
    VeilV4Miller2.loadArtifact('artifacts/src/v4/veilV4Miller2.json')
    VeilV4Miller3.loadArtifact('artifacts/src/v4/veilV4Miller3.json')
    VeilV4Finalizer.loadArtifact('artifacts/src/v4/veilV4Finalizer.json')
    const jsonVkey = JSON.parse(readFileSync(VKEY, 'utf8')) as SnarkVerificationKey
    const vk = toPreparedVerifyingKey(jsonVkey)
    const finalizer = new VeilV4Finalizer(
        ZERO_HASH,
        vk.millerb1a1,
        vk.root27,
        vk.root27Squared,
        vk.gammaLines[89],
        vk.deltaLines[89],
        vk.gammaLines[90],
        vk.deltaLines[90]
    )
    const stage3 = new VeilV4Miller3(
        ZERO_HASH,
        codeHash(finalizer.codePart),
        vk.gammaLines.slice(67, 89) as never,
        vk.deltaLines.slice(67, 89) as never
    )
    const stage2 = new VeilV4Miller2(
        ZERO_HASH,
        codeHash(stage3.codePart),
        vk.gammaLines.slice(44, 67) as never,
        vk.deltaLines.slice(44, 67) as never
    )
    const stage1 = new VeilV4Miller1(
        ZERO_HASH,
        codeHash(stage2.codePart),
        vk.gammaLines.slice(23, 44) as never,
        vk.deltaLines.slice(23, 44) as never
    )
    const stage0 = new VeilV4Miller0(
        ZERO_HASH,
        codeHash(stage1.codePart),
        vk.gammaLines.slice(0, 23) as never,
        vk.deltaLines.slice(0, 23) as never
    )
    const preparation = new VeilV4Preparation(
        ZERO_HASH,
        codeHash(stage0.codePart),
        vk.gammaAbc[0],
        vk.gammaAbc[1]
    )
    const pool = new ShieldedPoolV4(
        noteRoot,
        nullifierRoot,
        0n,
        codeHash(preparation.codePart)
    )
    return {
        pool,
        contracts: {
            pool: info(pool),
            preparation: info(preparation),
            stage0: info(stage0),
            stage1: info(stage1),
            stage2: info(stage2),
            stage3: info(stage3),
            finalizer: info(finalizer),
        },
    }
}

async function buildDeployment(
    wallet: WalletFile,
    funding: Funding,
    policy: Policy
): Promise<{ plan: V4Plan; transactionHex: string }> {
    const state = new PoolState(await createHash())
    const { pool, contracts } = buildContractChain(
        state.noteTree.root(),
        state.nullifierTree.root()
    )
    const overPolicy = Object.entries(contracts).filter(
        ([, value]) => value.lockingScriptBytes > policy.maxscriptsizepolicy
    )
    if (policy.maxscriptsizepolicy > POLICY_TARGET || overPolicy.length > 0) {
        throw new Error(
            `Unexpected script policy ${policy.maxscriptsizepolicy}; ` +
            `over-policy contracts: ${overPolicy.map(([name]) => name).join(', ') || 'none'}`
        )
    }

    const feeRate = Math.ceil(
        (policy.miningFee.satoshis * 1_000) / policy.miningFee.bytes
    )
    const estimatedBytes = pool.lockingScript.toBuffer().length + 1_000
    const estimatedFee =
        Math.ceil((estimatedBytes * feeRate) / 1_000) + FEE_SAFETY_SATS
    const minimumFunding = estimatedFee + STATE_ANCHOR_SATS + CHANGE_DUST_SATS
    if (funding.satoshis < minimumFunding) {
        throw new Error(`Funding requires at least ${minimumFunding} satoshis`)
    }

    const address = bsv.Address.fromString(wallet.address, bsv.Networks.testnet)
    const tx = new bsv.Transaction()
    tx.from({
        txId: funding.txid,
        outputIndex: funding.vout,
        script: bsv.Script.buildPublicKeyHashOut(address).toHex(),
        satoshis: funding.satoshis,
    })
    tx.addOutput(
        new bsv.Transaction.Output({ script: pool.lockingScript, satoshis: 1 })
    )
    tx.fee(estimatedFee)
    tx.change(address)
    tx.sign(bsv.PrivateKey.fromWIF(wallet.wif))
    if (!tx.isFullySigned()) throw new Error('V4 deployment is not fully signed')

    const transactionBytes = tx.toString().length / 2
    if (transactionBytes > policy.maxtxsizepolicy) {
        throw new Error('V4 deployment exceeds transaction-size policy')
    }
    const outputs = tx.outputs.reduce((sum, output) => sum + output.satoshis, 0)
    const feeSatoshis = funding.satoshis - outputs
    const minimumFee = Math.ceil((transactionBytes * feeRate) / 1_000)
    if (feeSatoshis < minimumFee) {
        throw new Error(`V4 deployment fee ${feeSatoshis} is below ${minimumFee}`)
    }
    const conflict = pendingConflict(funding)
    const conflictReason = conflict
        ? 'Funding outpoint is already referenced by the pending v3 shield; broadcasting would be a double-spend replacement.'
        : null
    return {
        transactionHex: tx.toString(),
        plan: {
            format: 'veil-v4-testnet-deployment-plan-v1',
            network: 'testnet',
            torOnly: true,
            broadcast: false,
            broadcastBlocked: conflict !== null,
            conflictReason,
            conflictsWithPendingTxid: conflict,
            fundingOutpoint: `${funding.txid}:${funding.vout}`,
            fundingSatoshis: funding.satoshis,
            deploymentTxid: tx.id,
            transactionBytes,
            feeRateSatsPerKb: feeRate,
            feeSatoshis,
            poolOutputIndex: 0,
            poolOutputSatoshis: 1,
            changeSatoshis: tx.outputs.slice(1).reduce(
                (sum, output) => sum + output.satoshis,
                0
            ),
            initialState: {
                noteRoot: state.noteTree.root().toString(),
                nullifierRoot: state.nullifierTree.root().toString(),
                nextNoteIndex: '0',
            },
            policy: {
                maxScriptBytes: policy.maxscriptsizepolicy,
                maxTransactionBytes: policy.maxtxsizepolicy,
            },
            contracts,
        },
    }
}

function auditSigned(value: SignedV4Deployment): Omit<SignedV4Deployment, 'transactionHex'> {
    const tx = new bsv.Transaction(value.transactionHex)
    const [txid, vout] = value.fundingOutpoint.split(':')
    const checks: Record<string, boolean> = {
        transactionId: tx.id === value.deploymentTxid,
        transactionBytes: tx.toString().length / 2 === value.transactionBytes,
        oneInput: tx.inputs.length === 1,
        fundingTxid: tx.inputs[0].prevTxId.toString('hex') === txid,
        fundingVout: tx.inputs[0].outputIndex === Number(vout),
        twoOutputs: tx.outputs.length === 2,
        poolAnchor: tx.outputs[0].satoshis === 1,
        poolScriptBytes:
            tx.outputs[0].script.toBuffer().length ===
            value.contracts.pool.lockingScriptBytes,
        change: tx.outputs[1].satoshis === value.changeSatoshis,
        fee:
            value.fundingSatoshis -
                tx.outputs.reduce((sum, output) => sum + output.satoshis, 0) ===
            value.feeSatoshis,
        notBroadcast: value.broadcast === false,
    }
    const failed = Object.entries(checks)
        .filter(([, passed]) => !passed)
        .map(([name]) => name)
    if (failed.length > 0) throw new Error(`V4 deployment audit failed: ${failed.join(', ')}`)
    const { transactionHex: _secretTransactionBytes, ...audit } = value
    return audit
}

async function main(): Promise<void> {
    const command = process.argv[2]
    if (!['status', 'dry-run', 'prepare', 'audit', 'send', 'confirm'].includes(command)) {
        throw new Error('Usage: testnet-v4-deploy.ts status|dry-run|prepare|audit|send|confirm [--funding=txid:vout:sats:height] [--replace-pending-v3=txid]')
    }
    if (command === 'audit') {
        if (!existsSync(SIGNED_FILE)) throw new Error('No signed v4 deployment exists')
        console.log(JSON.stringify(auditSigned(
            JSON.parse(readFileSync(SIGNED_FILE, 'utf8')) as SignedV4Deployment
        ), null, 2))
        return
    }
    if (command === 'confirm') {
        if (!existsSync(SIGNED_FILE)) throw new Error('No signed v4 deployment exists')
        const signed = JSON.parse(
            readFileSync(SIGNED_FILE, 'utf8')
        ) as SignedV4Deployment
        auditSigned(signed)
        const response = torJson(
            `${LEGACY_ARC}/v1/tx/${signed.deploymentTxid}`
        ) as ArcStatus
        if (
            response.txid?.toLowerCase() !== signed.deploymentTxid.toLowerCase() ||
            response.txStatus !== 'MINED' ||
            !Number.isSafeInteger(response.blockHeight) ||
            (response.blockHeight as number) <= 0 ||
            !/^[0-9a-f]{64}$/i.test(response.blockHash ?? '') ||
            typeof response.merklePath !== 'string' ||
            response.merklePath.length === 0
        ) {
            throw new Error('ARC has not returned valid mined inclusion evidence for v4')
        }
        const confirmation = {
            format: 'veil-v4-testnet-deployment-confirmation-v1',
            network: 'testnet',
            torOnly: true,
            deploymentTxid: signed.deploymentTxid,
            txStatus: response.txStatus,
            blockHeight: response.blockHeight,
            blockHash: response.blockHash,
            merklePath: response.merklePath,
            confirmedAt: new Date().toISOString(),
        }
        if (!existsSync(CONFIRMATION_FILE)) {
            writePrivate(CONFIRMATION_FILE, confirmation, true)
        }
        console.log(JSON.stringify({
            ...confirmation,
            merklePath: undefined,
            merkleInclusionEvidenceAvailable: true,
        }, null, 2))
        return
    }
    if (command === 'send') {
        if (!existsSync(SIGNED_FILE)) throw new Error('No signed v4 deployment exists')
        if (existsSync(RECEIPT_FILE)) {
            throw new Error('A v4 deployment receipt already exists; refusing to resubmit')
        }
        const signed = JSON.parse(
            readFileSync(SIGNED_FILE, 'utf8')
        ) as SignedV4Deployment
        auditSigned(signed)
        if (!signed.broadcastBlocked || !signed.conflictsWithPendingTxid) {
            throw new Error('This command is only for the explicitly approved v3 replacement')
        }
        const approvedReplacement = replacementApproval()
        if (approvedReplacement !== signed.conflictsWithPendingTxid.toLowerCase()) {
            throw new Error(
                'Refusing replacement without --replace-pending-v3=<exact pending v3 TXID>'
            )
        }
        const pending = torJson(
            `${LEGACY_ARC}/v1/tx/${signed.conflictsWithPendingTxid}`
        ) as ArcStatus
        if (pending.txStatus === 'MINED') {
            throw new Error('The v3 shield is already mined; its funding outpoint cannot be replaced')
        }
        const policy = getPolicy()
        if (
            signed.contracts.pool.lockingScriptBytes > policy.maxscriptsizepolicy ||
            signed.transactionBytes > policy.maxtxsizepolicy
        ) {
            throw new Error('Current miner policy no longer accepts the audited v4 deployment')
        }
        const submitted = torPostTransaction(signed.transactionHex)
        const receipt = {
            format: 'veil-v4-testnet-deployment-receipt-v1',
            submittedAt: new Date().toISOString(),
            deploymentTxid: signed.deploymentTxid,
            replacedPendingV3Txid: signed.conflictsWithPendingTxid,
            torOnly: true,
            httpStatus: submitted.httpStatus,
            response: submitted.response,
        }
        writePrivate(RECEIPT_FILE, receipt, true)
        const response = submitted.response as ArcStatus
        if (
            submitted.httpStatus < 200 ||
            submitted.httpStatus >= 300 ||
            response.txid?.toLowerCase() !== signed.deploymentTxid.toLowerCase() ||
            !response.txStatus ||
            ![
                'QUEUED',
                'RECEIVED',
                'STORED',
                'ANNOUNCED_TO_NETWORK',
                'REQUESTED_BY_NETWORK',
                'SENT_TO_NETWORK',
                'ACCEPTED_BY_NETWORK',
                'SEEN_ON_NETWORK',
                'MINED',
            ].includes(response.txStatus)
        ) {
            throw new Error(`ARC did not accept the v4 deployment: ${JSON.stringify(receipt)}`)
        }
        console.log(JSON.stringify(receipt, null, 2))
        return
    }
    const policy = getPolicy()
    if (command === 'status') {
        console.log(JSON.stringify({
            network: 'testnet',
            torOnly: true,
            policy,
            pendingV3ShieldRecord: existsSync(PENDING_V3_FILE),
            signedV4Deployment: existsSync(SIGNED_FILE),
            broadcastCommandAvailable: true,
        }, null, 2))
        return
    }
    const wallet = loadWallet()
    const supplied = fundingOverride()
    if (command === 'prepare' && !supplied) {
        throw new Error('prepare requires an explicit confirmed --funding override')
    }
    const funding = supplied ?? {
        txid: '11'.repeat(32),
        vout: 0,
        satoshis: FAKE_FUNDING_SATS,
        blockheight: 1,
    }
    if (supplied) validateFunding(supplied)
    const built = await buildDeployment(wallet, funding, policy)
    if (command === 'dry-run') {
        writePrivate(DRY_RUN_FILE, built.plan)
        console.log(JSON.stringify(built.plan, null, 2))
        return
    }
    if (existsSync(SIGNED_FILE)) {
        throw new Error('A signed v4 deployment already exists; audit it before any replacement')
    }
    const signed: SignedV4Deployment = {
        ...built.plan,
        createdAt: new Date().toISOString(),
        transactionHex: built.transactionHex,
    }
    writePrivate(SIGNED_FILE, signed, true)
    console.log(JSON.stringify(built.plan, null, 2))
    console.log('Signed v4 deployment saved locally with mode 0600; no broadcast command exists.')
}

main().catch((error: unknown) => {
    console.error(error instanceof Error ? error.message : error)
    process.exitCode = 1
})
