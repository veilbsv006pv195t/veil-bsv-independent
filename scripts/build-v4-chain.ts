import { createHash } from 'node:crypto'
import { deepStrictEqual } from 'node:assert'
import { mkdir, readFile, writeFile } from 'node:fs/promises'
import path from 'node:path'
import { Sha256, toByteString } from 'scrypt-ts'
import { SnarkVerificationKey } from '../src/groth16'
import { toPreparedVerifyingKey } from '../src/optimizedGroth16Data'
import { VeilV4Finalizer } from '../src/v4/veilV4Finalizer'
import { VeilV4Miller0 } from '../src/v4/veilV4Miller0'
import { VeilV4Miller1 } from '../src/v4/veilV4Miller1'
import { VeilV4Miller2 } from '../src/v4/veilV4Miller2'
import { VeilV4Miller3 } from '../src/v4/veilV4Miller3'
import { VeilV4Preparation } from '../src/v4/veilV4Preparation'
import { ShieldedPoolV4 } from '../src/v4/shieldedPoolV4'

function option(name: string, fallback: string): string {
    const prefix = `--${name}=`
    return process.argv.find((value) => value.startsWith(prefix))?.slice(prefix.length) ?? fallback
}

const VKEY = path.resolve(option('vkey', 'build/verification_key.json'))
const OUT = path.resolve(option('out', 'artifacts/v4/chain-manifest.json'))
const EXPECT = process.argv.find((value) => value.startsWith('--expect='))?.slice('--expect='.length)
const ZERO_HASH = Sha256(toByteString('00'.repeat(32)))

function hash256Hex(hex: string): string {
    const first = createHash('sha256').update(Buffer.from(hex, 'hex')).digest()
    return createHash('sha256').update(first).digest('hex')
}

function size(instance: { lockingScript: { toBuffer(): Buffer }; codePart: string }) {
    return {
        lockingScriptBytes: instance.lockingScript.toBuffer().length,
        codePartBytes: instance.codePart.length / 2,
        codePartHash256: hash256Hex(instance.codePart),
    }
}

async function main(): Promise<void> {
    VeilV4Finalizer.loadArtifact('artifacts/src/v4/veilV4Finalizer.json')
    VeilV4Miller0.loadArtifact('artifacts/src/v4/veilV4Miller0.json')
    VeilV4Miller1.loadArtifact('artifacts/src/v4/veilV4Miller1.json')
    VeilV4Miller2.loadArtifact('artifacts/src/v4/veilV4Miller2.json')
    VeilV4Miller3.loadArtifact('artifacts/src/v4/veilV4Miller3.json')
    VeilV4Preparation.loadArtifact('artifacts/src/v4/veilV4Preparation.json')
    ShieldedPoolV4.loadArtifact('artifacts/src/v4/shieldedPoolV4.json')

    const jsonVkey = JSON.parse(
        await readFile(VKEY, 'utf8')
    ) as SnarkVerificationKey
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
    const finalInfo = size(finalizer)

    const stage3 = new VeilV4Miller3(
        ZERO_HASH,
        Sha256(toByteString(finalInfo.codePartHash256)),
        vk.gammaLines.slice(67, 89) as never,
        vk.deltaLines.slice(67, 89) as never
    )
    const stage3Info = size(stage3)
    const stage2 = new VeilV4Miller2(
        ZERO_HASH,
        Sha256(toByteString(stage3Info.codePartHash256)),
        vk.gammaLines.slice(44, 67) as never,
        vk.deltaLines.slice(44, 67) as never
    )
    const stage2Info = size(stage2)
    const stage1 = new VeilV4Miller1(
        ZERO_HASH,
        Sha256(toByteString(stage2Info.codePartHash256)),
        vk.gammaLines.slice(23, 44) as never,
        vk.deltaLines.slice(23, 44) as never
    )
    const stage1Info = size(stage1)
    const stage0 = new VeilV4Miller0(
        ZERO_HASH,
        Sha256(toByteString(stage1Info.codePartHash256)),
        vk.gammaLines.slice(0, 23) as never,
        vk.deltaLines.slice(0, 23) as never
    )
    const stage0Info = size(stage0)
    const preparation = new VeilV4Preparation(
        ZERO_HASH,
        Sha256(toByteString(stage0Info.codePartHash256)),
        vk.gammaAbc[0],
        vk.gammaAbc[1]
    )
    const preparationInfo = size(preparation)
    const pool = new ShieldedPoolV4(
        0n,
        0n,
        0n,
        Sha256(toByteString(preparationInfo.codePartHash256))
    )
    const poolInfo = size(pool)

    const manifest = {
        format: 'veil-v4-staged-verifier-chain-v1',
        generatedAt: new Date().toISOString(),
        policyTargetBytes: 500_000,
        preparedLineRanges: {
            stage0: [0, 23],
            stage1: [23, 44],
            stage2: [44, 67],
            stage3: [67, 89],
            finalizer: [89, 91],
        },
        contracts: {
            pool: poolInfo,
            preparation: preparationInfo,
            stage0: stage0Info,
            stage1: stage1Info,
            stage2: stage2Info,
            stage3: stage3Info,
            finalizer: finalInfo,
        },
    }
    if (EXPECT) {
        const expected = JSON.parse(await readFile(path.resolve(EXPECT), 'utf8')) as {
            policyTargetBytes: number
            contracts: unknown
        }
        deepStrictEqual(manifest.policyTargetBytes, expected.policyTargetBytes)
        deepStrictEqual(manifest.contracts, expected.contracts)
        console.log(`✓ exact deployed v4 verifier manifest matched ${EXPECT}`)
        return
    }

    await mkdir(path.dirname(OUT), { recursive: true })
    await writeFile(OUT, JSON.stringify(manifest, null, 2) + '\n')
    console.log(JSON.stringify(manifest, null, 2))
}

main().catch((error: unknown) => {
    console.error(error)
    process.exitCode = 1
})
