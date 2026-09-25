import { copyFileSync, mkdirSync, writeFileSync } from 'node:fs'
import path from 'node:path'
import { Mimc7 } from 'scrypt-ts-lib/dist/hash/mimc7'

const root = process.cwd()
const destination = path.join(root, 'ui/public/zk')
mkdirSync(destination, { recursive: true })

for (const [source, name] of [
    ['build/shielded_pool_js/shielded_pool.wasm', 'shielded_pool.wasm'],
    ['build/shielded_pool_final.zkey', 'shielded_pool_final.zkey'],
    ['build/verification_key.json', 'verification_key.json'],
] as const) {
    copyFileSync(path.join(root, source), path.join(destination, name))
}
const contractDestination = path.join(destination, 'contracts')
const recipientDestination = path.join(destination, 'recipient')
mkdirSync(recipientDestination, { recursive: true })
for (const [source, name] of [
    ['shielded_pool_js/shielded_pool.wasm', 'shielded_pool.wasm'],
    ['shielded_pool_final.zkey', 'shielded_pool_final.zkey'],
    ['verification_key.json', 'verification_key.json'],
] as const) {
    copyFileSync(path.join(root, 'build/recipient', source), path.join(recipientDestination, name))
}
mkdirSync(contractDestination, { recursive: true })
for (const name of [
    'shieldedPoolV4',
    'veilV4Preparation',
    'veilV4Miller0',
    'veilV4Miller1',
    'veilV4Miller2',
    'veilV4Miller3',
    'veilV4Finalizer',
] as const) {
    copyFileSync(
        path.join(root, 'artifacts', 'src', 'v4', `${name}.json`),
        path.join(contractDestination, `${name}.json`)
    )
}
writeFileSync(
    path.join(destination, 'mimc_constants.json'),
    JSON.stringify(Mimc7.CONSTS.map((value) => value.toString()))
)

console.log('Synced Groth16 and v4 contract browser artifacts to ui/public/zk/.')
