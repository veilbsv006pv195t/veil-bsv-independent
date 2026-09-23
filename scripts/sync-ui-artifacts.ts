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
writeFileSync(
    path.join(destination, 'mimc_constants.json'),
    JSON.stringify(Mimc7.CONSTS.map((value) => value.toString()))
)

console.log('Synced Groth16 browser artifacts to ui/public/zk/.')
