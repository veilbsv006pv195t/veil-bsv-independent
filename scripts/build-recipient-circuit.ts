import { execFileSync } from 'node:child_process'
import { cpSync, existsSync, mkdirSync } from 'node:fs'
import path from 'node:path'

// Isolated from historical replay assets. Development/testnet ceremony only.
const build = 'build/recipient'
mkdirSync(build, { recursive: true })
function run(args: string[]): void {
    execFileSync(path.resolve('node_modules/.bin/' + args[0]), args.slice(1), { stdio: 'inherit' })
}
// WASI cannot reliably resolve a node_modules symlink outside this checkout.
cpSync('node_modules/circomlib/circuits', `${build}/includes/circomlib/circuits`, { recursive: true })
run(['circom2', 'circuits/recipient/shielded_pool.circom', '--r1cs', '--wasm', '--sym', '-l', `${build}/includes`, '-o', build])
if (process.argv.includes('--compile-only')) process.exit(0)
if (!existsSync('build/pot18_final.ptau')) throw new Error('Run the legacy build:circuit first to generate the development phase-one transcript')
run(['snarkjs', 'groth16', 'setup', `${build}/shielded_pool.r1cs`, 'build/pot18_final.ptau', `${build}/shielded_pool_0000.zkey`])
run(['snarkjs', 'zkey', 'contribute', `${build}/shielded_pool_0000.zkey`, `${build}/shielded_pool_final.zkey`, '--name=Veil recipient-owned development circuit', '-e=veil-recipient-owned-testnet-only-development-phase-two'])
run(['snarkjs', 'zkey', 'export', 'verificationkey', `${build}/shielded_pool_final.zkey`, `${build}/verification_key.json`])
run(['snarkjs', 'zkey', 'verify', `${build}/shielded_pool.r1cs`, 'build/pot18_final.ptau', `${build}/shielded_pool_final.zkey`])
