import { execFileSync } from 'node:child_process'
import { mkdirSync, rmSync } from 'node:fs'
import path from 'node:path'

const root = process.cwd()
const build = path.join(root, 'build')
const npx = process.platform === 'win32' ? 'npx.cmd' : 'npx'

function run(command: string, args: string[]): void {
    console.log(`\n> ${command} ${args.join(' ')}`)
    execFileSync(command, args, { cwd: root, stdio: 'inherit' })
}

mkdirSync(build, { recursive: true })
for (const target of [
    'shielded_pool.r1cs',
    'shielded_pool.sym',
    'shielded_pool_js',
    'pot18_0000.ptau',
    'pot18_0001.ptau',
    'pot18_final.ptau',
    'shielded_pool_0000.zkey',
    'shielded_pool_final.zkey',
    'verification_key.json',
]) {
    rmSync(path.join(build, target), { recursive: true, force: true })
}

run(npx, [
    'circom2',
    'circuits/shielded_pool.circom',
    '--r1cs',
    '--wasm',
    '--sym',
    '-l',
    'node_modules',
    '-o',
    'build',
])
run(npx, ['snarkjs', 'r1cs', 'info', 'build/shielded_pool.r1cs'])
run(npx, ['snarkjs', 'powersoftau', 'new', 'bn128', '18', 'build/pot18_0000.ptau'])
run(npx, [
    'snarkjs',
    'powersoftau',
    'contribute',
    'build/pot18_0000.ptau',
    'build/pot18_0001.ptau',
    '--name=Veil replayable development ceremony',
    '-e=veil-bsv-development-only-phase-one',
])
run(npx, [
    'snarkjs',
    'powersoftau',
    'prepare',
    'phase2',
    'build/pot18_0001.ptau',
    'build/pot18_final.ptau',
])
run(npx, [
    'snarkjs',
    'groth16',
    'setup',
    'build/shielded_pool.r1cs',
    'build/pot18_final.ptau',
    'build/shielded_pool_0000.zkey',
])
run(npx, [
    'snarkjs',
    'zkey',
    'contribute',
    'build/shielded_pool_0000.zkey',
    'build/shielded_pool_final.zkey',
    '--name=Veil replayable development phase two',
    '-e=veil-bsv-development-only-phase-two',
])
run(npx, [
    'snarkjs',
    'zkey',
    'export',
    'verificationkey',
    'build/shielded_pool_final.zkey',
    'build/verification_key.json',
])
run(npx, [
    'snarkjs',
    'zkey',
    'verify',
    'build/shielded_pool.r1cs',
    'build/pot18_final.ptau',
    'build/shielded_pool_final.zkey',
])

console.log('\nCircuit, proving key, and verification key are ready in build/.')
