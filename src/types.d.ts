declare module 'circomlibjs' {
    export function buildMimc7(): Promise<{
        F: { toString(value: unknown): string }
        hash(left: bigint, right: bigint): unknown
    }>
}

declare module 'snarkjs' {
    export const wtns: {
        calculate(input: unknown, wasmPath: string, witnessPath: string): Promise<void>
        check(r1csPath: string, witnessPath: string): Promise<boolean>
    }
    export const groth16: {
        fullProve(
            input: unknown,
            wasmPath: string,
            zkeyPath: string
        ): Promise<{ proof: unknown; publicSignals: string[] }>
        verify(vkey: unknown, publicSignals: string[], proof: unknown): Promise<boolean>
    }
}
