import { bsv } from 'scrypt-ts'
import { transactionStatus } from './live-network'
import type { LiveWallet } from './live-wallet'

export async function checkedFunding(raw: string, index: number, address: string): Promise<LiveWallet['funding']> {
    if (!Number.isSafeInteger(index) || index < 0 || raw.length > 22_000_000 || !/^(?:[0-9a-f]{2})+$/.test(raw)) throw new Error('Invalid raw funding transaction or output index')
    const tx = new bsv.Transaction(raw)
    const output = tx.outputs[index]
    if (!output || output.satoshis <= 0 || output.script.toHex() !== bsv.Script.buildPublicKeyHashOut(address).toHex()) throw new Error('Funding output is not owned by this wallet')
    if ((await transactionStatus(tx.id))?.txStatus !== 'MINED') throw new Error('Wait for funding to be mined')
    return { txid: tx.id, vout: index, satoshis: output.satoshis }
}
