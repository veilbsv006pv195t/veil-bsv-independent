export interface Timing {
    id: number; label: string; started: number; ended?: number; outcome?: string
    phases: Array<{ label: string; started: number; ended?: number }>
}
/** Local timing only. Never stores keys, addresses, amounts or transaction data. */
export class Stopwatches {
    readonly records: Timing[] = []
    private sequence = 0
    private overallStarted?: number
    private overallEnded?: number
    constructor(private readonly now = () => performance.now()) {}
    startOverall(): void { if (this.overallStarted === undefined) this.overallStarted = this.now() }
    stopOverall(): void { if (this.overallStarted !== undefined) this.overallEnded = this.now() }
    resetOverall(): void { this.overallStarted = this.now(); this.overallEnded = undefined }
    overallMs(): number { return this.overallStarted === undefined ? 0 : (this.overallEnded ?? this.now()) - this.overallStarted }
    start(label: string, phase = 'Starting'): number {
        this.startOverall()
        const id = ++this.sequence, started = this.now()
        this.records.push({ id, label, started, phases: [{ label: phase, started }] })
        return id
    }
    phase(id: number | null, label: string): void {
        const record = this.records.find(r => r.id === id)
        if (!record || record.ended !== undefined || record.phases.at(-1)?.label === label) return
        const now = this.now()
        record.phases.at(-1)!.ended = now
        record.phases.push({ label, started: now })
    }
    finish(id: number | null, outcome: string): void {
        const record = this.records.find(r => r.id === id)
        if (!record || record.ended !== undefined) return
        record.ended = this.now(); record.outcome = outcome
        record.phases.at(-1)!.ended = record.ended
    }
    snapshot() {
        const now = this.now()
        return { overallMs: this.overallMs(), running: this.overallStarted !== undefined && this.overallEnded === undefined,
            operations: this.records.map(r => ({ id: r.id, label: r.label, elapsedMs: (r.ended ?? now) - r.started,
                outcome: r.outcome ?? 'In progress', phases: r.phases.map(p => ({ label: p.label, elapsedMs: (p.ended ?? now) - p.started })) })) }
    }
}
export function elapsed(ms: number): string {
    const seconds = Math.max(0, Math.floor(ms / 1000))
    return `${String(Math.floor(seconds / 3600)).padStart(2, '0')}:${String(Math.floor(seconds / 60) % 60).padStart(2, '0')}:${String(seconds % 60).padStart(2, '0')}`
}
