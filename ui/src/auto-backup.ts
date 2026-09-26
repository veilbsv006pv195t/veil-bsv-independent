export function backupChoice(selected: boolean, enabled: boolean, busy: boolean) {
    const checked = selected || enabled
    return {
        checked,
        manualDisabled: busy || (selected && !enabled),
        consentDisabled: busy || enabled,
        autoDisabled: busy || !checked,
        autoLabel: enabled ? 'Update automatic-backup passphrase' : 'Enable automatic backups',
        hint: enabled
            ? 'Automatic backups are ON. Download backup now uses the current session passphrase and keeps automatic backups on. Enter a new passphrase only to update it with the separate button.'
            : selected
                ? 'Automatic selected, but not enabled yet. Enter your backup passphrase, then click Enable automatic backups. Uncheck to use manual download.'
                : 'Manual mode. Tick the checkbox to select automatic backups, then click Enable automatic backups.',
    }
}

export function backupPreparationMessage(dirty: boolean, busy: boolean, canConfirm: boolean, automatic: boolean): string | null {
    if (!dirty) return null
    if (busy) return 'Preparing your updated encrypted backup. Wait for the download, save it, then confirm it in Backup status. No upload is needed.'
    if (canConfirm) return 'Recovery data changed. Check that the latest backup file is saved, then confirm it in Backup status to enable preparation. No upload is needed.'
    return automatic
        ? 'Recovery data changed. An automatic backup is queued or needs retry. Review Backup status before preparing another action. No upload is needed.'
        : 'Recovery data changed. Download and save an updated backup, then confirm it in Backup status before preparing another action. No upload is needed.'
}

// Session-only coordination. A download request is NOT a saved-file receipt.
export class AutoBackup {
    revision = 0
    confirmedRevision = 0
    offeredRevision = -1
    attemptedRevision = -1
    busy = false
    status = 'Automatic backups off.'
    private password = ''
    private epoch = 0

    get enabled(): boolean { return this.password.length > 0 }
    get dirty(): boolean { return this.confirmedRevision !== this.revision }
    get canConfirm(): boolean { return this.dirty && !this.busy && this.offeredRevision === this.revision }
    get due(): boolean { return this.enabled && this.dirty && !this.busy && this.attemptedRevision !== this.revision }
    changed(): void {
        this.revision++
        this.status = this.enabled ? 'Wallet changed — encrypted backup queued.' : 'Wallet changed — save an updated encrypted backup.'
    }
    enable(password: string): void {
        if (password.length < 24) throw new Error('Use a unique backup passphrase of at least 24 characters')
        this.password = password
        this.epoch++
        this.attemptedRevision = -1
        this.offeredRevision = -1
        // Settings are not recovery mutations. A restored/confirmed checkpoint
        // remains valid; only an actual wallet change queues a required backup.
        this.status = this.dirty
            ? 'Automatic backups enabled — changed recovery data is queued for backup.'
            : 'Automatic backups enabled. Your restored or confirmed backup remains valid; no new download is needed until recovery data changes. Keep its original passphrase; the session passphrase is used for future exports.'
    }
    disable(): void {
        this.password = ''
        this.epoch++
        this.status = 'Automatic backups off. Manual backups remain available.'
    }
    restored(): void {
        this.disable()
        this.revision++
        this.confirmedRevision = this.revision
        this.offeredRevision = -1
        this.attemptedRevision = -1
        this.status = 'Restored backup. Automatic backups are off until you opt in for this session.'
    }
    confirm(): boolean {
        if (!this.canConfirm) return false
        this.confirmedRevision = this.revision
        this.status = 'Latest backup saved — confirmed by you, not verified by the browser.'
        return true
    }
    async request<T>(build: (password: string, revision: number) => Promise<T>, offer: (file: T, revision: number) => void, manualPassword?: string): Promise<void> {
        if (this.busy) return
        const password = manualPassword ?? this.password
        if (!password) throw new Error('Enable automatic backups or enter your backup passphrase')
        const revision = this.revision, epoch = this.epoch
        this.busy = true
        this.attemptedRevision = revision
        this.offeredRevision = -1
        this.status = 'Compressing, encrypting and verifying backup…'
        try {
            const file = await build(password, revision)
            // Never offer stale state or finish a cancelled session's download.
            if (epoch !== this.epoch || revision !== this.revision) return
            offer(file, revision)
            this.offeredRevision = revision
            this.status = this.dirty
                ? 'Download requested — check Downloads and confirm the file is saved. Browser prompts or blocking may apply.'
                : 'Additional backup copy requested. Your restored or confirmed backup remains valid. Check Downloads for this optional copy; browser prompts or blocking may apply.'
        } catch {
            if (epoch === this.epoch && revision === this.revision) this.status = this.dirty
                ? 'Backup failed. Keep this tab open; retry a manual download. No saved backup for the changed recovery data has been confirmed.'
                : 'Additional backup copy failed. Your restored or confirmed backup remains valid; retry the optional download if needed.'
            throw new Error('Encrypted backup could not be prepared or downloaded. Keep this wallet tab open.')
        } finally { this.busy = false }
    }
}
