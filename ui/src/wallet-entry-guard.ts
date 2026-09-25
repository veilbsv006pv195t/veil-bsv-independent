export interface WalletEntryState {
    busy: boolean
    unlocking: boolean
    hasWallet: boolean
    pendingPlan: boolean
    checkingHandoff: boolean
    restoreRequired: boolean
}

/** Shared by the button and handler so Enter cannot bypass disabled Unlock. */
export function canUnlockOriginalWallet(state: WalletEntryState): boolean {
    return !state.busy && !state.unlocking && !state.hasWallet &&
        !state.pendingPlan && !state.checkingHandoff && !state.restoreRequired
}
