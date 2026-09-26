# v0.3.2 testnet lock heights

Published separately at `/veil-bsv-independent/v0.3.2/`; previous versions stay unchanged.

The UI requests the testnet miner height at launch, after wallet restore, and every minute while idle. Animated dots indicate a request; a failed request shows unavailable with Retry. There is no simulated height fallback. Requests time out after 45 seconds. Height updates do not rerender or clear password, amount, or recipient inputs.

Enter `+3` for three blocks beyond the fresh preparation-time height, or `1,759,968` for an absolute target. Plain numbers at or below the current height are rejected, never reinterpreted as offsets. Targets must be whole block heights below 500,000,000.

Live transaction preparation fetches the height again, then resolves the target once before proof construction. Review displays `1,759,968 (+3)` and the checked height. That count is measured from preparation, not a live countdown or time estimate. The signed transaction target does not move during review, broadcast or retry. The +100 and +1,000 shortcuts have been removed.

This changes no contract, wallet keys, note ownership, backup format or automatic-broadcast policy. Restore the latest encrypted backup into the new version; never operate the same wallet concurrently in two tabs, and never reload a partially submitted chain.
