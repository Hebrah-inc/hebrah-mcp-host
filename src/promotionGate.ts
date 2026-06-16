/** Promotion plan gate — extracted for unit tests. */

export function assertCanPromoteToLive(canPromoteToLive: boolean | undefined): void {
  if (!canPromoteToLive) {
    throw new Error(
      'Promote-to-Live requires a Pro plan. Upgrade your organization to use promotion tools (create_promotion, approve_promotion, etc.).'
    )
  }
}
