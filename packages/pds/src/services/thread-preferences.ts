import { AccountPreference } from '../actor-store/preference/reader'
import { AppContext } from '../context'

/**
 * Set default thread view preferences for an account
 * Sets both lab_treeViewEnabled (threaded vs linear) and sort preference
 */
export async function setThreadViewPreferences(
  ctx: AppContext,
  accountDid: string,
  options: {
    treeViewEnabled: boolean
    sort: string
  },
): Promise<void> {
  await ctx.actorStore.transact(accountDid, async (actorTxn) => {
    // Get existing preferences to preserve other settings
    const existingPrefs = await actorTxn.pref.getPreferences('app.bsky', {
      hasAccessFull: true,
    })

    // Remove any existing threadViewPref
    const otherPrefs = existingPrefs.filter(
      (pref) => pref.$type !== 'app.bsky.actor.defs#threadViewPref',
    )

    // Add new threadViewPref with both sort and lab_treeViewEnabled
    const newThreadPref: AccountPreference = {
      $type: 'app.bsky.actor.defs#threadViewPref',
      sort: options.sort,
      lab_treeViewEnabled: options.treeViewEnabled,
    }

    const updatedPrefs = [...otherPrefs, newThreadPref]

    await actorTxn.pref.putPreferences(updatedPrefs, 'app.bsky', {
      hasAccessFull: true,
    })
  })
}
