import { AtUri } from '@atproto/syntax'
import { AppContext } from '../context'

/**
 * Subscribe an account to one or more lists by adding them to savedFeedsPrefV2.
 *
 * This is used for:
 * - Auto-subscribing human/test accounts to default lists on creation
 * - Admin command to subscribe existing accounts to lists
 *
 * @param ctx - Application context
 * @param accountDid - DID of the account to subscribe
 * @param listUris - Array of AT-URIs for lists to subscribe to
 * @param pinned - Whether to pin the lists (default: true)
 * @returns Number of lists successfully subscribed to
 */
export async function subscribeToLists(
  ctx: AppContext,
  accountDid: string,
  listUris: string[],
  pinned = true,
): Promise<number> {
  if (listUris.length === 0) {
    return 0
  }

  // Validate all list URIs before modifying preferences
  for (const listUri of listUris) {
    try {
      const parsed = new AtUri(listUri)
      if (parsed.collection !== 'app.bsky.graph.list') {
        throw new Error(
          `Invalid list URI: ${listUri} (must be app.bsky.graph.list collection)`,
        )
      }
    } catch (err) {
      throw new Error(`Invalid list AT-URI: ${listUri}`)
    }
  }

  // Get current preferences
  const currentPrefs = await ctx.actorStore.transact(
    accountDid,
    async (actorTxn) => {
      return actorTxn.pref.getPreferences('app.bsky', {
        hasAccessFull: true,
      })
    },
  )

  // Find existing savedFeedsPrefV2 or create new one
  const savedFeedsIndex = currentPrefs.findIndex(
    (pref: any) => pref.$type === 'app.bsky.actor.defs#savedFeedsPrefV2',
  )

  let savedFeeds: {
    $type: string
    items: Array<{
      id: string
      type: string
      value: string
      pinned: boolean
    }>
  }

  if (savedFeedsIndex >= 0) {
    const existing = currentPrefs[savedFeedsIndex]
    if ('items' in existing && Array.isArray(existing.items)) {
      savedFeeds = existing as typeof savedFeeds
    } else {
      savedFeeds = {
        $type: 'app.bsky.actor.defs#savedFeedsPrefV2',
        items: [],
      }
    }
  } else {
    savedFeeds = {
      $type: 'app.bsky.actor.defs#savedFeedsPrefV2',
      items: [],
    }
  }

  // Add new list subscriptions (skip duplicates)
  const existingValues = new Set(savedFeeds.items.map((item) => item.value))
  let subscribedCount = 0

  for (const listUri of listUris) {
    if (!existingValues.has(listUri)) {
      savedFeeds.items.push({
        id: `list-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
        type: 'list',
        value: listUri,
        pinned,
      })
      subscribedCount++
    }
  }

  // Update preferences if any lists were added
  if (subscribedCount > 0) {
    const updatedPrefs = [...currentPrefs]
    if (savedFeedsIndex >= 0) {
      updatedPrefs[savedFeedsIndex] = savedFeeds
    } else {
      updatedPrefs.push(savedFeeds)
    }

    await ctx.actorStore.transact(accountDid, async (actorTxn) => {
      await actorTxn.pref.putPreferences(updatedPrefs, 'app.bsky', {
        hasAccessFull: true,
      })
    })
  }

  return subscribedCount
}
