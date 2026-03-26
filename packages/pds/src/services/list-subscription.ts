import { AtUri } from '@atproto/syntax'
import { AppContext } from '../context'
import { prepareCreate } from '../repo/prepare'

/**
 * Subscribe an account to one or more lists by creating listitem records in their repo.
 *
 * This is used for:
 * - Auto-subscribing human/test accounts to default lists on creation
 * - Admin command to subscribe existing accounts to lists
 *
 * @param ctx - Application context
 * @param accountDid - DID of the account to subscribe
 * @param listUris - Array of AT-URIs for lists to subscribe to
 * @returns Number of lists successfully subscribed to
 */
export async function subscribeToLists(
  ctx: AppContext,
  accountDid: string,
  listUris: string[],
): Promise<number> {
  if (listUris.length === 0) {
    return 0
  }

  // Validate all list URIs before creating any records
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

  let subscribedCount = 0

  // Create listitem records for each list
  for (const listUri of listUris) {
    try {
      const listItemRecord = {
        $type: 'app.bsky.graph.listitem',
        subject: accountDid,
        list: listUri,
        createdAt: new Date().toISOString(),
      }

      // Prepare the write
      const write = await prepareCreate({
        did: accountDid,
        collection: 'app.bsky.graph.listitem',
        record: listItemRecord,
      })

      // Create the listitem record in the account's repo
      await ctx.actorStore.transact(accountDid, async (actorTxn) => {
        const commit = await actorTxn.repo.processWrites([write])
        await ctx.sequencer.sequenceCommit(accountDid, commit)
        return commit
      })

      subscribedCount++
    } catch (err) {
      // Continue with other lists even if one fails
      // Caller is responsible for logging errors
      continue
    }
  }

  return subscribedCount
}
