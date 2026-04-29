/**
 * Override for getPopularFeedGenerators.
 *
 * Pipethroughs anonymously to the upstream AppView. The previous
 * implementation read a curated list from a wadmin backend
 * (`<wadminUrl>/api/wsocial/feeds`) but in practice that endpoint served a
 * fixed 3-feed list which silently replaced the live upstream response and
 * — critically — ignored the `query` parameter, breaking feed search.
 * Restoring upstream is the fix for the "feed search returns the same 3
 * feeds for any query" bug.
 *
 * Anonymous pipethrough (no `iss` option) is required because Bluesky's
 * AppView returns the caller's saved feeds and ignores `query` when called
 * authenticated. Calling without service auth gives us the proper search
 * behaviour.
 *
 * If/when W-curated popular feeds are brought back, the right shape is to
 * merge wadmin entries on top of the upstream response (and to bypass
 * wadmin entirely whenever `params.query` is set, since wadmin can't
 * search).
 */
import { AppContext } from '../../../../context'
import { Server } from '../../../../lexicon'
import { pipethrough } from '../../../../pipethrough'

export default function (server: Server, ctx: AppContext) {
  server.app.bsky.unspecced.getPopularFeedGenerators({
    handler: async ({ req }) => {
      return pipethrough(ctx, req)
    },
  })
}
