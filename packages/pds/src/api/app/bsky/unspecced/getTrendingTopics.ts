/**
 * Override for getTrendingTopics.
 *
 * Pipethroughs anonymously to the upstream AppView. The previous
 * implementation read curated topics from a wadmin backend
 * (`<wadminUrl>/api/wsocial/trending-topics`), but in practice that endpoint
 * served a single stale entry ("Spain NATO (Archived)") which silently
 * replaced the live upstream trending list. Restoring upstream is the
 * primary fix for the "trending sidebar looks dead" bug.
 *
 * Anonymous pipethrough (no `iss` option) is required because Bluesky's
 * AppView returns a stale/empty personalized cohort when called
 * authenticated. Calling without service auth gives us the proper global
 * trending response.
 *
 * If/when W-curated trending is brought back, the right shape is to merge
 * wadmin entries on top of the upstream response rather than replace it —
 * otherwise an empty/broken wadmin response will resurrect this bug.
 */
import { AppContext } from '../../../../context'
import { Server } from '../../../../lexicon'
import { pipethrough } from '../../../../pipethrough'

export default function (server: Server, ctx: AppContext) {
  server.app.bsky.unspecced.getTrendingTopics({
    handler: async ({ req }) => {
      return pipethrough(ctx, req)
    },
  })
}
