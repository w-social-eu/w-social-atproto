/**
 * Override for getTrendingTopics.
 *
 * Strategy:
 *   1. Try the W-curated source (wadmin) first.
 *   2. If wadmin returns no topics AND no suggested feeds, fall through to
 *      the upstream AppView via pipethrough WITHOUT service auth — Bluesky's
 *      AppView ignores the live trending list when the request carries an
 *      authenticated session (it returns a stale/empty personalized cohort
 *      instead). Calling anonymously gives us the proper global trending
 *      response.
 *
 * Failure modes (missing wadmin URL, non-2xx, network error, malformed body)
 * all silently fall through to the upstream so the endpoint never returns
 * empty when the upstream has data.
 */
import { AppContext } from '../../../../context'
import { Server } from '../../../../lexicon'
import type { TrendingTopic } from '../../../../lexicon/types/app/bsky/unspecced/defs'
import { pipethrough } from '../../../../pipethrough'

export default function (server: Server, ctx: AppContext) {
  server.app.bsky.unspecced.getTrendingTopics({
    handler: async ({ req }) => {
      const wadminUrl = ctx.cfg.wadmin.url
      if (wadminUrl) {
        try {
          const res = await fetch(`${wadminUrl}/api/wsocial/trending-topics`)
          if (res.ok) {
            const data = (await res.json()) as {
              topics?: TrendingTopic[]
              suggested?: TrendingTopic[]
            }
            const topics = Array.isArray(data.topics) ? data.topics : []
            const suggested = Array.isArray(data.suggested)
              ? data.suggested
              : []
            // Only short-circuit when wadmin actually has curated content.
            // Otherwise fall through to upstream so the user sees something.
            if (topics.length > 0 || suggested.length > 0) {
              return {
                encoding: 'application/json' as const,
                body: { topics, suggested },
              }
            }
          }
        } catch {
          // fall through to upstream pipethrough below
        }
      }

      // Anonymous pipethrough — no `iss` means no service-auth header is
      // attached, which is required to get the live trending response.
      return pipethrough(ctx, req)
    },
  })
}
