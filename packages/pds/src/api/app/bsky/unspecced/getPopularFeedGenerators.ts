/**
 * Override for getPopularFeedGenerators.
 *
 * Strategy:
 *   1. If the caller provided a `query` parameter (feed search), always
 *      pipethrough to the upstream AppView — wadmin doesn't index feeds
 *      for search.
 *   2. Otherwise, try the W-curated source (wadmin) first.
 *   3. If wadmin returns no feeds, fall through to the upstream AppView
 *      via pipethrough WITHOUT service auth. Bluesky's AppView returns the
 *      caller's saved feeds (and ignores the `query` parameter) when the
 *      request is authenticated; calling anonymously gives us the proper
 *      popular-feeds response.
 *
 * Failure modes (missing wadmin URL, non-2xx, network error, malformed body)
 * all silently fall through to upstream.
 */
import { AppContext } from '../../../../context'
import { Server } from '../../../../lexicon'
import type { GeneratorView } from '../../../../lexicon/types/app/bsky/feed/defs'
import { pipethrough } from '../../../../pipethrough'

export default function (server: Server, ctx: AppContext) {
  server.app.bsky.unspecced.getPopularFeedGenerators({
    handler: async ({ params, req }) => {
      // Search queries always go straight to upstream — wadmin can't filter
      // by query string.
      if (params.query && params.query.length > 0) {
        return pipethrough(ctx, req)
      }

      const wadminUrl = ctx.cfg.wadmin.url
      if (wadminUrl) {
        try {
          const res = await fetch(`${wadminUrl}/api/wsocial/feeds`)
          if (res.ok) {
            const data = (await res.json()) as { feeds?: GeneratorView[] }
            const feeds = Array.isArray(data.feeds) ? data.feeds : []
            if (feeds.length > 0) {
              return {
                encoding: 'application/json' as const,
                body: { feeds },
              }
            }
          }
        } catch {
          // fall through to upstream pipethrough below
        }
      }

      // Anonymous pipethrough — no `iss` means no service-auth header.
      return pipethrough(ctx, req)
    },
  })
}
