/**
 * Override for getPopularFeedGenerators.
 * Pulls hydrated GeneratorViews from the admin backend. On any failure
 * (missing URL, non-2xx, network error, malformed body) returns an empty
 * array so the endpoint never fails loudly.
 */
import { AppContext } from '../../../../context'
import { Server } from '../../../../lexicon'
import type { GeneratorView } from '../../../../lexicon/types/app/bsky/feed/defs'

export default function (server: Server, ctx: AppContext) {
  server.app.bsky.unspecced.getPopularFeedGenerators({
    handler: async () => {
      let feeds: GeneratorView[] = []
      const wadminUrl = ctx.cfg.wadmin.url
      if (wadminUrl) {
        try {
          const res = await fetch(`${wadminUrl}/api/wsocial/feeds`)
          if (res.ok) {
            const data = (await res.json()) as { feeds?: GeneratorView[] }
            if (Array.isArray(data.feeds)) feeds = data.feeds
          }
        } catch {
          // fall through to empty
        }
      }
      return {
        encoding: 'application/json' as const,
        body: { feeds },
      }
    },
  })
}
