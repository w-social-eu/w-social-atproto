import { Server } from '@atproto/xrpc-server'
import { AppContext } from '../../../../context'
import { app } from '../../../../lexicons/index.js'

export default function (server: Server, ctx: AppContext) {
  server.add(app.bsky.ageassurance.getConfig, {
    auth: ctx.authVerifier.standardOptional,
    handler: async () => {
      return {
        encoding: 'application/json',
        body: {
          // W Social: empty regions list — everyone gets full access (all
          // users treated as adults). Upstream Bluesky uses AGE_ASSURANCE_CONFIG.
          regions: [],
        },
      }
    },
  })
}
