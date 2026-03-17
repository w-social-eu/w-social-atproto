import { AppContext } from '../../../../context'
import { Server } from '../../../../lexicon'

export default function (server: Server, ctx: AppContext) {
  server.app.bsky.ageassurance.getConfig({
    auth: ctx.authVerifier.standardOptional,
    handler: async () => {
      return {
        encoding: 'application/json',
        body: {
          // Empty regions list — everyone gets full access (all users treated as adults)
          regions: [],
        },
      }
    },
  })
}
