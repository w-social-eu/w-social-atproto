import { Server } from '../../../../lexicon'
import { AppContext } from '../../../../context'
import { validateAdminAuth } from './shared'

export default function (server: Server, ctx: AppContext) {
  server.io.trustanchor.admin.getInventoryStatus({
    handler: async ({ req }) => {
      // Validate admin authentication
      validateAdminAuth(req, ctx)

      // Get inventory statistics
      const status = await ctx.widInventoryManager.getInventoryStatus()

      return {
        encoding: 'application/json',
        body: {
          available: status.available,
          allocated: status.allocated,
          consumed: status.consumed,
          total: status.total,
        },
      }
    },
  })
}
