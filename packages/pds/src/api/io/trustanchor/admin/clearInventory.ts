import { InvalidRequestError } from '@atproto/xrpc-server'
import { AppContext } from '../../../../context'
import { Server } from '../../../../lexicon'
import { validateAdminAuth } from './shared'

export default function (server: Server, ctx: AppContext) {
  server.io.trustanchor.admin.clearInventory({
    handler: async ({ req, input }) => {
      // Validate admin authentication
      validateAdminAuth(req, ctx)

      const { olderThanDays } = (input?.body as { olderThanDays?: number }) || {}

      // Validate olderThanDays if provided
      if (
        olderThanDays !== undefined &&
        (!Number.isInteger(olderThanDays) || olderThanDays < 0)
      ) {
        throw new InvalidRequestError(
          'olderThanDays must be a non-negative integer',
        )
      }

      req.log.info(
        { olderThanDays: olderThanDays ?? 'all' },
        'Clearing available WID accounts from inventory',
      )

      // Clear accounts
      const result = await ctx.widInventoryManager.clearAvailableAccounts(
        olderThanDays,
      )

      req.log.info(
        { deleted: result.deleted },
        'Cleared WID accounts from inventory',
      )

      return {
        encoding: 'application/json',
        body: {
          deleted: result.deleted,
        },
      }
    },
  })
}
