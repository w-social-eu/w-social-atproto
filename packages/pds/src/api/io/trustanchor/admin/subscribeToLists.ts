import { InvalidRequestError } from '@atproto/xrpc-server'
import { AppContext } from '../../../../context'
import { Server } from '../../../../lexicon'
import { subscribeToLists } from '../../../../services/list-subscription'
import { validateAdminAuth } from './shared'

export default function (server: Server, ctx: AppContext) {
  server.io.trustanchor.admin.subscribeToLists({
    handler: async ({ input, req }) => {
      validateAdminAuth(req, ctx)
      const { did, lists } = input.body

      req.log.info(
        { did, listCount: lists.length },
        'Subscribing account to lists',
      )

      // Verify account exists
      const account = await ctx.accountManager.getAccount(did, {
        includeDeactivated: false,
      })

      if (!account) {
        throw new InvalidRequestError(`Account ${did} not found`)
      }

      // Subscribe to lists
      const subscribedCount = await subscribeToLists(ctx, did, lists)

      req.log.info({ did, subscribedCount }, 'Account subscribed to lists')

      return {
        encoding: 'application/json',
        body: {
          success: true,
          subscribedCount,
        },
      }
    },
  })
}
