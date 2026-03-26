import { InvalidRequestError } from '@atproto/xrpc-server'
import { AppContext } from '../../../../context'
import { Server } from '../../../../lexicon'
import { setThreadViewPreferences } from '../../../../services/thread-preferences'
import { validateAdminAuth } from './shared'

export default function (server: Server, ctx: AppContext) {
  server.io.trustanchor.admin.setThreadViewPreferences({
    handler: async ({ input, req }) => {
      validateAdminAuth(req, ctx)
      const { did, treeViewEnabled, sort } = input.body

      req.log.info(
        { did, treeViewEnabled, sort },
        'Setting thread view preferences for account',
      )

      // Validate sort value
      const validSorts = ['oldest', 'newest', 'most-likes', 'random', 'hotness']
      if (!validSorts.includes(sort)) {
        throw new InvalidRequestError(
          `Invalid sort value: "${sort}". Must be one of: ${validSorts.join(', ')}`,
          'InvalidSort',
        )
      }

      // Verify account exists
      const account = await ctx.accountManager.getAccount(did, {
        includeDeactivated: false,
      })

      if (!account) {
        throw new InvalidRequestError(
          `Account ${did} not found`,
          'AccountNotFound',
        )
      }

      // Set thread view preferences
      await setThreadViewPreferences(ctx, did, {
        treeViewEnabled,
        sort,
      })

      req.log.info(
        { did, treeViewEnabled, sort },
        'Thread view preferences set for account',
      )

      return {
        encoding: 'application/json',
        body: {
          success: true,
        },
      }
    },
  })
}
