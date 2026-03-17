import { InvalidRequestError } from '@atproto/xrpc-server'
import { AppContext } from '../../../../context'
import { Server } from '../../../../lexicon'
import { validateAdminAuth } from './shared'

export default function (server: Server, ctx: AppContext) {
  server.io.trustanchor.admin.loadInventory({
    handler: async ({ req, input }) => {
      // Validate admin authentication
      validateAdminAuth(req, ctx)

      const { accounts, batchName } = input.body as {
        accounts: Array<{
          did: string
          onboardingUrl: string
          qrCodeUrl: string
          preferredHandle?: string
        }>
        batchName?: string
      }

      // Validate input
      if (!accounts || !Array.isArray(accounts)) {
        throw new InvalidRequestError('accounts must be an array')
      }

      if (accounts.length === 0) {
        throw new InvalidRequestError('accounts array cannot be empty')
      }

      if (accounts.length > 10000) {
        throw new InvalidRequestError(
          'Maximum 10,000 accounts per batch. Split into multiple requests.',
        )
      }

      // Validate each account
      for (let i = 0; i < accounts.length; i++) {
        const account = accounts[i]

        if (!account.did || typeof account.did !== 'string') {
          throw new InvalidRequestError(
            `Account at index ${i}: did is required and must be a string`,
          )
        }

        if (
          !account.onboardingUrl ||
          typeof account.onboardingUrl !== 'string'
        ) {
          throw new InvalidRequestError(
            `Account at index ${i}: onboardingUrl is required and must be a string`,
          )
        }

        if (!account.qrCodeUrl || typeof account.qrCodeUrl !== 'string') {
          throw new InvalidRequestError(
            `Account at index ${i}: qrCodeUrl is required and must be a string`,
          )
        }

        if (
          account.preferredHandle &&
          typeof account.preferredHandle !== 'string'
        ) {
          throw new InvalidRequestError(
            `Account at index ${i}: preferredHandle must be a string if provided`,
          )
        }
      }

      req.log.info(
        {
          accountCount: accounts.length,
          batchName: batchName || 'unnamed',
        },
        'Loading WID accounts into inventory',
      )

      // Load accounts
      const result = await ctx.widInventoryManager.loadAccounts(
        accounts,
        batchName,
      )

      req.log.info(
        {
          loaded: result.loaded,
          skipped: result.skipped,
          total: result.total,
        },
        'WID inventory load complete',
      )

      return {
        encoding: 'application/json',
        body: {
          loaded: result.loaded,
          skipped: result.skipped,
          total: result.total,
        },
      }
    },
  })
}
