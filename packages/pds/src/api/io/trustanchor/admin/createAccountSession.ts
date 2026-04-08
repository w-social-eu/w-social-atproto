import { InvalidRequestError } from '@atproto/xrpc-server'
import { AppContext } from '../../../../context'
import { Server } from '../../../../lexicon'
import { validateAdminAuth } from './shared'

export default function (server: Server, ctx: AppContext) {
  server.io.trustanchor.admin.createAccountSession({
    handler: async ({ input, req }) => {
      validateAdminAuth(req, ctx)

      const { did } = input.body

      if (!did || !did.startsWith('did:')) {
        throw new InvalidRequestError(
          'Invalid DID format. Must start with "did:"',
        )
      }

      const account = await ctx.accountManager.getAccount(did, {
        includeDeactivated: true,
        includeTakenDown: true,
      })
      if (!account) {
        throw new InvalidRequestError(`Account not found: ${did}`)
      }

      // Create a full-scope session (appPassword=null) without any password check.
      // This is admin-only — auth is validated above via validateAdminAuth.
      const { accessJwt, refreshJwt } = await ctx.accountManager.createSession(
        did,
        null,
      )

      req.log.info(
        { did, handle: account.handle },
        'Admin created legacy ATProto session for account',
      )

      return {
        encoding: 'application/json',
        body: {
          accessJwt,
          refreshJwt,
          handle: account.handle ?? '',
          did,
        },
      }
    },
  })
}
