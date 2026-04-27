import { InvalidRequestError } from '@atproto/xrpc-server'
import { AppContext } from '../../../../context'
import { Server } from '../../../../lexicon'

export default function (server: Server, ctx: AppContext) {
  server.com.atproto.admin.addNeuroLink({
    auth: ctx.authVerifier.adminToken,
    handler: async ({ input, req }) => {
      const { jid, did } = input.body

      // Check account exists
      const account = await ctx.accountManager.db.db
        .selectFrom('account')
        .select(['did'])
        .where('did', '=', did)
        .executeTakeFirst()

      if (!account) {
        throw new InvalidRequestError('Account not found', 'NotFound')
      }

      // Check (jid, did) pair not already linked (many-to-many: same JID → multiple accounts is allowed)
      const conflict = await ctx.accountManager.db.db
        .selectFrom('neuro_identity_link')
        .select(['did'])
        .where('jid', '=', jid)
        .where('did', '=', did)
        .executeTakeFirst()

      if (conflict) {
        throw new InvalidRequestError(
          'This JID is already linked to this account',
          'JidInUse',
        )
      }

      const linkedAt = new Date().toISOString()

      await ctx.accountManager.db.db
        .insertInto('neuro_identity_link')
        .values({ jid, did, linkedAt, lastLoginAt: null })
        .execute()

      req.log.info({ did, jid }, 'Added Neuro identity link')

      return {
        encoding: 'application/json',
        body: {
          success: true,
          jid,
          did,
          linkedAt,
        },
      }
    },
  })
}
