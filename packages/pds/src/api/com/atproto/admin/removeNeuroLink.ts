import { InvalidRequestError } from '@atproto/xrpc-server'
import { AppContext } from '../../../../context'
import { Server } from '../../../../lexicon'

export default function (server: Server, ctx: AppContext) {
  server.com.atproto.admin.removeNeuroLink({
    auth: ctx.authVerifier.adminToken,
    handler: async ({ input, req }) => {
      const { jid, did } = input.body

      // Verify the link exists
      const link = await ctx.accountManager.db.db
        .selectFrom('neuro_identity_link')
        .select(['jid', 'did'])
        .where('jid', '=', jid)
        .where('did', '=', did)
        .executeTakeFirst()

      if (!link) {
        throw new InvalidRequestError(
          'No link found for this JID/DID combination',
          'NotFound',
        )
      }

      // Check if this is the last link for this DID
      const remainingLinks = await ctx.accountManager.db.db
        .selectFrom('neuro_identity_link')
        .select(['jid'])
        .where('did', '=', did)
        .execute()

      const isLastLink = remainingLinks.length === 1

      await ctx.accountManager.db.db
        .deleteFrom('neuro_identity_link')
        .where('jid', '=', jid)
        .where('did', '=', did)
        .execute()

      // Revoke all active sessions for the unlinked account so the user
      // is forced to re-authenticate on next token refresh.
      await ctx.accountManager.revokeAllSessionsForDid(did)

      req.log.info({ did, jid, isLastLink }, 'Removed Neuro identity link')

      return {
        encoding: 'application/json',
        body: {
          success: true,
          jid,
          did,
          warning: isLastLink
            ? 'This was the last JID linked to this account. The account can no longer log in via QuickLogin.'
            : undefined,
        },
      }
    },
  })
}
