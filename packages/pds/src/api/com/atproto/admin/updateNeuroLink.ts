import { InvalidRequestError } from '@atproto/xrpc-server'
import { AppContext } from '../../../../context'
import { Server } from '../../../../lexicon'

export default function (server: Server, ctx: AppContext) {
  server.com.atproto.admin.updateNeuroLink({
    auth: ctx.authVerifier.adminToken,
    handler: async ({ input, req }) => {
      const { did, newJid } = input.body

      // Check if account exists
      const account = await ctx.accountManager.db.db
        .selectFrom('account')
        .select(['did'])
        .where('did', '=', did)
        .executeTakeFirst()

      if (!account) {
        throw new InvalidRequestError('Account not found', 'NotFound')
      }

      // Check if the new JID is already linked to a different account
      const conflict = await ctx.accountManager.db.db
        .selectFrom('neuro_identity_link')
        .select(['did', 'jid'])
        .where('jid', '=', newJid)
        .executeTakeFirst()

      if (conflict && conflict.did !== did) {
        throw new InvalidRequestError(
          `This JID is already linked to account ${conflict.did}`,
          'JidInUse',
        )
      }

      // Get current oldest link for this DID
      const currentLinks = await ctx.accountManager.db.db
        .selectFrom('neuro_identity_link')
        .select(['jid'])
        .where('did', '=', did)
        .orderBy('linkedAt', 'asc')
        .execute()

      const oldJid = currentLinks[0]?.jid || null
      const updatedAt = new Date().toISOString()

      if (currentLinks.length > 0) {
        await ctx.accountManager.db.db
          .updateTable('neuro_identity_link')
          .set({ jid: newJid, lastLoginAt: null })
          .where('did', '=', did)
          .where('jid', '=', oldJid!)
          .execute()
      } else {
        await ctx.accountManager.db.db
          .insertInto('neuro_identity_link')
          .values({
            jid: newJid,
            did,
            linkedAt: updatedAt,
            lastLoginAt: null,
          })
          .execute()
      }

      req.log.info({ did, oldJid, newJid }, 'Updated Neuro identity link')

      return {
        encoding: 'application/json',
        body: {
          success: true,
          deprecated:
            'updateNeuroLink is deprecated. Use addNeuroLink/removeNeuroLink instead.',
          did,
          oldJid: oldJid || undefined,
          newJid,
          updatedAt,
        },
      }
    },
  })
}
