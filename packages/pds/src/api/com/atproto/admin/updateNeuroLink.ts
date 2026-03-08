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
      const existingLink = await ctx.accountManager.db.db
        .selectFrom('neuro_identity_link')
        .select(['did', 'userJid', 'testUserJid'])
        .where('userJid', '=', newJid)
        .where('isTestUser', '=', 0)
        .executeTakeFirst()

      if (existingLink && existingLink.did !== did) {
        throw new InvalidRequestError(
          `This JID is already linked to account ${existingLink.did}`,
          'JidInUse',
        )
      }

      // Get current link (if any)
      const currentLink = await ctx.accountManager.db.db
        .selectFrom('neuro_identity_link')
        .select(['userJid', 'testUserJid'])
        .where('did', '=', did)
        .executeTakeFirst()

      const oldJid = currentLink?.userJid || currentLink?.testUserJid || null
      const updatedAt = new Date().toISOString()

      // Update or insert the link
      if (currentLink) {
        // Update existing link
        await ctx.accountManager.db.db
          .updateTable('neuro_identity_link')
          .set({
            userJid: newJid,
            testUserJid: null,
            isTestUser: 0,
            linkedAt: updatedAt,
            lastLoginAt: null, // Reset last login
          })
          .where('did', '=', did)
          .execute()

        req.log.info({ did, oldJid, newJid }, 'Updated Neuro identity link')
      } else {
        // Create new link
        await ctx.accountManager.db.db
          .insertInto('neuro_identity_link')
          .values({
            userJid: newJid,
            testUserJid: null,
            did,
            isTestUser: 0,
            linkedAt: updatedAt,
            lastLoginAt: null,
          })
          .execute()

        req.log.info({ did, newJid }, 'Created Neuro identity link')
      }

      return {
        encoding: 'application/json',
        body: {
          success: true,
          did,
          oldJid: oldJid || undefined,
          newJid,
          updatedAt,
        },
      }
    },
  })
}
