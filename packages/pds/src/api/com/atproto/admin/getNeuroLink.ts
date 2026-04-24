import { InvalidRequestError } from '@atproto/xrpc-server'
import { AppContext } from '../../../../context'
import { Server } from '../../../../lexicon'

export default function (server: Server, ctx: AppContext) {
  server.com.atproto.admin.getNeuroLink({
    auth: ctx.authVerifier.adminToken,
    handler: async ({ params }) => {
      const { did } = params

      const [account, actor, neuroLinks] = await Promise.all([
        ctx.accountManager.getAccount(did),
        ctx.accountManager.db.db
          .selectFrom('actor')
          .select(['accountType'])
          .where('did', '=', did)
          .executeTakeFirst(),
        ctx.accountManager.db.db
          .selectFrom('neuro_identity_link')
          .selectAll()
          .where('did', '=', did)
          .orderBy('linkedAt', 'asc')
          .execute(),
      ])

      if (!account) {
        throw new InvalidRequestError('Account not found', 'NotFound')
      }

      const primary = neuroLinks[0]

      return {
        encoding: 'application/json',
        body: {
          did: account.did,
          handle: account.handle || '',
          email: account.email || undefined,
          accountType: actor?.accountType || 'organization',
          jid: primary?.jid || undefined,
          linkedAt: primary?.linkedAt || undefined,
          lastLoginAt: primary?.lastLoginAt || undefined,
          neuroLinks: neuroLinks.map((l) => ({
            jid: l.jid,
            linkedAt: l.linkedAt || undefined,
            lastLoginAt: l.lastLoginAt || undefined,
          })),
        },
      }
    },
  })
}
