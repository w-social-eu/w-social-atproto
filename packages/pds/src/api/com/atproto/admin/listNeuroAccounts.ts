import { AppContext } from '../../../../context'
import { Server } from '../../../../lexicon'

export default function (server: Server, ctx: AppContext) {
  server.com.atproto.admin.listNeuroAccounts({
    auth: ctx.authVerifier.adminToken,
    handler: async ({ params }) => {
      const { limit = 100, cursor } = params

      let query = ctx.accountManager.db.db
        .selectFrom('actor')
        .leftJoin('account', 'actor.did', 'account.did')
        .select([
          'actor.did as did',
          'actor.handle as handle',
          'actor.accountType as accountType',
          'account.email as email',
        ])
        .where('actor.deactivatedAt', 'is', null)
        .where((qb) =>
          qb
            .where('actor.takedownRef', 'is', null)
            .orWhere('actor.takedownRef', '=', ''),
        )

      if (cursor) {
        query = query.where('actor.handle', '>', cursor)
      }

      const accounts = await query
        .orderBy('actor.handle', 'asc')
        .limit(limit + 1)
        .execute()

      const dids = accounts.map((acc) => acc.did)
      const allNeuroLinks = dids.length
        ? await ctx.accountManager.db.db
            .selectFrom('neuro_identity_link')
            .select(['jid', 'did', 'linkedAt', 'lastLoginAt'])
            .where('did', 'in', dids)
            .orderBy('lastLoginAt', 'desc')
            .execute()
        : []

      // Group all rows by DID
      const neuroLinksByDid = new Map<string, typeof allNeuroLinks>()
      for (const link of allNeuroLinks) {
        const existing = neuroLinksByDid.get(link.did) ?? []
        existing.push(link)
        neuroLinksByDid.set(link.did, existing)
      }

      // Paginate
      const hasMore = accounts.length > limit
      const accountsToReturn = hasMore ? accounts.slice(0, limit) : accounts
      const nextCursor = hasMore
        ? accountsToReturn[accountsToReturn.length - 1].handle
        : undefined

      return {
        encoding: 'application/json',
        body: {
          accounts: accountsToReturn.map((account) => {
            const links = neuroLinksByDid.get(account.did) ?? []
            const primary = links[0] // most recently used
            return {
              did: account.did,
              handle: account.handle || '',
              email: account.email || undefined,
              accountType: account.accountType,
              jid: primary?.jid || undefined,
              linkedAt: primary?.linkedAt || undefined,
              lastLoginAt: primary?.lastLoginAt || undefined,
              neuroLinks: links.map((l) => ({
                jid: l.jid,
                linkedAt: l.linkedAt || undefined,
                lastLoginAt: l.lastLoginAt || undefined,
              })),
            }
          }),
          cursor: nextCursor || undefined,
        },
      }
    },
  })
}
