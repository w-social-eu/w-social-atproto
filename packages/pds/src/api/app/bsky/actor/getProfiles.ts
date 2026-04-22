import { AppContext } from '../../../../context'
import { Server } from '../../../../lexicon'
import { ids } from '../../../../lexicon/lexicons'
import { computeProxyTo } from '../../../../pipethrough'
import {
  mungeProfilesWithWSocial,
  pipethroughWithWSocialExtensions,
} from '../../../io/trustanchor/profile-pipethrough'

export default function (server: Server, ctx: AppContext) {
  if (!ctx.bskyAppView) return

  server.app.bsky.actor.getProfiles({
    auth: ctx.authVerifier.authorization({
      authorize: (permissions, { req }) => {
        const lxm = ids.AppBskyActorGetProfiles
        const aud = computeProxyTo(ctx, req, lxm)
        permissions.assertRpc({ aud, lxm })
      },
    }),
    handler: async (reqCtx) => {
      return pipethroughWithWSocialExtensions(
        ctx,
        reqCtx,
        mungeProfilesWithWSocial(ctx),
      )
    },
  })
}
