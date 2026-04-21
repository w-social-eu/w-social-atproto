import { Server } from '@atproto/xrpc-server'
import { AppContext } from '../../../../context'
import { app } from '../../../../lexicons/index.js'
import { computeProxyTo } from '../../../../pipethrough'
import {
  mungeProfilesWithWSocial,
  pipethroughWithWSocialExtensions,
} from '../../../io/trustanchor/profile-pipethrough'

export default function (server: Server, ctx: AppContext) {
  if (!ctx.bskyAppView) return

  server.add(app.bsky.actor.getProfiles, {
    auth: ctx.authVerifier.authorization({
      authorize: (permissions, { req }) => {
        const lxm = app.bsky.actor.getProfiles.$lxm
        const aud = computeProxyTo(ctx, req, lxm)
        permissions.assertRpc({ aud, lxm })
      },
    }),
    opts: {
      // @TODO remove after grace period has passed, behavior is non-standard.
      // temporarily added for compat w/ previous version of xrpc-server to avoid breakage of a few specified parties.
      paramsParseLoose: true,
    },
    handler: async (reqCtx) => {
      // W Social: always buffer upstream's response and apply our trust-anchor
      // profile munger. Upstream's `pipethroughReadAfterWrite` only rewrites
      // the profile for the requesting user.
      return pipethroughWithWSocialExtensions(
        ctx,
        reqCtx,
        mungeProfilesWithWSocial(ctx),
      )
    },
  })
}
