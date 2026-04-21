import { Server } from '@atproto/xrpc-server'
import { AppContext } from '../../../../context'
import { app } from '../../../../lexicons/index.js'
import { computeProxyTo } from '../../../../pipethrough'
import {
  mungeProfileWithWSocial,
  pipethroughWithWSocialExtensions,
} from '../../../io/trustanchor/profile-pipethrough'

export default function (server: Server, ctx: AppContext) {
  if (!ctx.bskyAppView) return

  server.add(app.bsky.actor.getProfile, {
    auth: ctx.authVerifier.authorization({
      authorize: (permissions, { req }) => {
        const lxm = app.bsky.actor.getProfile.$lxm
        const aud = computeProxyTo(ctx, req, lxm)
        permissions.assertRpc({ aud, lxm })
      },
    }),
    handler: async (reqCtx) => {
      // W Social: always buffer the upstream AppView response and munge in
      // our trust-anchor/profile extensions. Upstream uses the lighter
      // `pipethroughReadAfterWrite` which only rewrites the profile for the
      // requesting user — we need our munger to run on every response.
      return pipethroughWithWSocialExtensions(
        ctx,
        reqCtx,
        mungeProfileWithWSocial(ctx),
      )
    },
  })
}
