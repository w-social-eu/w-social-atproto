import { AppContext } from '../../../../context'
import { Server } from '../../../../lexicon'
import { ids } from '../../../../lexicon/lexicons'
import { OutputSchema } from '../../../../lexicon/types/app/bsky/actor/getProfile'
import { computeProxyTo } from '../../../../pipethrough'
import {
  LocalRecords,
  LocalViewer,
  pipethroughReadAfterWrite,
} from '../../../../read-after-write'
import { addWSocialExtensions } from '../../../io/trustanchor/profile-extensions'

export default function (server: Server, ctx: AppContext) {
  if (!ctx.bskyAppView) return

  server.app.bsky.actor.getProfile({
    auth: ctx.authVerifier.authorization({
      authorize: (permissions, { req }) => {
        const lxm = ids.AppBskyActorGetProfile
        const aud = computeProxyTo(ctx, req, lxm)
        permissions.assertRpc({ aud, lxm })
      },
    }),
    handler: async (reqCtx) => {
      return pipethroughReadAfterWrite(ctx, reqCtx, getProfileMunge(ctx))
    },
  })
}

const getProfileMunge =
  (ctx: AppContext) =>
  async (
    localViewer: LocalViewer,
    original: OutputSchema,
    local: LocalRecords,
    requester: string,
  ): Promise<OutputSchema> => {
    // Apply read-after-write updates if viewing own profile
    let profile = original
    if (local.profile && original.did === requester) {
      profile = localViewer.updateProfileDetailed(
        original,
        local.profile.record,
      )
    }

    // Add W Social extensions to any profile (local accounts only)
    return addWSocialExtensions(ctx, profile)
  }
