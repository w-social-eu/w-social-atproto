import { AppContext } from '../../../../context'
import { Server } from '../../../../lexicon'
import { ids } from '../../../../lexicon/lexicons'
import { OutputSchema } from '../../../../lexicon/types/app/bsky/actor/getProfiles'
import { computeProxyTo } from '../../../../pipethrough'
import {
  LocalRecords,
  LocalViewer,
  pipethroughReadAfterWrite,
} from '../../../../read-after-write'
import { addWSocialExtensions } from '../../../io/trustanchor/profile-extensions'

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
      return pipethroughReadAfterWrite(ctx, reqCtx, getProfilesMunge(ctx))
    },
  })
}

const getProfilesMunge =
  (ctx: AppContext) =>
  async (
    localViewer: LocalViewer,
    original: OutputSchema,
    local: LocalRecords,
    requester: string,
  ): Promise<OutputSchema> => {
    const localProf = local.profile

    // Process all profiles: apply read-after-write + W Social extensions
    const profiles = await Promise.all(
      original.profiles.map(async (prof) => {
        // Apply read-after-write updates if viewing own profile
        let profile = prof
        if (localProf && prof.did === requester) {
          profile = localViewer.updateProfileDetailed(prof, localProf.record)
        }

        // Add W Social extensions to any profile (local accounts only)
        return addWSocialExtensions(ctx, profile)
      }),
    )

    return {
      ...original,
      profiles,
    }
  }
