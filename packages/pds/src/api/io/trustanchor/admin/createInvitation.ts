import { InvalidRequestError } from '@atproto/xrpc-server'
import { AppContext } from '../../../../context'
import { Server } from '../../../../lexicon'
import { validateAdminAuth } from './shared'

export default function (server: Server, ctx: AppContext) {
  server.io.trustanchor.admin.createInvitation({
    handler: async ({ req, input }) => {
      validateAdminAuth(req, ctx)

      const { email, preferredHandle, invitationTimestamp } = input.body as {
        email?: string
        preferredHandle?: string | null
        invitationTimestamp?: number
      }

      if (!email || !email.trim()) {
        throw new InvalidRequestError('email is required')
      }

      if (!Number.isInteger(invitationTimestamp)) {
        throw new InvalidRequestError('invitationTimestamp is required')
      }

      try {
        await ctx.invitationManager.createInvitation(
          email,
          preferredHandle,
          invitationTimestamp,
        )
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err)
        if (message.includes('PDS_INVITATION_EMAIL_HASH_SALT')) {
          throw new InvalidRequestError(message, 'InvitationConfigError')
        }
        throw err
      }

      const invitation = await ctx.invitationManager.getInvitationByEmail(email)

      return {
        encoding: 'application/json',
        body: {
          success: true,
          email: invitation?.email ?? email.trim().toLowerCase(),
          preferredHandle: invitation?.preferred_handle ?? null,
          expiresAt: invitation?.expires_at,
        },
      }
    },
  })
}
