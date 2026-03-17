import { InvalidRequestError } from '@atproto/xrpc-server'
import { AppContext } from '../../../../context'
import { Server } from '../../../../lexicon'
import { validateAdminAuth } from './shared'

export default function (server: Server, ctx: AppContext) {
  server.io.trustanchor.admin.updateInvitationEmailStatus({
    handler: async ({ req, input }) => {
      validateAdminAuth(req, ctx)

      const { email, status, error, messageId } = input.body as {
        email?: string
        status?: 'email_sent' | 'email_failed'
        error?: string
        messageId?: string
      }

      if (!email || !email.trim()) {
        throw new InvalidRequestError('email is required')
      }

      if (!status || !['email_sent', 'email_failed'].includes(status)) {
        throw new InvalidRequestError(
          'status must be either email_sent or email_failed',
        )
      }

      const normalizedEmail = email.trim().toLowerCase()

      // Get invitation by email hash
      const emailHash = ctx.invitationManager.hashEmail(normalizedEmail)
      const invitation =
        await ctx.invitationManager.getActiveInvitationByEmailHash(emailHash)

      if (!invitation) {
        throw new InvalidRequestError(
          `No active invitation found for email: ${normalizedEmail}`,
          'InvitationNotFound',
        )
      }

      // Update email delivery status
      await ctx.invitationManager.updateEmailDeliveryStatus(
        invitation.id,
        status,
        error,
        messageId,
      )

      return {
        encoding: 'application/json',
        body: {
          success: true,
          invitationId: invitation.id,
        },
      }
    },
  })
}
