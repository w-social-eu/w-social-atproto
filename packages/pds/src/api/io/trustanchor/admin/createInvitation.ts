import { InvalidRequestError } from '@atproto/xrpc-server'
import { AppContext } from '../../../../context'
import { Server } from '../../../../lexicon'
import { validateAdminAuth } from './shared'

/**
 * Call Neuro to create empty WID account
 * Returns JID and onboarding URL/QR
 * TODO: Finalize Neuro API contract (endpoint, request/response format)
 */
async function allocateNeuroAccount(
  ctx: AppContext,
): Promise<{ jid: string; onboardingUrl: string }> {
  // TODO: Replace with actual Neuro endpoint once contract is finalized
  if (!ctx.cfg.quicklogin?.apiBaseUrl) {
    throw new Error(
      'Neuro API base URL not configured (PDS_NEURO_API_BASE_URL required)',
    )
  }

  const neuroUrl = new URL(
    '/api/create-empty-account', // Placeholder endpoint
    ctx.cfg.quicklogin.apiBaseUrl,
  ).toString()

  try {
    const response = await ctx.safeFetch.call(undefined, neuroUrl, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        // TODO: Add required parameters once contract is known
        purpose: 'invitation',
      }),
    })

    if (!response.ok) {
      const body = await response.text()
      throw new Error(
        `Neuro account creation failed: ${response.status} ${body}`,
      )
    }

    const data = (await response.json()) as {
      jid?: string
      onboardingUrl?: string
      qrCodeUrl?: string
    }

    // TODO: Adjust field names based on actual Neuro response format
    if (!data.jid || (!data.onboardingUrl && !data.qrCodeUrl)) {
      throw new Error('Invalid Neuro response: missing jid or onboarding URL')
    }

    return {
      jid: data.jid,
      onboardingUrl: data.onboardingUrl || data.qrCodeUrl || '',
    }
  } catch (err) {
    throw new Error(
      `Neuro account allocation failed: ${err instanceof Error ? err.message : String(err)}`,
    )
  }
}

/**
 * Send invitation email via Brevo
 * TODO: Implement Brevo integration with template
 */
async function sendInvitationEmail(
  ctx: AppContext,
  email: string,
  onboardingUrl: string,
  preferredHandle?: string | null,
): Promise<void> {
  // TODO: Implement Brevo API call with invitation template
  // For now, just log that email would be sent
  ctx.logger.info(
    {
      email: email.substring(0, 3) + '***', // Privacy: log prefix only
      hasHandle: !!preferredHandle,
      onboardingUrl: onboardingUrl.substring(0, 20) + '...',
    },
    'TODO: Send invitation email via Brevo',
  )

  // Placeholder - in production this would call Brevo API
  // throw new Error('Brevo integration not yet implemented')
}

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

      const normalizedEmail = email.trim().toLowerCase()
      let invitation

      try {
        // Step 1: Check for existing active invitation by email hash
        const emailHash = ctx.invitationManager.hashEmail(normalizedEmail)
        const existingInvitation =
          await ctx.invitationManager.getActiveInvitationByEmailHash(emailHash)

        if (existingInvitation && existingInvitation.jid) {
          // Reuse existing JID/onboarding URL for reminder send
          req.log.info(
            {
              invitationId: existingInvitation.id,
              hasJid: true,
            },
            'Reusing existing invitation for reminder',
          )

          // Update preferred handle if provided
          if (preferredHandle !== undefined) {
            await ctx.invitationManager.updateInvitationForReminder(
              existingInvitation.id,
              preferredHandle,
            )
          } else {
            await ctx.invitationManager.updateInvitationForReminder(
              existingInvitation.id,
            )
          }

          invitation = await ctx.db.db
            .selectFrom('pending_invitations')
            .selectAll()
            .where('id', '=', existingInvitation.id)
            .executeTakeFirst()

          // Send reminder email (idempotent - always sends per policy)
          if (invitation && invitation.onboarding_url) {
            try {
              await sendInvitationEmail(
                ctx,
                normalizedEmail,
                invitation.onboarding_url,
                invitation.preferred_handle,
              )
              await ctx.invitationManager.updateEmailDeliveryStatus(
                invitation.id,
                'email_sent',
              )
            } catch (emailErr) {
              const errorMsg =
                emailErr instanceof Error ? emailErr.message : String(emailErr)
              await ctx.invitationManager.updateEmailDeliveryStatus(
                invitation.id,
                'email_failed',
                errorMsg,
              )
              throw new InvalidRequestError(
                'Invitation reminder email failed',
                'EmailDeliveryError',
              )
            }
          }
        } else {
          // Step 2: No reusable invitation - allocate new JID from Neuro
          req.log.info('Allocating new JID from Neuro')

          let jid: string
          let onboardingUrl: string

          try {
            const neuroAccount = await allocateNeuroAccount(ctx)
            jid = neuroAccount.jid
            onboardingUrl = neuroAccount.onboardingUrl
          } catch (neuroErr) {
            const errorMsg =
              neuroErr instanceof Error ? neuroErr.message : String(neuroErr)
            req.log.error({ error: errorMsg }, 'Neuro account allocation failed')
            throw new InvalidRequestError(
              'Failed to allocate WID account',
              'NeuroAllocationError',
            )
          }

          // Step 3: Persist invitation with JID (only after successful Neuro allocation)
          invitation = await ctx.invitationManager.createInvitationWithJid(
            normalizedEmail,
            jid,
            onboardingUrl,
            preferredHandle,
            invitationTimestamp,
          )

          // Step 4: Send initial invitation email
          try {
            await sendInvitationEmail(
              ctx,
              normalizedEmail,
              onboardingUrl,
              preferredHandle,
            )
            await ctx.invitationManager.updateEmailDeliveryStatus(
              invitation.id,
              'email_sent',
            )
          } catch (emailErr) {
            const errorMsg =
              emailErr instanceof Error ? emailErr.message : String(emailErr)
            await ctx.invitationManager.updateEmailDeliveryStatus(
              invitation.id,
              'email_failed',
              errorMsg,
            )
            throw new InvalidRequestError(
              'Invitation email failed',
              'EmailDeliveryError',
            )
          }
        }
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err)
        if (message.includes('PDS_INVITATION_EMAIL_HASH_SALT')) {
          throw new InvalidRequestError(message, 'InvitationConfigError')
        }
        if (err instanceof InvalidRequestError) {
          throw err
        }
        req.log.error({ error: message }, 'Invitation creation failed')
        throw new InvalidRequestError('Invitation creation failed')
      }

      if (!invitation) {
        throw new InvalidRequestError('Failed to create or update invitation')
      }

      return {
        encoding: 'application/json',
        body: {
          success: true,
          email: invitation.email,
          preferredHandle: invitation.preferred_handle ?? undefined,
          expiresAt: invitation.expires_at,
          emailStatus: invitation.status,
          // JID is not returned for privacy (admin doesn't need it)
        },
      }
    },
  })
}
