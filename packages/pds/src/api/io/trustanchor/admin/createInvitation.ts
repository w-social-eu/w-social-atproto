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
  logger: { info: (data: unknown, msg: string) => void },
  email: string,
  onboardingUrl: string,
  qrCodeUrl: string,
  preferredHandle?: string | null,
): Promise<void> {
  // TODO: Implement Brevo API call with invitation template
  // Template should receive:
  // - ONBOARDING_URL: onboardingUrl
  // - QR_CODE_IMAGE: qrCodeUrl (hosted image URL)
  // - INLINE_QR_CODE: base64-encoded data URI (fetch and encode qrCodeUrl)
  // - PREFERRED_HANDLE: preferredHandle (optional)

  // For now, just log that email would be sent
  logger.info(
    {
      email: email.substring(0, 3) + '***', // Privacy: log prefix only
      hasHandle: !!preferredHandle,
      onboardingUrl: onboardingUrl.substring(0, 20) + '...',
      qrCodeUrl: qrCodeUrl.substring(0, 30) + '...',
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

          invitation = await ctx.accountManager.db.db
            .selectFrom('pending_invitations')
            .selectAll()
            .where('id', '=', existingInvitation.id)
            .executeTakeFirst()

          // Email sending handled by CLI (pds-wadmin), not by PDS
        } else {
          // Step 2: No reusable invitation - allocate account from WID inventory
          req.log.info('Allocating WID account from inventory')

          let jid: string
          let onboardingUrl: string
          let qrCodeUrl: string

          try {
            const inventoryAccount =
              await ctx.widInventoryManager.allocateAccount(normalizedEmail)

            if (!inventoryAccount) {
              throw new Error('No WID accounts available in inventory')
            }

            // Use the DID from inventory as the JID
            jid = inventoryAccount.did
            onboardingUrl = inventoryAccount.onboarding_url
            qrCodeUrl = inventoryAccount.qr_code_url || ''

            req.log.info(
              {
                jid: jid.substring(0, 8) + '...',
                allocated_to: normalizedEmail.substring(0, 3) + '***',
              },
              'WID account allocated from inventory',
            )
          } catch (inventoryErr) {
            const errorMsg =
              inventoryErr instanceof Error
                ? inventoryErr.message
                : String(inventoryErr)
            req.log.error(
              { error: errorMsg },
              'WID inventory allocation failed',
            )
            throw new InvalidRequestError(
              errorMsg.includes('No WID accounts available')
                ? 'No WID accounts available in inventory. Load more accounts to continue.'
                : 'Failed to allocate WID account from inventory',
              'InventoryAllocationError',
            )
          }

          // Step 3: Persist invitation with JID (only after successful inventory allocation)
          invitation = await ctx.invitationManager.createInvitationWithJid(
            normalizedEmail,
            jid,
            onboardingUrl,
            preferredHandle,
            invitationTimestamp,
          )

          // Email sending handled by CLI (pds-wadmin), not by PDS
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
          onboardingUrl: invitation.onboarding_url ?? undefined,
          qrCodeUrl: invitation.jid
            ? (await ctx.widInventoryManager.getAccountByDid(invitation.jid))
                ?.qr_code_url ?? undefined
            : undefined,
          expiresAt: invitation.expires_at,
          emailStatus: invitation.status,
          // JID is not returned for privacy (admin doesn't need it)
        },
      }
    },
  })
}
