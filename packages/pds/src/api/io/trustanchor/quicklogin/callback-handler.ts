import type { EmailTokenPurpose } from '../../../../account-manager/db'
import { AppContext } from '../../../../context'
import {
  NeuroCallbackPayload,
  createAccountViaQuickLogin,
  extractEmail,
  extractUserName,
  getHandleForDid,
} from './helpers'
import type { QuickLoginSession } from './store'

export interface CallbackResult {
  did: string
  handle: string
  accessJwt: string
  refreshJwt: string
  created: boolean
}

export interface Logger {
  info(obj: any, msg: string): void
  warn(obj: any, msg: string): void
  error(obj: any, msg: string): void
}

/**
 * Shared QuickLogin callback handler logic.
 * This is called by both the Express endpoint and XRPC endpoint.
 *
 * Account Creation Behavior:
 * - NEW ACCOUNT: Requires invitation if PDS_INVITE_REQUIRED=true
 *   - Checks invitation exists and is pending
 *   - Creates account with prefered_handle from invitation
 *   - Consumes invitation after successful account creation
 *
 * - EXISTING ACCOUNT (zombie account from W ID provision webhook):
 *   - Does NOT require invitation to be checked again
 *   - Links JID to existing account
 *   - Consumes invitation if one exists (allows admin-created invitations)
 *     This handles the recovery flow where admin creates invitation for zombie account
 *
 * Invitation Consumption:
 * - Invitation marked as consumed after first successful login
 * - Prevents double-use of invitations
 * - Maintains audit trail of who provisioned the account
 */
export async function handleQuickLoginCallback(
  payload: NeuroCallbackPayload,
  ctx: AppContext,
  log: Logger,
): Promise<CallbackResult | void> {
  log.info(
    {
      sessionId: payload.SessionId,
      key: payload.Key,
      state: payload.State,
    },
    'QuickLogin callback received',
  )

  // The provider sends back its own SessionId, but we need to look up by Key (serviceId)
  const serviceId = payload.Key
  if (!serviceId) {
    log.warn({ payload }, 'Missing Key/serviceId in callback')
    throw new Error('Missing Key')
  }

  // Find session by serviceId
  const session = ctx.quickloginStore.getSessionByServiceId(serviceId)
  if (!session) {
    log.warn({ serviceId }, 'Session not found for serviceId')
    throw new Error('Session not found')
  }

  // Check if session expired
  if (new Date() > new Date(session.expiresAt)) {
    log.warn({ sessionId: payload.SessionId }, 'Session expired')
    throw new Error('Session expired')
  }

  // Validate state (mTLS handles signature verification)
  if (payload.State !== 'Approved') {
    log.info(
      { sessionId: session.sessionId, state: payload.State },
      'QuickLogin not approved',
    )
    ctx.quickloginStore.updateSession(session.sessionId, {
      status: 'failed',
      error: `QuickLogin ${payload.State}`,
    })
    throw new Error(`QuickLogin ${payload.State}`)
  }

  // Extract JID from payload
  const jid = payload.JID
  if (!jid) {
    log.error({ payload }, 'JID missing from callback')
    ctx.quickloginStore.updateSession(session.sessionId, {
      status: 'failed',
      error: 'JID missing',
    })
    throw new Error('JID missing from callback')
  }

  log.info({ jid }, 'Processing QuickLogin for JID')

  // Branch: non-login approval sessions (delete_account, plc_operation)
  if (session.purpose && session.purpose !== 'login') {
    return handleApprovalCallback(session, jid, ctx, log)
  }

  // Check if this Neuro identity is already linked (check Legal ID first for real users, then JID for test users)
  let existingLink = await ctx.accountManager.db.db
    .selectFrom('neuro_identity_link')
    .selectAll()
    .where('legalId', '=', jid)
    .executeTakeFirst()

  // Fallback: check JID column for test users
  if (!existingLink) {
    existingLink = await ctx.accountManager.db.db
      .selectFrom('neuro_identity_link')
      .selectAll()
      .where('jid', '=', jid)
      .executeTakeFirst()
  }

  let did: string
  let accessJwt: string
  let refreshJwt: string
  let handle: string

  if (existingLink) {
    // User has logged in via QuickLogin before - use existing link
    log.info(
      { jid, did: existingLink.did },
      'Existing Neuro identity link found',
    )

    did = existingLink.did
    handle = await getHandleForDid(ctx, did)

    // Update last login
    await ctx.accountManager.db.db
      .updateTable('neuro_identity_link')
      .set({ lastLoginAt: new Date().toISOString() })
      .where((eb) => eb.where('legalId', '=', jid).orWhere('jid', '=', jid))
      .execute()

    // Create session
    const account = await ctx.accountManager.getAccount(did)
    if (!account) {
      log.error({ did }, 'Account not found for linked DID')
      throw new Error('Account not found')
    }

    const tokens = await ctx.accountManager.createSession(did, null, false)
    accessJwt = tokens.accessJwt
    refreshJwt = tokens.refreshJwt
  } else {
    // No existing link - this is user's first QuickLogin (but account should exist)
    //
    // IMPORTANT: QuickLogin is ONLY for login, not account creation.
    // The W ID app enforces that users cannot scan QR codes until both their
    // W ID account AND W Social account have been provisioned. Account provisioning
    // happens via the /neuro/provision/account endpoint when Neuro sends a
    // LegalIdUpdated notification. Therefore, when we reach this code, the account
    // must already exist - we just need to create the neuro_identity_link.

    // Log Properties to debug email extraction
    log.info(
      {
        jid,
        properties: payload.Properties,
        propertyKeys: payload.Properties ? Object.keys(payload.Properties) : [],
      },
      'QuickLogin Properties received',
    )

    const email = extractEmail(payload.Properties)
    const userName = extractUserName(payload.Properties)

    log.info(
      { jid, email, userName },
      'Extracted email and userName from Properties',
    )

    if (!email) {
      log.error(
        { jid, properties: payload.Properties },
        'No email found in QuickLogin payload',
      )
      ctx.quickloginStore.updateSession(session.sessionId, {
        status: 'failed',
        error: 'Email required',
      })
      throw new Error('Email required')
    }

    // Check if invitation is required and exists
    const inviteRequired = ctx.cfg.invites?.required ?? false
    let invitation: Awaited<
      ReturnType<typeof ctx.invitationManager.getInvitationByEmail>
    > = null

    if (inviteRequired) {
      invitation = await ctx.invitationManager.getInvitationByEmail(email)

      if (!invitation) {
        log.warn(
          { email: ctx.invitationManager.hashEmail(email), jid },
          'No invitation found - access denied',
        )
        ctx.quickloginStore.updateSession(session.sessionId, {
          status: 'failed',
          error: 'Invitation required',
        })
        const error: any = new Error(
          'An invitation is required to create an account. Please contact support.',
        )
        error.code = 'InvitationRequired'
        throw error
      }

      log.info(
        {
          email: ctx.invitationManager.hashEmail(email),
          preferredHandle: invitation.preferred_handle,
        },
        'Valid invitation found',
      )
    }

    // Find the existing account by email
    const existingAccount = await ctx.accountManager.db.db
      .selectFrom('account')
      .selectAll()
      .where('email', '=', email.toLowerCase())
      .executeTakeFirst()

    if (!existingAccount) {
      // Account doesn't exist yet
      if (inviteRequired && !invitation) {
        // Should never reach here due to earlier check, but defensive
        log.error({ jid, email }, 'No invitation and account not found')
        ctx.quickloginStore.updateSession(session.sessionId, {
          status: 'failed',
          error: 'Invitation required',
        })
        const error: any = new Error(
          'An invitation is required to create an account.',
        )
        error.code = 'InvitationRequired'
        throw error
      }

      // Create new account with invitation (if available)
      log.info(
        { jid, email, preferredHandle: invitation?.preferred_handle },
        'Creating new account via QuickLogin',
      )

      const preferredHandle = invitation?.preferred_handle || null
      const result = await createAccountViaQuickLogin(
        ctx,
        jid,
        email,
        userName,
        preferredHandle,
      )

      did = result.did
      handle = result.handle
      accessJwt = result.accessJwt
      refreshJwt = result.refreshJwt

      // Mark the invitation as consumed
      if (invitation) {
        await ctx.invitationManager.consumeInvitation(email, did, handle)
        log.info(
          { email: ctx.invitationManager.hashEmail(email) },
          'Invitation consumed',
        )
      }
    } else {
      // Account exists - create the link
      log.info(
        { jid, email, did: existingAccount.did },
        'Creating Neuro identity link for existing account',
      )

      did = existingAccount.did
      handle = await getHandleForDid(ctx, did)

      // Mark the invitation as consumed (if it exists)
      // This handles the case where account was created via provision webhook
      // but user is now logging in via QuickLogin
      if (invitation) {
        await ctx.invitationManager.consumeInvitation(email, did, handle)
        log.info(
          { email: ctx.invitationManager.hashEmail(email) },
          'Invitation consumed for existing account',
        )
      }

      // Create the neuro_identity_link (QuickLogin is for real users, not test users)
      await ctx.accountManager.db.db
        .insertInto('neuro_identity_link')
        .values({
          legalId: jid, // Real users use Legal ID
          jid: null, // NULL for real users
          did,
          email: email || null,
          userName: userName || null,
          isTestUser: 0,
          linkedAt: new Date().toISOString(),
          lastLoginAt: new Date().toISOString(),
        })
        .execute()

      // Create session
      const tokens = await ctx.accountManager.createSession(did, null, false)
      accessJwt = tokens.accessJwt
      refreshJwt = tokens.refreshJwt

      // Delete the invitation if it exists (account already created via other means)
      if (invitation) {
        await ctx.invitationManager.deleteInvitation(invitation.id)
        log.info(
          { email: ctx.invitationManager.hashEmail(email) },
          'Invitation consumed for existing account',
        )
      }
    }
  }

  // Update session with success
  ctx.quickloginStore.updateSession(session.sessionId, {
    status: 'completed',
    result: {
      did,
      handle,
      accessJwt,
      refreshJwt,
      created: !existingLink,
    },
  })

  log.info(
    { sessionId: session.sessionId, did, handle },
    'QuickLogin completed successfully',
  )

  return {
    did,
    handle,
    accessJwt,
    refreshJwt,
    created: !existingLink,
  }
}

/**
 * Handle a QuickLogin callback for a non-login approval session
 * (delete_account, plc_operation). Creates an internal email-style token
 * and stores it in the session for the client to retrieve via status polling.
 */
async function handleApprovalCallback(
  session: QuickLoginSession,
  jid: string,
  ctx: AppContext,
  log: Logger,
): Promise<void> {
  const { purpose, approvalDid } = session

  if (!approvalDid) {
    log.error(
      { sessionId: session.sessionId },
      'Approval session missing approvalDid',
    )
    ctx.quickloginStore.updateSession(session.sessionId, {
      status: 'failed',
      error: 'Approval session missing DID',
    })
    return
  }

  log.info(
    { purpose, did: approvalDid, jid },
    'WID approval QR scanned — creating token',
  )

  try {
    const token = await ctx.accountManager.createEmailToken(
      approvalDid,
      purpose as EmailTokenPurpose,
    )

    log.info(
      { purpose, did: approvalDid },
      'WID approval token created successfully',
    )

    ctx.quickloginStore.updateSession(session.sessionId, {
      status: 'completed',
      approvalToken: token,
    })
  } catch (err) {
    log.error(
      { err, purpose, did: approvalDid },
      'Failed to create approval token',
    )
    ctx.quickloginStore.updateSession(session.sessionId, {
      status: 'failed',
      error: 'Failed to create approval token',
    })
  }
}
