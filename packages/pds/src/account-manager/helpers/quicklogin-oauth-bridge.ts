import { InvalidRequestError } from '@atproto/oauth-provider'
import type { Fetch } from '@atproto-labs/fetch-node'
import type { QuickLoginSessionStore } from '../../api/io/trustanchor/quicklogin/store'
import type { QuickLoginConfig } from '../../config/config'
import { oauthLogger } from '../../logger'

/**
 * Bridges the OAuth sign-in flow to the real QuickLogin (WID) session machinery.
 *
 * Replaces the defunct NeuroAuthManager that was previously used in OAuthStore.
 * Unlike that manager, this bridge uses the same QuickLoginSessionStore and the
 * same callback endpoint (/xrpc/io.trustanchor.quicklogin.callback) that the
 * standalone QuickLogin XRPC flow uses — so no separate callback route is needed.
 */
export class QuickLoginOAuthBridge {
  constructor(
    private readonly store: QuickLoginSessionStore,
    private readonly cfg: QuickLoginConfig,
    private readonly safeFetch: Fetch,
    private readonly publicUrl: string,
  ) {}

  /**
   * Register a new session with the Neuro provider, create it in the local
   * store, and return the QR code URL + session credentials for the browser.
   *
   * Mirrors the logic in xrpc-init.ts so the resulting session is handled by
   * the same xrpc-callback.ts / callback-handler.ts code.
   */
  async initiateSession(): Promise<{
    sessionId: string
    sessionToken: string
    qrCodeUrl: string
    expiresAt: string
  }> {
    const { randomUUID } = await import('node:crypto')

    const callbackUrl = `${this.publicUrl}/xrpc/io.trustanchor.quicklogin.callback`
    const tempSessionId = randomUUID()
    const providerUrl = `${this.cfg.apiBaseUrl}/QuickLogin`

    oauthLogger.info(
      { providerUrl, callbackUrl },
      'QuickLogin OAuth bridge: step 1 — registering callback with WID provider',
    )

    // Step 1: Register callback with Neuro provider to get a serviceId
    const t1 = Date.now()
    const providerRes = await this.safeFetch.call(undefined, providerUrl, {
      method: 'POST',
      redirect: 'error',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ service: callbackUrl, sessionId: tempSessionId }),
    })

    if (!providerRes.ok) {
      const body = await providerRes.text().catch(() => '')
      oauthLogger.error(
        { status: providerRes.status, body, durationMs: Date.now() - t1 },
        'QuickLogin OAuth bridge: step 1 failed — WID provider returned non-OK',
      )
      throw new InvalidRequestError(
        `Failed to initialize QuickLogin session (provider ${providerRes.status}: ${body})`,
      )
    }

    const providerData = (await providerRes.json()) as Record<string, unknown>
    const serviceId = providerData.serviceId
    if (typeof serviceId !== 'string' || !serviceId) {
      oauthLogger.error(
        { providerData, durationMs: Date.now() - t1 },
        'QuickLogin OAuth bridge: step 1 failed — missing serviceId in response',
      )
      throw new InvalidRequestError(
        'Invalid response from Neuro provider: missing serviceId',
      )
    }
    oauthLogger.info(
      { durationMs: Date.now() - t1 },
      'QuickLogin OAuth bridge: step 1 OK — serviceId received',
    )

    // Step 2: Create a session in the local store (allowCreate=true — callback
    // handler already enforces invitation requirements independently)
    const session = this.store.createSession(true, serviceId)

    // Step 3: Request the QR code image from the provider
    const qrBody: Record<string, unknown> = {
      mode: 'image',
      purpose: this.cfg.purposeTextLogin || 'Login to W Social',
      serviceId,
      tab: session.sessionId,
    }
    if (this.cfg.propertyFilter) qrBody.propertyFilter = this.cfg.propertyFilter
    if (this.cfg.attachmentFilter !== undefined)
      qrBody.attachmentFilter = this.cfg.attachmentFilter

    oauthLogger.info(
      { sessionId: session.sessionId },
      'QuickLogin OAuth bridge: step 2 — requesting QR code image',
    )

    const t2 = Date.now()
    const qrRes = await this.safeFetch.call(undefined, providerUrl, {
      method: 'POST',
      redirect: 'manual',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(qrBody),
    })

    if (!qrRes.ok) {
      const body = await qrRes.text().catch(() => '')
      oauthLogger.error(
        { status: qrRes.status, body, durationMs: Date.now() - t2 },
        'QuickLogin OAuth bridge: step 2 failed — QR code generation failed',
      )
      throw new InvalidRequestError(
        `QR code generation failed (provider ${qrRes.status}: ${body})`,
      )
    }

    const qrData = (await qrRes.json()) as Record<string, unknown>
    if (!qrData.src || !qrData.signUrl) {
      oauthLogger.error(
        { keys: Object.keys(qrData), durationMs: Date.now() - t2 },
        'QuickLogin OAuth bridge: step 2 failed — missing src or signUrl in QR response',
      )
      throw new InvalidRequestError(
        'Invalid QR response from Neuro provider: missing src or signUrl',
      )
    }
    oauthLogger.info(
      { durationMs: Date.now() - t2 },
      'QuickLogin OAuth bridge: step 2 OK — QR code received',
    )

    // Step 4: Extract the signKey from signUrl ("tagsign:provider,KEY") and
    // store it on the session so the callback can look it up via Key field
    const signKey = (qrData.signUrl as string).split(',')[1]
    if (!signKey) {
      throw new InvalidRequestError(
        'Invalid signUrl format from Neuro provider',
      )
    }
    this.store.updateSessionKey(session.sessionId, signKey)

    return {
      sessionId: session.sessionId,
      sessionToken: session.sessionToken,
      qrCodeUrl: qrData.src as string,
      expiresAt: session.expiresAt,
    }
  }

  /**
   * Look up a completed QuickLogin session by its sessionToken and return the
   * authenticated DID, or null if the session is not yet completed / not found.
   *
   * The sessionToken is a 48-char random hex string that was given to the
   * browser when the session was initiated — it proves the browser was the one
   * that started this session.
   */
  getCompletedDid(sessionToken: string): string | null {
    const session = this.store.getSessionByToken(sessionToken)
    if (!session || session.status !== 'completed' || !session.result) {
      return null
    }
    return session.result.did
  }
}
