import { OAuthError } from './oauth-error.js'

export class SecondAuthenticationFactorRequiredError extends OAuthError {
  constructor(
    public type: 'emailOtp',
    public hint: string,
    /** URL to the QR code image (WID flow) */
    public qrCodeUrl?: string,
    /**
     * QuickLogin session ID — the browser uses this to poll
     * /xrpc/io.trustanchor.quicklogin.status for scan completion.
     */
    public sessionId?: string,
    /**
     * QuickLogin session token — the browser auto-submits this as emailOtp
     * once the scan is detected as completed, proving the browser initiated
     * the session.
     */
    public sessionToken?: string,
    cause?: unknown,
  ) {
    const error = 'second_authentication_factor_required'
    super(
      error,
      `${type} authentication factor required (hint: ${hint})`,
      401,
      cause,
    )
  }

  toJSON() {
    return {
      ...super.toJSON(),
      type: this.type,
      hint: this.hint,
      ...(this.qrCodeUrl && { qrCodeUrl: this.qrCodeUrl }),
      ...(this.sessionId && { sessionId: this.sessionId }),
      ...(this.sessionToken && { sessionToken: this.sessionToken }),
    } as const
  }
}
