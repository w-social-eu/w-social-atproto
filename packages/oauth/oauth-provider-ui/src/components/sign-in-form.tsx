import { Trans, useLingui } from '@lingui/react/macro'
import { AtIcon } from '@phosphor-icons/react'
import { ReactNode, useCallback, useEffect, useRef, useState } from 'react'
import { Button } from '#/components/forms/button.tsx'
import {
  FormCardAsync,
  FormCardAsyncProps,
} from '#/components/forms/form-card-async.tsx'
import { FormField } from '#/components/forms/form-field'
import { InputCheckbox } from '#/components/forms/input-checkbox.tsx'
import { InputPassword } from '#/components/forms/input-password.tsx'
import { InputText } from '#/components/forms/input-text.tsx'
import { InputToken } from '#/components/forms/input-token.tsx'
import { Admonition } from '#/components/utils/admonition.tsx'
import { AsyncActionController } from '#/hooks/use-async-action.ts'
import {
  InvalidCredentialsError,
  SecondAuthenticationFactorRequiredError,
} from '#/lib/api.ts'
import { isValidDomain } from '#/lib/handle'
import { mergeRefs } from '#/lib/ref.ts'
import { Override } from '#/lib/util.ts'

export type SignInFormOutput = {
  username: string
  password: string
  remember?: boolean
}

export type SignInFormProps = Override<
  Omit<FormCardAsyncProps, 'append' | 'onCancel'>,
  {
    usernameDefault?: string
    usernameReadonly?: boolean
    rememberDefault?: boolean
    disableRemember?: boolean
    domains?: readonly string[]

    onBack?: () => void
    backLabel?: ReactNode
    onForgotPassword?: (emailHint?: string) => void
    onSubmit: (
      credentials: SignInFormOutput,
      signal: AbortSignal,
    ) => void | PromiseLike<void>
  }
>

export function SignInForm({
  usernameDefault = '',
  usernameReadonly = false,
  rememberDefault = false,
  disableRemember = false,
  domains: availableDomains = [],

  onSubmit,
  onBack,
  backLabel,
  onForgotPassword,

  // FormCardAsync
  ref,
  invalid,
  children,
  ...props
}: SignInFormProps) {
  const { t } = useLingui()
  const domains = availableDomains.filter(isValidDomain)

  const [username, setUsername] = useState<string>(usernameDefault)
  const [password, setPassword] = useState<string>('')
  const [remember, setRemember] = useState<boolean>(rememberDefault)
  const [otp, setOtp] = useState<string | null>(null)

  const [secondFactor, setSecondFactor] =
    useState<null | SecondAuthenticationFactorRequiredError>(null)

  const [loading, setLoading] = useState(false)
  const [showPassword, setShowPassword] = useState(false)

  const formRef = useRef<AsyncActionController>(null)

  // In QR mode: poll QuickLogin status and auto-submit when the scan completes
  const pendingAutoSubmitRef = useRef(false)

  useEffect(() => {
    const { qrCodeUrl, sessionId, sessionToken } = secondFactor ?? {}
    if (!qrCodeUrl || !sessionId || !sessionToken) return

    const ac = new AbortController()
    const poll = async () => {
      while (!ac.signal.aborted) {
        await new Promise<void>((r) => setTimeout(r, 2000))
        if (ac.signal.aborted) break
        try {
          const res = await fetch('/xrpc/io.trustanchor.quicklogin.status', {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ sessionId, sessionToken }),
            signal: ac.signal,
          })
          if (!res.ok) continue
          const data = (await res.json()) as { status?: string }
          if (data.status === 'completed') {
            pendingAutoSubmitRef.current = true
            setOtp(sessionToken)
            break
          }
        } catch {
          if (!ac.signal.aborted) continue
        }
      }
    }
    void poll()
    return () => ac.abort()
  }, [
    secondFactor?.sessionId,
    secondFactor?.sessionToken,
    secondFactor?.qrCodeUrl,
  ])

  useEffect(() => {
    if (pendingAutoSubmitRef.current && otp) {
      pendingAutoSubmitRef.current = false
      formRef.current?.submit()
    }
  }, [otp])

  const clearSecondFactor = useCallback(() => {
    setOtp(null)
    setSecondFactor(null)
  }, [setOtp, setSecondFactor])

  const resetState = useCallback(() => {
    clearSecondFactor()
    formRef.current?.reset()
  }, [clearSecondFactor, formRef])

  const doSubmit = useCallback(
    async (signal: AbortSignal) => {
      try {
        await onSubmit(
          {
            username,
            password,
            remember: !disableRemember && remember,
            ...(secondFactor ? { [secondFactor.type]: otp } : {}),
          },
          signal,
        )
      } catch (err) {
        if (signal.aborted) {
          // If the action was aborted, ignore the error
          return
        }

        if (err instanceof SecondAuthenticationFactorRequiredError) {
          setSecondFactor(err)

          // Do not re-throw 2FA required error to prevent the form from from
          // displaying it. Instead, we handle the error by showing the second
          // factor form.
          return
        }

        if (err instanceof InvalidCredentialsError) {
          // If the username/password are not valid, clear the second factor
          // as valid credentials are a pre-requisite for 2FA.
          clearSecondFactor()
        }

        // Any thrown err will be displayed through the form's errorRender
        throw err
      }
    },
    [username, password, remember, secondFactor, otp, onSubmit],
  )

  return (
    <FormCardAsync
      {...props}
      ref={mergeRefs([ref, formRef])}
      onLoading={setLoading}
      onCancel={onBack}
      cancelLabel={backLabel ?? t`Back`}
      append={children}
      invalid={
        invalid ||
        !username ||
        (!secondFactor && showPassword && !password) ||
        (secondFactor != null && !secondFactor.qrCodeUrl && !otp)
      }
      submitLabel={
        secondFactor ? (
          <Trans context="verb">Confirm</Trans>
        ) : showPassword ? (
          <Trans context="verb">Sign in</Trans>
        ) : (
          <Trans context="verb">Sign in with WID</Trans>
        )
      }
      onSubmit={doSubmit}
    >
      <FormField disabled={loading} label={<Trans>Identifier</Trans>}>
        <InputText
          icon={<AtIcon aria-hidden weight="bold" className="w-5" />}
          name="username"
          type="text"
          title={t`Username or email address`}
          autoCapitalize="none"
          autoCorrect="off"
          autoComplete="username"
          spellCheck="false"
          dir="auto"
          enterKeyHint="next"
          required
          readOnly={usernameReadonly}
          disabled={usernameReadonly}
          autoFocus={!usernameReadonly}
          // email, handle (full domain), or DID
          pattern="([^@]+@[^@]+|[^.@]+(\.[^.@]+)+)|did:[a-z0-9]+:.+"
          value={username}
          onChange={(event) => {
            resetState()
            setUsername(event.target.value)
          }}
          onBlur={(event) => {
            if (usernameReadonly) return
            let value = event.target.value.trim().toLowerCase()
            if (value.startsWith('@')) {
              value = value.slice(1)
            }
            if (
              value.length > 0 &&
              !value.startsWith('did:') &&
              !value.includes('@') &&
              !value.includes('.') &&
              domains.length > 0
            ) {
              setUsername(`${value}${domains[0]}`)
            }
          }}
        />
      </FormField>

      {/* W Social: Password field only shown when user opts in (WID is the default) */}
      {!secondFactor?.qrCodeUrl && showPassword && (
        <FormField disabled={loading} label={<Trans>Password</Trans>}>
          <InputPassword
            name="password"
            onChange={(event) => {
              resetState()
              setPassword(event.target.value)
            }}
            append={
              onForgotPassword && (
                <Button
                  className="text-sm"
                  type="button"
                  color="darkGrey"
                  onClick={() => {
                    onForgotPassword(
                      username?.includes('@') ? username : undefined,
                    )
                  }}
                  aria-label={t`Reset your password`}
                >
                  <Trans>Forgot?</Trans>
                </Button>
              )
            }
            enterKeyHint={secondFactor ? 'next' : 'done'}
            disabled={loading}
            autoFocus={usernameReadonly}
            required
          />
        </FormField>
      )}

      {/* W Social: Toggle to reveal password field (app password fallback) */}
      {!secondFactor && !showPassword && (
        <div className="text-center">
          <button
            type="button"
            className="text-sm text-slate-500 underline dark:text-slate-400"
            onClick={() => {
              resetState()
              setShowPassword(true)
            }}
          >
            <Trans>Use app password instead</Trans>
          </button>
        </div>
      )}

      {/* W Social: Only show the password warning when actually using a password */}
      {!secondFactor?.qrCodeUrl && showPassword && password && (
        <Admonition role="status" title={<Trans>Warning</Trans>}>
          <Trans>
            Verify the website address before entering your password. Only sign
            in on sites you recognize and trust.
          </Trans>
        </Admonition>
      )}

      {!disableRemember && (
        <InputCheckbox
          name="remember"
          title={t`Remember this account on this device`}
          enterKeyHint={secondFactor ? 'next' : 'done'}
          checked={remember}
          onChange={(event) => setRemember(event.target.checked)}
        >
          <Trans>Remember this account on this device</Trans>
        </InputCheckbox>
      )}

      {secondFactor && (
        <FormField
          key="2fa"
          disabled={loading}
          label={
            secondFactor.qrCodeUrl ? (
              <Trans>WID Authentication</Trans>
            ) : (
              <Trans>2FA Confirmation</Trans>
            )
          }
        >
          <div className="flex flex-col gap-3">
            {secondFactor.qrCodeUrl ? (
              <>
                {/* W Social: WID QR code flow — user scans with WID app */}
                <img
                  src={secondFactor.qrCodeUrl}
                  alt={t`WID QR code`}
                  className="mx-auto block h-44 w-44"
                />
                <p className="text-center text-sm text-slate-600 dark:text-slate-400">
                  <Trans>Scan this QR code with your WID app to sign in.</Trans>
                </p>
                <p className="text-center text-sm italic text-slate-500 dark:text-slate-400">
                  <Trans>Waiting for scan…</Trans>
                </p>
              </>
            ) : (
              <>
                <InputToken
                  title={t`Confirmation code`}
                  enterKeyHint="done"
                  required
                  autoFocus={true}
                  value={otp ?? ''}
                  onToken={setOtp}
                />

                <p className="text-text-light text-sm">
                  <Trans>
                    Check your {secondFactor.hint} email for a login code and
                    enter it here.
                  </Trans>
                </p>
              </>
            )}
          </div>
        </FormField>
      )}
    </FormCardAsync>
  )
}
