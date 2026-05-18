import * as plc from '@did-plc/lib'
import { isEmailValid } from '@hapi/address'
import { isDisposableEmail } from 'disposable-email-domains-js'
import { DidDocument, MINUTE, check } from '@atproto/common'
import { ExportableKeypair, Keypair, Secp256k1Keypair } from '@atproto/crypto'
import { AtprotoData, ensureAtpDocument } from '@atproto/identity'
import { AuthRequiredError, InvalidRequestError } from '@atproto/xrpc-server'
import { AccountStatus } from '../../../../account-manager/account-manager'
import { NEW_PASSWORD_MAX_LENGTH } from '../../../../account-manager/helpers/scrypt'
import { AppContext } from '../../../../context'
import { baseNormalizeAndValidate } from '../../../../handle'
import { Server } from '../../../../lexicon'
import { InputSchema as CreateAccountInput } from '../../../../lexicon/types/com/atproto/server/createAccount'
import { CommitDataWithOps } from '../../../../actor-store/repo/transactor'
import { syncEvtDataFromCommit } from '../../../../sequencer'
import { sendIdentityEventWithRetry } from '../../../../sequencer/identity-event-helper'
import { safeResolveDidDoc } from './util'

export default function (server: Server, ctx: AppContext) {
  server.com.atproto.server.createAccount({
    rateLimit: {
      durationMs: 5 * MINUTE,
      points: 100,
    },
    auth: ctx.authVerifier.userServiceAuthOptional,
    handler: async ({ input, auth, req }) => {
      // @NOTE Until this code and the OAuthStore's `createAccount` are
      // refactored together, any change made here must be reflected over there.

      const requester = auth.credentials?.did ?? null
      const {
        did,
        handle,
        email,
        password,
        inviteCode,
        signingKey,
        plcOp,
        deactivated,
      } = ctx.entrywayAgent
        ? await validateInputsForEntrywayPds(ctx, input.body)
        : await validateInputsForLocalPds(ctx, input.body, requester)

      // Pre-validate Neuro Legal ID before creating account
      if (password && password.includes('@') && password.includes('legal.')) {
        if (!ctx.neuroAuthManager) {
          throw new InvalidRequestError(
            'Neuro authentication is not configured on this server. Please use a regular password instead.',
          )
        }
      }
      // Regular password - no special validation needed

      let didDoc: DidDocument | undefined
      let creds: { accessJwt: string; refreshJwt: string }

      // Phase 1: irreversible side effects — actor store + PLC + DB write.
      // The catch block only covers this phase. If anything here fails the
      // actor store is safe to destroy because the DB was never committed.
      await ctx.actorStore.create(did, signingKey)
      // eslint-disable-next-line prefer-const
      let commit!: CommitDataWithOps
      try {
        commit = await ctx.actorStore.transact(did, (actorTxn) =>
          actorTxn.repo.createRepo([]),
        )

        if (plcOp) {
          try {
            await ctx.plcClient.sendOperation(did, plcOp)
          } catch (err) {
            req.log.error(
              { didKey: ctx.plcRotationKey.did(), handle },
              'failed to create did:plc',
            )
            throw err
          }
        }

        didDoc = await safeResolveDidDoc(ctx, did, true)

        creds = await ctx.accountManager.createAccountAndSession({
          did,
          handle,
          email,
          password,
          repoCid: commit.cid,
          repoRev: commit.rev,
          inviteCode,
          deactivated,
        })
      } catch (err) {
        // Only reached when the DB write has NOT committed — safe to destroy.
        await ctx.actorStore.destroy(did)
        throw err
      }

      // Phase 2: best-effort steps after the account is committed to the DB.
      // Failures here must NOT destroy the actor store or delete DB records —
      // the account exists and is usable. Log and continue in every case.

      // Neuro Legal ID linking
      if (password && password.includes('@') && password.includes('legal.')) {
        if (!ctx.neuroAuthManager) {
          req.log.error(
            { did },
            'neuro auth manager not configured, skipping legal id link',
          )
        } else {
          try {
            req.log.info(
              { did, legalId: password },
              'Linking Neuro identity during account creation',
            )
            await ctx.neuroAuthManager.linkIdentity(password, did, email)
          } catch (err) {
            req.log.error(
              { err, did, legalId: password },
              'Failed to link Neuro identity — account created, link skipped',
            )
          }
        }
      }

      if (!deactivated) {
        // Auto-verify email when an invite code from a pending_invitations row is used
        // and the submitted email matches the invited email. This is safe because
        // the invite was sent to that specific address, proving ownership.
        if (ctx.cfg.invites.required && inviteCode && email) {
          try {
            const pendingInv =
              await ctx.invitationManager.getInvitationByInviteCode(inviteCode)
            if (
              pendingInv &&
              pendingInv.email.toLowerCase() === email.toLowerCase()
            ) {
              await ctx.accountManager.db.db
                .updateTable('account')
                .set({ emailConfirmedAt: new Date().toISOString() })
                .where('did', '=', did)
                .execute()
              req.log.info({ did }, 'Auto-verified email via invite code match')
            }
          } catch (err) {
            req.log.warn({ err }, 'Failed to auto-verify email via invite code')
          }
        }

        await sendIdentityEventWithRetry(
          ctx.sequencer,
          ctx.backgroundQueue,
          did,
          handle,
          req.log,
          'account creation',
        )

        try {
          await ctx.sequencer.sequenceAccountEvt(did, AccountStatus.Active)
          await ctx.sequencer.sequenceCommit(did, commit)
          await ctx.sequencer.sequenceSyncEvt(did, syncEvtDataFromCommit(commit))
        } catch (err) {
          req.log.error(
            { err, did },
            'sequencer failed during account creation — account created, events skipped',
          )
        }
      }

      try {
        await ctx.accountManager.updateRepoRoot(did, commit.cid, commit.rev)
      } catch (err) {
        req.log.error({ err, did }, 'updateRepoRoot failed after account creation')
      }

      try {
        await ctx.actorStore.clearReservedKeypair(signingKey.did(), did)
      } catch (err) {
        req.log.warn({ err, did }, 'clearReservedKeypair failed')
      }

      return {
        encoding: 'application/json',
        body: {
          handle,
          did: did,
          didDoc,
          accessJwt: creds.accessJwt,
          refreshJwt: creds.refreshJwt,
        },
      }
    },
  })
}

const validateInputsForEntrywayPds = async (
  ctx: AppContext,
  input: CreateAccountInput,
) => {
  const { did, plcOp } = input
  const handle = baseNormalizeAndValidate(input.handle)
  if (!did || !input.plcOp) {
    throw new InvalidRequestError(
      'non-entryway pds requires bringing a DID and plcOp',
    )
  }
  if (!check.is(plcOp, plc.def.operation)) {
    throw new InvalidRequestError('invalid plc operation', 'IncompatibleDidDoc')
  }
  const plcRotationKey = ctx.cfg.entryway?.plcRotationKey
  if (!plcRotationKey || !plcOp.rotationKeys.includes(plcRotationKey)) {
    throw new InvalidRequestError(
      'PLC DID does not include service rotation key',
      'IncompatibleDidDoc',
    )
  }
  try {
    await plc.assureValidOp(plcOp)
    await plc.assureValidSig([plcRotationKey], plcOp)
  } catch (err) {
    throw new InvalidRequestError('invalid plc operation', 'IncompatibleDidDoc')
  }
  const doc = plc.formatDidDoc({ did, ...plcOp })
  const data = ensureAtpDocument(doc)

  let signingKey: ExportableKeypair | undefined
  if (input.did) {
    signingKey = await ctx.actorStore.getReservedKeypair(input.did)
  }
  if (!signingKey) {
    signingKey = await ctx.actorStore.getReservedKeypair(data.signingKey)
  }
  if (!signingKey) {
    throw new InvalidRequestError('reserved signing key does not exist')
  }

  validateAtprotoData(data, {
    handle,
    pds: ctx.cfg.service.publicUrl,
    signingKey: signingKey.did(),
  })

  return {
    did,
    handle,
    email: undefined,
    password: undefined,
    inviteCode: undefined,
    signingKey,
    plcOp,
    deactivated: false,
  }
}

const validateInputsForLocalPds = async (
  ctx: AppContext,
  input: CreateAccountInput,
  requester: string | null,
) => {
  const { email, password, inviteCode } = input
  if (input.plcOp) {
    throw new InvalidRequestError('Unsupported input: "plcOp"')
  }

  // SECURITY: Block password-based account creation when invitations are disabled.
  // Bot accounts should only be created by admins via dedicated endpoint.
  // Human accounts should use WID/QuickLogin authentication.
  // Exception: account migrations carry a service JWT from the source PDS, which
  // sets `requester` to the migrating DID. Only the legitimate DID owner can
  // produce such a JWT, so this is a cryptographically proven ownership assertion.
  const isMigration = input.did != null && requester === input.did
  if (!ctx.cfg.invites.required && !isMigration) {
    throw new InvalidRequestError(
      'Password-based account creation is disabled. Please use WID authentication via QuickLogin.',
      'PasswordAccountCreationDisabled',
    )
  }

  if (password && password.length > NEW_PASSWORD_MAX_LENGTH) {
    throw new InvalidRequestError(
      `Password too long. Maximum length is ${NEW_PASSWORD_MAX_LENGTH} characters.`,
    )
  }

  if (ctx.cfg.invites.required && !inviteCode) {
    throw new InvalidRequestError(
      'No invite code provided',
      'InvalidInviteCode',
    )
  }

  if (!email) {
    throw new InvalidRequestError('Email is required')
  } else if (!isEmailValid(email) || isDisposableEmail(email)) {
    throw new InvalidRequestError(
      'This email address is not supported, please use a different email.',
    )
  }

  // normalize & ensure valid handle
  const handle = await ctx.accountManager.normalizeAndValidateHandle(
    input.handle,
    { did: input.did },
  )

  // check that the invite code still has uses
  if (ctx.cfg.invites.required && inviteCode) {
    await ctx.accountManager.ensureInviteIsAvailable(inviteCode)
  }

  // check that the handle and email are available
  const [handleAccnt, emailAcct] = await Promise.all([
    ctx.accountManager.getAccount(handle),
    ctx.accountManager.getAccountByEmail(email),
  ])
  if (handleAccnt) {
    throw new InvalidRequestError(`Handle already taken: ${handle}`)
  } else if (emailAcct) {
    throw new InvalidRequestError(`Email already taken: ${email}`)
  }

  // determine the did & any plc ops we need to send
  // if the provided did document is poorly setup, we throw
  const signingKey = await Secp256k1Keypair.create({ exportable: true })

  let did: string
  let plcOp: plc.Operation | null
  let deactivated = false
  if (input.did) {
    if (input.did !== requester) {
      throw new AuthRequiredError(
        `Missing auth to create account with did: ${input.did}`,
      )
    }
    did = input.did
    plcOp = null
    deactivated = true
  } else {
    const formatted = await formatDidAndPlcOp(ctx, handle, input, signingKey)
    did = formatted.did
    plcOp = formatted.plcOp
  }

  return {
    did,
    handle,
    email,
    password,
    inviteCode,
    signingKey,
    plcOp,
    deactivated,
  }
}

const formatDidAndPlcOp = async (
  ctx: AppContext,
  handle: string,
  input: CreateAccountInput,
  signingKey: Keypair,
): Promise<{
  did: string
  plcOp: plc.Operation | null
}> => {
  // if the user is not bringing a DID, then we format a create op for PLC
  const rotationKeys = [ctx.plcRotationKey.did()]
  if (ctx.cfg.identity.recoveryDidKey) {
    rotationKeys.unshift(ctx.cfg.identity.recoveryDidKey)
  }
  if (input.recoveryKey) {
    rotationKeys.unshift(input.recoveryKey)
  }
  const plcCreate = await plc.createOp({
    signingKey: signingKey.did(),
    rotationKeys,
    handle,
    pds: ctx.cfg.service.publicUrl,
    signer: ctx.plcRotationKey,
  })
  return {
    did: plcCreate.did,
    plcOp: plcCreate.op,
  }
}
const validateAtprotoData = (
  data: AtprotoData,
  expected: {
    handle: string
    pds: string
    signingKey: string
  },
) => {
  // if the user is bringing their own did:
  // resolve the user's did doc data, including rotationKeys if did:plc
  // determine if we have the capability to make changes to their DID
  if (data.handle !== expected.handle) {
    throw new InvalidRequestError(
      'provided handle does not match DID document handle',
      'IncompatibleDidDoc',
    )
  } else if (data.pds !== expected.pds) {
    throw new InvalidRequestError(
      'DID document pds endpoint does not match service endpoint',
      'IncompatibleDidDoc',
    )
  } else if (data.signingKey !== expected.signingKey) {
    throw new InvalidRequestError(
      'DID document signing key does not match service signing key',
      'IncompatibleDidDoc',
    )
  }
}
