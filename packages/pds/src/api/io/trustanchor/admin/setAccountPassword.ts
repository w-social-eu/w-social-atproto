import { InvalidRequestError } from '@atproto/xrpc-server'
import { NEW_PASSWORD_MAX_LENGTH } from '../../../../account-manager/helpers/scrypt'
import { AppContext } from '../../../../context'
import { Server } from '../../../../lexicon'
import { validateAdminAuth } from './shared'

const MIN_PASSWORD_LENGTH = 8

export default function (server: Server, ctx: AppContext) {
  server.io.trustanchor.admin.setAccountPassword({
    handler: async ({ input, req }) => {
      validateAdminAuth(req, ctx)

      const { did, password, removePassword = false } = input.body

      // Validate DID format — must start with "did:" to prevent treating
      // a handle or arbitrary string as a DID and corrupting a wrong row.
      if (!did || !did.startsWith('did:')) {
        throw new InvalidRequestError(
          'Invalid DID format. Must start with "did:"',
        )
      }

      // Exactly one of password or removePassword must be specified.
      if (removePassword && password != null) {
        throw new InvalidRequestError(
          'Provide either password or removePassword, not both',
        )
      }
      if (!removePassword && (password == null || password === '')) {
        throw new InvalidRequestError(
          'Either password or removePassword:true is required',
        )
      }

      // Enforce password length bounds.
      // Minimum prevents trivially weak passwords.
      // Maximum prevents bcrypt/scrypt DoS via oversized input.
      if (!removePassword && password != null) {
        if (password.length < MIN_PASSWORD_LENGTH) {
          throw new InvalidRequestError(
            `Password must be at least ${MIN_PASSWORD_LENGTH} characters`,
          )
        }
        if (password.length > NEW_PASSWORD_MAX_LENGTH) {
          throw new InvalidRequestError(
            `Password must be at most ${NEW_PASSWORD_MAX_LENGTH} characters`,
          )
        }
      }

      // Verify the account exists before attempting the write.
      // Avoids a silent no-op if the DID is wrong.
      const account = await ctx.accountManager.getAccount(did, {
        includeDeactivated: true,
        includeTakenDown: true,
      })
      if (!account) {
        throw new InvalidRequestError(`Account not found: ${did}`)
      }

      if (removePassword) {
        // removeAccountPassword:
        //   1. Sets account.passwordScrypt to NULL
        //   2. Deletes any pending reset_password email tokens for this DID
        //   3. Revokes all active refresh tokens for this DID
        await ctx.accountManager.removeAccountPassword(did)
        req.log.info(
          { did, handle: account.handle },
          'Admin removed main account password (WID-only auth restored)',
        )
      } else {
        // updateAccountPassword:
        //   1. Hashes the password with scrypt
        //   2. Writes to account.passwordScrypt (works even if previously NULL)
        //   3. Deletes any pending reset_password email tokens for this DID
        //   4. Revokes all active refresh tokens for this DID
        await ctx.accountManager.updateAccountPassword({
          did,
          password: password!,
        })
        req.log.info(
          { did, handle: account.handle },
          'Admin set main account password',
        )
      }

      return {
        encoding: 'application/json',
        body: { success: true },
      }
    },
  })
}
