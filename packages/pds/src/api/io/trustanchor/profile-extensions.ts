import type { AppContext } from '../../../context'
import type { ProfileViewDetailed } from '../../../lexicon/types/app/bsky/actor/defs'

/**
 * Add W Social platform extensions to a profile.
 * Only applies to accounts hosted on this PDS.
 *
 * Extensions:
 * - wsocialAccountType: 'human' | 'test' | 'organization' | 'bot'
 * - wsocialVerified: true (always true for W Social accounts)
 */
export async function addWSocialExtensions(
  ctx: AppContext,
  profile: ProfileViewDetailed,
): Promise<
  ProfileViewDetailed & {
    wsocialAccountType?: string
    wsocialVerified?: boolean
  }
> {
  try {
    // Check if account exists on this PDS
    const account = await ctx.accountManager.getAccount(profile.did, {
      includeDeactivated: true,
    })

    if (!account) {
      // Not a local account - return profile unchanged
      return profile
    }

    // Query neuro_identity_link to determine account type
    const neuroLink = await ctx.accountManager.db.db
      .selectFrom('neuro_identity_link')
      .select(['userJid', 'testUserJid'])
      .where('did', '=', profile.did)
      .executeTakeFirst()

    // Determine account type based on neuro link and configuration
    let accountType: string

    if (neuroLink?.userJid) {
      // Has a real user JID - verified human
      accountType = 'human'
    } else if (neuroLink?.testUserJid) {
      // Has a test user JID - test account
      accountType = 'test'
    } else if (ctx.cfg.wsocial.organizationDids.includes(profile.did)) {
      // DID is in the organization list
      accountType = 'organization'
    } else {
      // Local account with no neuro link - bot account
      accountType = 'bot'
    }

    // Return profile with W Social extensions
    return {
      ...profile,
      wsocialAccountType: accountType,
      wsocialVerified: true,
    }
  } catch (error) {
    // On any error, silently return original profile without extensions
    // This prevents breaking the endpoint due to transient DB issues
    console.error('Error adding W Social extensions to profile:', error)
    return profile
  }
}
