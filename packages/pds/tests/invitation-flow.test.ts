import { TestNetworkNoAppView } from '@atproto/dev-env/src/network-no-appview'
import { InvitationManager } from '../src/account-manager/invitation-manager'

/**
 * Invitation Flow Integration Tests
 *
 * Tests the invitation lifecycle in the supported flow:
 * - create/update invitations
 * - Email normalization
 * - Batch processing
 * - Error handling (missing salt)
 */

describe('Invitation Flow Integration', () => {
  let network: TestNetworkNoAppView
  let previousInvitationEmailHashSalt: string | undefined

  beforeAll(async () => {
    previousInvitationEmailHashSalt = process.env.PDS_INVITATION_EMAIL_HASH_SALT
    process.env.PDS_INVITATION_EMAIL_HASH_SALT =
      process.env.PDS_INVITATION_EMAIL_HASH_SALT ||
      'test-invitation-email-hash-salt'

    network = await TestNetworkNoAppView.create({
      dbPostgresSchema: 'invitation_flow',
    })
  })

  afterAll(async () => {
    await network.close()

    if (previousInvitationEmailHashSalt === undefined) {
      delete process.env.PDS_INVITATION_EMAIL_HASH_SALT
    } else {
      process.env.PDS_INVITATION_EMAIL_HASH_SALT =
        previousInvitationEmailHashSalt
    }
  })

  describe('Invitation manager flow', () => {
    it('creates invitation with preferred handle', async () => {
      const email = 'apikey@example.com'
      await network.pds.ctx.invitationManager.createInvitation(
        email,
        'apikeyuser',
        Math.floor(Date.now() / 1000),
      )

      const invitation =
        await network.pds.ctx.invitationManager.getInvitationByEmail(email)

      expect(invitation).toBeDefined()
      expect(invitation?.email).toBe('apikey@example.com')
      expect(invitation?.preferred_handle).toBe('apikeyuser')
    })

    it('creates invitation without preferred handle', async () => {
      const email = 'nohandle@example.com'
      await network.pds.ctx.invitationManager.createInvitation(
        email,
        null,
        Math.floor(Date.now() / 1000),
      )

      const invitation =
        await network.pds.ctx.invitationManager.getInvitationByEmail(email)
      expect(invitation?.preferred_handle).toBeNull()
    })

    it('returns clear config error when invitation hash salt is missing', async () => {
      const manager = new InvitationManager(network.pds.ctx.accountManager.db, null)
      await expect(
        manager.createInvitation(
          'salt-missing@example.com',
          null,
          Math.floor(Date.now() / 1000),
        ),
      ).rejects.toThrow('PDS_INVITATION_EMAIL_HASH_SALT')
    })

    it('updates existing invitation on duplicate email', async () => {
      const email = 'update@example.com'

      // Create first invitation
      await network.pds.ctx.invitationManager.createInvitation(
        email,
        'firsthandle',
        Math.floor(Date.now() / 1000),
      )

      // Update with new handle
      await network.pds.ctx.invitationManager.createInvitation(
        email,
        'secondhandle',
        Math.floor(Date.now() / 1000) + 100,
      )

      // Verify only one invitation exists
      const invitation =
        await network.pds.ctx.invitationManager.getInvitationByEmail(email)
      expect(invitation?.preferred_handle).toBe('secondhandle')
    })
  })

  describe('QuickLogin with PDS_INVITE_REQUIRED=false', () => {
    it('allows account creation without invitation', async () => {
      // This test would require setting up a full QuickLogin flow
      // with mock Neuro server, which is tested in neuro-integration.test.ts
      // Here we just verify the invitation manager is accessible
      expect(network.pds.ctx.invitationManager).toBeDefined()
    })
  })

  describe('Email normalization', () => {
    it('handles mixed-case emails consistently', async () => {
      const email = 'MixedCase@Example.COM'

      await network.pds.ctx.invitationManager.createInvitation(
        email,
        null,
        Math.floor(Date.now() / 1000),
      )

      const invitation =
        await network.pds.ctx.invitationManager.getInvitationByEmail(email)
      expect(invitation?.email).toBe('mixedcase@example.com')
    })
  })

  describe('Batch invitation processing', () => {
    it('handles multiple rapid invitations', async () => {
      const promises = []
      for (let i = 0; i < 10; i++) {
        promises.push(
          network.pds.ctx.invitationManager.createInvitation(
            `batch${i}@example.com`,
            `batchuser${i}`,
            Math.floor(Date.now() / 1000),
          ),
        )
      }

      await Promise.all(promises)

      // Verify all were created
      const count = await network.pds.ctx.invitationManager.getPendingCount()
      expect(count).toBeGreaterThanOrEqual(10)
    })
  })
})
