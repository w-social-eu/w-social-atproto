import { dbLogger } from '../logger'
import { AccountDb } from './db'
import { WidAccountInventoryEntry } from './db/schema'

export class WidInventoryManager {
  constructor(public db: AccountDb) {}

  /**
   * Allocate an available WID account from inventory
   * Returns null if no accounts available
   * Updates status to 'allocated' and records email  */
  async allocateAccount(
    email: string,
  ): Promise<WidAccountInventoryEntry | null> {
    const normalizedEmail = email.trim().toLowerCase()

    // Find an available account
    const account = await this.db.db
      .selectFrom('wid_account_inventory')
      .selectAll()
      .where('status', '=', 'available')
      .orderBy('created_at', 'asc') // FIFO allocation
      .limit(1)
      .executeTakeFirst()

    if (!account) {
      dbLogger.warn('No WID accounts available in inventory')
      return null
    }

    // Allocate it
    const now = new Date().toISOString()
    await this.db.db
      .updateTable('wid_account_inventory')
      .set({
        status: 'allocated',
        allocated_at: now,
        allocated_to_email: normalizedEmail,
      })
      .where('did', '=', account.did)
      .execute()

    dbLogger.info(
      {
        did: account.did,
        email: normalizedEmail,
      },
      'Allocated WID account from inventory',
    )

    // Return updated account
    return {
      ...account,
      status: 'allocated',
      allocated_at: now,
      allocated_to_email: normalizedEmail,
    }
  }

  /**
   * Mark account as consumed after successful activation
   */
  async markAccountConsumed(did: string): Promise<void> {
    await this.db.db
      .updateTable('wid_account_inventory')
      .set({ status: 'consumed' })
      .where('did', '=', did)
      .where('status', '=', 'allocated')
      .execute()

    dbLogger.info({ did }, 'Marked WID account as consumed')
  }

  /**
   * Get inventory status counts
   */
  async getInventoryStatus(): Promise<{
    available: number
    allocated: number
    consumed: number
    total: number
  }> {
    const [availableResult, allocatedResult, consumedResult, totalResult] =
      await Promise.all([
        this.db.db
          .selectFrom('wid_account_inventory')
          .select((eb) => eb.fn.count('did').as('count'))
          .where('status', '=', 'available')
          .executeTakeFirst(),
        this.db.db
          .selectFrom('wid_account_inventory')
          .select((eb) => eb.fn.count('did').as('count'))
          .where('status', '=', 'allocated')
          .executeTakeFirst(),
        this.db.db
          .selectFrom('wid_account_inventory')
          .select((eb) => eb.fn.count('did').as('count'))
          .where('status', '=', 'consumed')
          .executeTakeFirst(),
        this.db.db
          .selectFrom('wid_account_inventory')
          .select((eb) => eb.fn.count('did').as('count'))
          .executeTakeFirst(),
      ])

    return {
      available: Number(availableResult?.count || 0),
      allocated: Number(allocatedResult?.count || 0),
      consumed: Number(consumedResult?.count || 0),
      total: Number(totalResult?.count || 0),
    }
  }

  /**
   * Get detailed inventory list (for admin)
   */
  async getInventoryList(opts?: {
    status?: 'available' | 'allocated' | 'consumed'
    limit?: number
    offset?: number
  }): Promise<WidAccountInventoryEntry[]> {
    let query = this.db.db
      .selectFrom('wid_account_inventory')
      .selectAll()
      .orderBy('created_at', 'desc')

    if (opts?.status) {
      query = query.where('status', '=', opts.status)
    }

    if (opts?.limit) {
      query = query.limit(opts.limit)
    }

    if (opts?.offset) {
      query = query.offset(opts.offset)
    }

    return await query.execute()
  }

  /**
   * Check if inventory is below threshold
   */
  async isInventoryLow(threshold: number): Promise<boolean> {
    const status = await this.getInventoryStatus()
    return status.available < threshold
  }

  /**
   * Get account by DID (for admin lookups)
   */
  async getAccountByDid(did: string): Promise<WidAccountInventoryEntry | null> {
    return await this.db.db
      .selectFrom('wid_account_inventory')
      .selectAll()
      .where('did', '=', did)
      .executeTakeFirst()
      .then((row) => row || null)
  }

  /**
   * Load accounts into inventory from batch import
   * Returns counts of loaded and skipped (duplicate) accounts
   */
  async loadAccounts(
    accounts: Array<{
      did: string
      onboardingUrl: string
      qrCodeUrl: string
      preferredHandle?: string
    }>,
    batchName?: string,
  ): Promise<{ loaded: number; skipped: number; total: number }> {
    const now = new Date().toISOString()
    let loaded = 0
    let skipped = 0

    for (const account of accounts) {
      // Check if account already exists
      const existing = await this.getAccountByDid(account.did)

      if (existing) {
        dbLogger.info({ did: account.did }, 'Skipping duplicate account')
        skipped++
        continue
      }

      // Insert new account
      await this.db.db
        .insertInto('wid_account_inventory')
        .values({
          did: account.did,
          onboarding_url: account.onboardingUrl,
          qr_code_url: account.qrCodeUrl,
          preferred_handle: account.preferredHandle || null,
          created_at: now,
          status: 'available',
          allocated_at: null,
          allocated_to_email: null,
        })
        .execute()

      loaded++
    }

    dbLogger.info(
      { loaded, skipped, total: accounts.length, batchName },
      'Loaded WID accounts into inventory',
    )

    return {
      loaded,
      skipped,
      total: accounts.length,
    }
  }
}
