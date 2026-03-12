import { Kysely } from 'kysely'

// Migration 018: WID Account Inventory table.
//
// Background:
//   To support invitation batches, we pre-provision WID accounts via Neuro
//   and store them in inventory. When sending an invitation, we allocate
//   an available account from inventory and link it to the invitation.
//
// Table stores:
//   - did: Pre-provisioned DID from Neuro
//   - onboarding_url: Single-use URL for account activation
//   - qr_code_url: URL to QR code image (fetched for email inlining)
//   - preferred_handle: Optional handle suggestion
//   - created_at: Timestamp of batch load
//   - allocated_at: Timestamp when allocated to invitation
//   - allocated_to_email: Email of invitation recipient
//   - status: 'available' | 'allocated' | 'consumed'

export async function up(db: Kysely<unknown>): Promise<void> {
  await db.schema
    .createTable('wid_account_inventory')
    .addColumn('did', 'varchar', (col) => col.primaryKey())
    .addColumn('onboarding_url', 'varchar', (col) => col.notNull())
    .addColumn('qr_code_url', 'varchar')
    .addColumn('preferred_handle', 'varchar')
    .addColumn('created_at', 'varchar', (col) => col.notNull())
    .addColumn('allocated_at', 'varchar')
    .addColumn('allocated_to_email', 'varchar')
    .addColumn('status', 'varchar', (col) =>
      col.notNull().defaultTo('available'),
    )
    .execute()

  // Index for quick lookups of available accounts
  await db.schema
    .createIndex('wid_account_inventory_status_idx')
    .on('wid_account_inventory')
    .column('status')
    .execute()

  // Index for allocated email lookups (audit trail)
  await db.schema
    .createIndex('wid_account_inventory_email_idx')
    .on('wid_account_inventory')
    .column('allocated_to_email')
    .execute()

  // Index for chronological queries
  await db.schema
    .createIndex('wid_account_inventory_created_idx')
    .on('wid_account_inventory')
    .column('created_at')
    .execute()
}

export async function down(db: Kysely<unknown>): Promise<void> {
  await db.schema.dropIndex('wid_account_inventory_status_idx').execute()
  await db.schema.dropIndex('wid_account_inventory_email_idx').execute()
  await db.schema.dropIndex('wid_account_inventory_created_idx').execute()
  await db.schema.dropTable('wid_account_inventory').execute()
}
