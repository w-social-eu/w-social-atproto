import { Kysely } from 'kysely'

export async function up(db: Kysely<unknown>): Promise<void> {
  // Add JID column for invitation keying
  await db.schema
    .alterTable('pending_invitations')
    .addColumn('jid', 'varchar')
    .execute()

  // Add onboarding URL from Neuro
  await db.schema
    .alterTable('pending_invitations')
    .addColumn('onboarding_url', 'varchar')
    .execute()

  // Add email delivery tracking columns
  await db.schema
    .alterTable('pending_invitations')
    .addColumn('email_last_sent_at', 'varchar')
    .execute()

  await db.schema
    .alterTable('pending_invitations')
    .addColumn('email_attempt_count', 'integer', (col) =>
      col.notNull().defaultTo(0),
    )
    .execute()

  await db.schema
    .alterTable('pending_invitations')
    .addColumn('email_last_error', 'varchar')
    .execute()

  // Create unique index on jid for JID-based lookups
  // Index is partial to allow multiple NULL jids during migration
  await db.schema
    .createIndex('pending_invitations_jid_idx')
    .on('pending_invitations')
    .column('jid')
    .execute()
}

export async function down(db: Kysely<unknown>): Promise<void> {
  await db.schema.dropIndex('pending_invitations_jid_idx').execute()

  // SQLite doesn't support DROP COLUMN safely across all deployments.
  // Keep columns in place on down migration.
}
