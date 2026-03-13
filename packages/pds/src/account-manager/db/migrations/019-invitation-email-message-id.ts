import { Kysely } from 'kysely'

/**
 * Add email_message_id column to track Brevo message IDs
 */
export async function up(db: Kysely<unknown>): Promise<void> {
  // Add email_message_id column for Brevo message tracking
  await db.schema
    .alterTable('pending_invitations')
    .addColumn('email_message_id', 'varchar')
    .execute()
}

export async function down(db: Kysely<unknown>): Promise<void> {
  // SQLite doesn't support DROP COLUMN safely across all deployments.
  // Keep column in place on down migration.
}
