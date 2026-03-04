import { Kysely } from 'kysely'

export async function up(db: Kysely<unknown>): Promise<void> {
  await db.schema
    .alterTable('pending_invitations')
    .addColumn('email_hash', 'varchar')
    .execute()

  await db.schema
    .createIndex('pending_invitations_email_hash_idx')
    .on('pending_invitations')
    .column('email_hash')
    .execute()
}

export async function down(db: Kysely<unknown>): Promise<void> {
  await db.schema.dropIndex('pending_invitations_email_hash_idx').execute()

  // SQLite doesn't support DROP COLUMN safely across all deployments.
  // Keep column in place on down migration.
}
