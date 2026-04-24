import { Kysely, sql } from 'kysely'

// Migration 020: Many-to-many JID<->DID mapping + accountType on actor.
//
// Changes:
//   1. Add accountType TEXT NOT NULL DEFAULT 'organization' to actor table.
//   2. Backfill actor.accountType using first-match precedence:
//      a. passwordScrypt IS NOT NULL AND != '__WID_AUTH_ACCT__'  -> 'bot'
//      b. neuro_identity_link.userJid IS NOT NULL               -> 'personal'
//      c. neuro_identity_link.testUserJid IS NOT NULL           -> 'test'
//      d. else                                                  -> 'organization'
//   3. Rebuild neuro_identity_link as a join table (composite PK: jid + did).
//      - Drops: userJid, testUserJid, isTestUser (type now lives on actor)
//      - Keeps: linkedAt, lastLoginAt (now per-(jid,did) pair)
//   4. Add indices on jid and did columns.
//
// down() reverses accountType migration and restores the pre-020 1:1 schema.
// NOTE: down() can only reconstruct isTestUser (where accountType='test');
//       it cannot distinguish 'bot' from 'organization' — acceptable for rollback.

export async function up(db: Kysely<unknown>): Promise<void> {
  // --- Step 1: Add accountType to actor ---
  await sql`ALTER TABLE actor ADD COLUMN accountType TEXT NOT NULL DEFAULT 'organization'`.execute(
    db,
  )

  // --- Step 2: Backfill accountType from existing data ---
  // Join actor with account (for passwordScrypt) and neuro_identity_link (for JID columns).
  // First-match-wins order: bot > personal > test > organization.
  await sql`
    UPDATE actor
    SET accountType = CASE
      WHEN (
        SELECT a.passwordScrypt
        FROM account a
        WHERE a.did = actor.did
        LIMIT 1
      ) IS NOT NULL
      AND (
        SELECT a.passwordScrypt
        FROM account a
        WHERE a.did = actor.did
        LIMIT 1
      ) != '__WID_AUTH_ACCT__'
        THEN 'bot'
      WHEN (
        SELECT n.userJid
        FROM neuro_identity_link n
        WHERE n.did = actor.did AND n.userJid IS NOT NULL
        LIMIT 1
      ) IS NOT NULL
        THEN 'personal'
      WHEN (
        SELECT n.testUserJid
        FROM neuro_identity_link n
        WHERE n.did = actor.did AND n.testUserJid IS NOT NULL
        LIMIT 1
      ) IS NOT NULL
        THEN 'test'
      ELSE 'organization'
    END
  `.execute(db)

  // --- Step 3: Rebuild neuro_identity_link as a many-to-many join table ---

  const tableRows = (
    await sql<{ name: string }>`
      SELECT name FROM sqlite_master
      WHERE type = 'table'
        AND name IN ('neuro_identity_link', 'neuro_identity_link_old')
    `.execute(db)
  ).rows

  const hasCurrent = tableRows.some((r) => r.name === 'neuro_identity_link')
  const hasOld = tableRows.some((r) => r.name === 'neuro_identity_link_old')

  if (hasCurrent && !hasOld) {
    await db.schema
      .alterTable('neuro_identity_link')
      .renameTo('neuro_identity_link_old')
      .execute()
  }

  // Create new join table
  await sql`
    CREATE TABLE IF NOT EXISTS neuro_identity_link (
      jid       VARCHAR NOT NULL,
      did       VARCHAR NOT NULL,
      linkedAt  VARCHAR NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
      lastLoginAt VARCHAR,
      PRIMARY KEY (jid, did)
    )
  `.execute(db)

  // Migrate existing rows from old table (skip rows without a JID)
  const tableRowsAfter = (
    await sql<{ name: string }>`
      SELECT name FROM sqlite_master
      WHERE type = 'table' AND name = 'neuro_identity_link_old'
    `.execute(db)
  ).rows

  if (tableRowsAfter.some((r) => r.name === 'neuro_identity_link_old')) {
    const oldRows = (
      await sql<any>`SELECT * FROM neuro_identity_link_old`.execute(db)
    ).rows as Array<Record<string, any>>

    await sql`DELETE FROM neuro_identity_link`.execute(db)

    for (const row of oldRows) {
      const did = row.did as string | undefined
      const jid =
        (row.userJid as string | null | undefined) ??
        (row.testUserJid as string | null | undefined)
      if (!did || !jid) continue

      const linkedAt =
        (row.linkedAt as string | null | undefined) ?? new Date().toISOString()
      const lastLoginAt = (row.lastLoginAt as string | null | undefined) ?? null

      await sql`
        INSERT INTO neuro_identity_link (jid, did, linkedAt, lastLoginAt)
        VALUES (${jid}, ${did}, ${linkedAt}, ${lastLoginAt})
        ON CONFLICT(jid, did) DO UPDATE SET
          linkedAt = excluded.linkedAt,
          lastLoginAt = excluded.lastLoginAt
      `.execute(db)
    }

    await sql`DROP TABLE neuro_identity_link_old`.execute(db)
  }

  // --- Step 4: Indices ---
  await sql`
    CREATE INDEX IF NOT EXISTS neuro_identity_link_jid_idx
    ON neuro_identity_link(jid)
  `.execute(db)

  await sql`
    CREATE INDEX IF NOT EXISTS neuro_identity_link_did_idx
    ON neuro_identity_link(did)
  `.execute(db)
}

export async function down(db: Kysely<unknown>): Promise<void> {
  // 1) Rename current join table aside
  await db.schema
    .alterTable('neuro_identity_link')
    .renameTo('neuro_identity_link_new')
    .execute()

  // 2) Recreate the pre-020 schema (did as PRIMARY KEY)
  await sql`
    CREATE TABLE neuro_identity_link (
      did         VARCHAR PRIMARY KEY,
      userJid     VARCHAR,
      testUserJid VARCHAR,
      isTestUser  INTEGER NOT NULL DEFAULT 0,
      linkedAt    VARCHAR NOT NULL,
      lastLoginAt VARCHAR
    )
  `.execute(db)

  // 3) Migrate data back: pick the first link per DID (oldest linkedAt)
  //    Reconstruct isTestUser from actor.accountType
  await sql`
    INSERT INTO neuro_identity_link (did, userJid, testUserJid, isTestUser, linkedAt, lastLoginAt)
    SELECT
      n.did,
      CASE WHEN a.accountType = 'test' THEN NULL ELSE n.jid END,
      CASE WHEN a.accountType = 'test' THEN n.jid ELSE NULL END,
      CASE WHEN a.accountType = 'test' THEN 1 ELSE 0 END,
      n.linkedAt,
      n.lastLoginAt
    FROM neuro_identity_link_new n
    LEFT JOIN actor a ON a.did = n.did
    WHERE n.linkedAt = (
      SELECT MIN(n2.linkedAt) FROM neuro_identity_link_new n2 WHERE n2.did = n.did
    )
  `.execute(db)

  // 4) Recreate old indices
  await sql`
    CREATE UNIQUE INDEX IF NOT EXISTS neuro_identity_link_userJid_real_idx
    ON neuro_identity_link(userJid)
  `.execute(db)

  await sql`
    CREATE UNIQUE INDEX IF NOT EXISTS neuro_identity_link_testUserJid_test_idx
    ON neuro_identity_link(testUserJid)
  `.execute(db)

  await sql`
    CREATE INDEX IF NOT EXISTS neuro_identity_link_test_user_idx
    ON neuro_identity_link(isTestUser)
  `.execute(db)

  // 5) Drop rebuilt table
  await db.schema.dropTable('neuro_identity_link_new').execute()

  // 6) Remove accountType from actor (SQLite: rebuild table)
  await db.schema.alterTable('actor').renameTo('actor_with_type').execute()

  await sql`
    CREATE TABLE actor (
      did           VARCHAR PRIMARY KEY,
      handle        VARCHAR,
      createdAt     VARCHAR NOT NULL,
      takedownRef   VARCHAR,
      deactivatedAt VARCHAR,
      deleteAfter   VARCHAR
    )
  `.execute(db)

  await sql`
    INSERT INTO actor (did, handle, createdAt, takedownRef, deactivatedAt, deleteAfter)
    SELECT did, handle, createdAt, takedownRef, deactivatedAt, deleteAfter
    FROM actor_with_type
  `.execute(db)

  await db.schema.dropTable('actor_with_type').execute()
}
