import { Generated, Selectable } from 'kysely'

// NeuroIdentityLink: Many-to-many join table between JIDs and DIDs.
// PDS stores ONLY pseudonymous JID keys; no validated identity attributes.
// WID (Neuro) owns all identity verification, eligibility, invitations.
// One JID may be linked to multiple DIDs; one DID may be linked to multiple JIDs.
export interface NeuroIdentityLink {
  jid: string // XMPP JID — composite PK with did
  did: string // Foreign key to actor.did — composite PK with jid
  linkedAt: Generated<string> // ISO timestamp when this link was created
  lastLoginAt: string | null // ISO timestamp of last login via this specific (jid, did) pair
}

export type NeuroIdentityLinkEntry = Selectable<NeuroIdentityLink>

export const tableName = 'neuro_identity_link'

export type PartialDB = { [tableName]: NeuroIdentityLink }

