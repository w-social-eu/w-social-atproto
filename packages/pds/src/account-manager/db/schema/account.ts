import { Generated, Selectable } from 'kysely'
import { DatetimeString } from '@atproto/lex'

export interface Account {
  did: string
  email: string
  // W Social: nullable password — OAuth/WID-only accounts have no password.
  passwordScrypt: string | null
  emailConfirmedAt: DatetimeString | null
  invitesDisabled: Generated<0 | 1>
}

export type AccountEntry = Selectable<Account>

export const tableName = 'account'

export type PartialDB = { [tableName]: Account }
