/**
 * GENERATED CODE - DO NOT MODIFY
 */
import { type ValidationResult, BlobRef } from '@atproto/lexicon'
import { CID } from 'multiformats/cid'
import { validate as _validate } from '../../../../lexicons'
import {
  type $Typed,
  is$typed as _is$typed,
  type OmitKey,
} from '../../../../util'

const is$typed = _is$typed,
  validate = _validate
const id = 'io.trustanchor.quicklogin.getLinkedAccounts'

export type QueryParams = {}

export interface InputSchema {}

export interface OutputSchema {
  /** All accounts (including the caller's) linked to the same WID, ordered by lastLoginAt descending. */
  accounts: LinkedAccount[]
}

export interface HandlerInput {
  encoding: 'application/json'
  body: InputSchema
}

export interface HandlerSuccess {
  encoding: 'application/json'
  body: OutputSchema
  headers?: { [key: string]: string }
}

export interface HandlerError {
  status: number
  message?: string
}

export type HandlerOutput = HandlerError | HandlerSuccess

export interface LinkedAccount {
  $type?: 'io.trustanchor.quicklogin.getLinkedAccounts#linkedAccount'
  /** Access token for this account */
  accessJwt: string
  /** Refresh token for this account */
  refreshJwt: string
  /** DID of this account */
  did: string
  /** Handle of this account */
  handle: string
}

const hashLinkedAccount = 'linkedAccount'

export function isLinkedAccount<V>(v: V) {
  return is$typed(v, id, hashLinkedAccount)
}

export function validateLinkedAccount<V>(v: V) {
  return validate<LinkedAccount & V>(v, id, hashLinkedAccount)
}
