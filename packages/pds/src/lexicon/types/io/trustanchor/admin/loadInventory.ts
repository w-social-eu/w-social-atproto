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
const id = 'io.trustanchor.admin.loadInventory'

export type QueryParams = {}

export interface InputSchema {
  /** Array of WID accounts to load */
  accounts: InventoryAccount[]
  /** Optional batch identifier */
  batchName?: string
}

export interface OutputSchema {
  /** Number of accounts successfully loaded */
  loaded: number
  /** Number of accounts skipped (duplicates) */
  skipped: number
  /** Total accounts processed */
  total: number
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

export interface InventoryAccount {
  $type?: 'io.trustanchor.admin.loadInventory#inventoryAccount'
  /** Account DID (used as JID) */
  did: string
  /** Onboarding URL for account activation */
  onboardingUrl: string
  /** URL to QR code image */
  qrCodeUrl: string
  /** Optional suggested handle */
  preferredHandle?: string
}

const hashInventoryAccount = 'inventoryAccount'

export function isInventoryAccount<V>(v: V) {
  return is$typed(v, id, hashInventoryAccount)
}

export function validateInventoryAccount<V>(v: V) {
  return validate<InventoryAccount & V>(v, id, hashInventoryAccount)
}
