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
const id = 'io.trustanchor.admin.getInventoryStatus'

export type QueryParams = {}
export type InputSchema = undefined

export interface OutputSchema {
  /** Number of available accounts (ready to allocate) */
  available: number
  /** Number of allocated accounts (assigned to invitations) */
  allocated: number
  /** Number of consumed accounts (activated) */
  consumed: number
  /** Total number of accounts in inventory */
  total: number
}

export type HandlerInput = void

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
