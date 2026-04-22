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
const id = 'io.trustanchor.admin.setAccountPassword'

export type QueryParams = {}

export interface InputSchema {
  /** DID of the account whose main password should be set */
  did: string
  /** New main account password (min 8, max 256 characters). Omit when removePassword is true. */
  password?: string
  /** When true, removes the main password (sets it to null), reverting to WID-only auth */
  removePassword?: boolean
}

export interface OutputSchema {
  success: boolean
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
