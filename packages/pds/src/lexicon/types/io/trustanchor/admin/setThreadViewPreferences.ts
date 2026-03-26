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
const id = 'io.trustanchor.admin.setThreadViewPreferences'

export type QueryParams = {}

export interface InputSchema {
  /** The DID of the account to update */
  did: string
  /** Whether to enable threaded view (true) or linear view (false) */
  treeViewEnabled: boolean
  /** Sort order for thread replies */
  sort:
    | 'oldest'
    | 'newest'
    | 'most-likes'
    | 'random'
    | 'hotness'
    | (string & {})
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
  error?: 'AccountNotFound' | 'InvalidSort'
}

export type HandlerOutput = HandlerError | HandlerSuccess
