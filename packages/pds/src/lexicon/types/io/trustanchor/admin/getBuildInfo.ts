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
const id = 'io.trustanchor.admin.getBuildInfo'

export type QueryParams = {}
export type InputSchema = undefined

export interface OutputSchema {
  /** Git commit hash of the build */
  buildHash: string
  /** ISO 8601 timestamp of when the build was created */
  buildTime: string
  /** ISO 8601 timestamp of when the server started */
  startedAt: string
  /** Server uptime in seconds */
  uptime: number
  /** Node.js version */
  nodeVersion?: string
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
