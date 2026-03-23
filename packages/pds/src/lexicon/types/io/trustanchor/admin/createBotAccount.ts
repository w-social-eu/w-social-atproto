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
const id = 'io.trustanchor.admin.createBotAccount'

export type QueryParams = {}

export interface InputSchema {
  /** Handle for the bot account (e.g., 'mybot' or 'test-bot') */
  handle: string
  /** Optional email for account recovery */
  email?: string
  /** Whether app password has full privileges (default: true) */
  privileged: boolean
}

export interface OutputSchema {
  /** DID of created account */
  did: string
  /** Full handle (e.g., 'mybot.wsky.social') */
  handle: string
  /** Generated app password (1234-abcd-5678-efgh) */
  appPassword: string
  /** Deep link URL for auto-login */
  deepLink: string
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
