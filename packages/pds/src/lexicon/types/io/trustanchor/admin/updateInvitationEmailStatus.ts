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
const id = 'io.trustanchor.admin.updateInvitationEmailStatus'

export type QueryParams = {}

export interface InputSchema {
  /** Invitation email address */
  email: string
  /** Email delivery status */
  status: 'email_sent' | 'email_failed'
  /** Error message if status is email_failed */
  error?: string
  /** Brevo message ID if status is email_sent */
  messageId?: string
}

export interface OutputSchema {
  success: boolean
  invitationId?: number
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
