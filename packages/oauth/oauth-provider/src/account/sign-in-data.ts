import { z } from 'zod'
import { localeSchema } from '../lib/util/locale.js'
import { emailOtpSchema } from '../types/email-otp.js'

export const signInDataSchema = z
  .object({
    locale: localeSchema,
    username: z.string(),
    // Allow empty string so WID/QR users (no password) can submit without one.
    password: z.string(),
    emailOtp: emailOtpSchema.optional(),
  })
  .strict()

export type SignInData = z.output<typeof signInDataSchema>
