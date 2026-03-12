import { Selectable } from 'kysely'

export interface WidAccountInventory {
  did: string // Primary key
  onboarding_url: string
  qr_code_url: string | null
  preferred_handle: string | null
  created_at: string
  allocated_at: string | null
  allocated_to_email: string | null
  status: string // 'available' | 'allocated' | 'consumed'
}

export type WidAccountInventoryEntry = Selectable<WidAccountInventory>

export const tableName = 'wid_account_inventory'

export type PartialDB = { [tableName]: WidAccountInventory }
