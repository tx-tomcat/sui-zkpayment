import { getFullnodeUrl, SuiClient } from '@mysten/sui.js/client'
import { clsx, type ClassValue } from 'clsx'
import { twMerge } from 'tailwind-merge'

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

export const client = new SuiClient({
  url: getFullnodeUrl('testnet'),
})
