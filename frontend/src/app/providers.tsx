'use client'

import { PropsWithChildren } from 'react'

import { WalletProvider } from '@suiet/wallet-kit'

export default function ClientProviders({ children }: PropsWithChildren) {
  return <WalletProvider>{children}</WalletProvider>
}
