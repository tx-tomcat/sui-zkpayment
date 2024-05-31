'use client'

import Image from 'next/image'
import Link from 'next/link'
import { FC, useMemo, useState } from 'react'

import { formatAddress } from '@mysten/sui.js/utils'
import { useAccountBalance, useWallet } from '@suiet/wallet-kit'
import { AlertOctagon } from 'lucide-react'
import aznsIconSvg from 'public/icons/azns-icon.svg'
import toast from 'react-hot-toast'
import { AiOutlineCheckCircle, AiOutlineDisconnect } from 'react-icons/ai'
import { FiChevronDown, FiExternalLink } from 'react-icons/fi'
import { RiArrowDownSLine } from 'react-icons/ri'

import { Button } from '@/components/ui/button'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { env } from '@/config/environment'
import { formatNumber, truncateHash } from '@/utils/truncate-hash'

import { Tooltip, TooltipContent, TooltipTrigger } from '../ui/tooltip'

export interface ConnectButtonProps {}
export const ConnectButton: FC<ConnectButtonProps> = () => {
  const {
    disconnect,
    select,
    connecting,
    account,
    configuredWallets, // default wallets
    detectedWallets, // Sui-standard wallets detected from browser env
    allAvailableWallets,
  } = useWallet()
  const { error, loading, balance } = useAccountBalance()

  // Connect Button
  if (!account)
    return (
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button
            className="h-12 min-w-[14rem] gap-2 rounded-2xl border border-white/10 bg-primary px-4 py-3 font-bold text-black"
            isLoading={connecting}
            disabled={connecting}
            translate="no"
          >
            Connect Wallet
            <RiArrowDownSLine size={20} aria-hidden="true" />
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent className="min-w-[14rem]">
          {!account &&
            [...configuredWallets, ...detectedWallets].map((w) =>
              w.installed ? (
                <DropdownMenuItem
                  key={w.name}
                  className="cursor-pointer"
                  onClick={() => {
                    select(w.name)
                  }}
                >
                  {w.name}
                </DropdownMenuItem>
              ) : (
                <DropdownMenuItem key={w.name} className="opacity-50">
                  <Link href={w.downloadUrl.browserExtension!}>
                    <div className="align-center flex justify-start gap-2">
                      <p>{w.name}</p>
                      <FiExternalLink size={16} />
                    </div>
                    <p>Not installed</p>
                  </Link>
                </DropdownMenuItem>
              ),
            )}
        </DropdownMenuContent>
      </DropdownMenu>
    )

  // Account Menu & Disconnect Button
  return (
    <div className="flex select-none flex-wrap items-stretch justify-center gap-4">
      {/* Account Name, Address, and SUI.ID-Domain (if assigned) */}
      <DropdownMenu>
        <DropdownMenuTrigger
          asChild
          className="rounded-2xl bg-gray-900 px-4 py-6 font-bold text-foreground"
        >
          <Button className="min-w-[14rem] border" translate="no">
            <div className="flex items-center justify-between gap-2">
              <div className="flex flex-col items-center justify-center">
                <span className="text-xs font-normal">{formatAddress(account.address)}</span>
              </div>
              <FiChevronDown className="shrink-0" size={22} aria-hidden="true" />
            </div>
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent
          align="end"
          className="no-scrollbar max-h-[40vh] min-w-[14rem] overflow-scroll rounded-2xl"
        >
          {/* Available Accounts/Wallets */}
          <DropdownMenuSeparator />

          {/* Disconnect Button */}
          <DropdownMenuSeparator />
          <DropdownMenuItem className="cursor-pointer" onClick={() => disconnect?.()}>
            <div className="flex gap-2">
              <AiOutlineDisconnect size={18} />
              Disconnect
            </div>
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>

      {/* Account Balance */}
      {balance !== undefined && (
        <div className="flex min-w-[10rem] items-center justify-center gap-2 rounded-2xl border bg-gray-900 px-4 py-3 font-mono text-sm font-bold text-foreground">
          {formatNumber(balance)}
          {!balance && (
            <Tooltip>
              <TooltipTrigger className="cursor-help">
                <AlertOctagon size={16} className="text-warning" />
              </TooltipTrigger>
              <TooltipContent>No balance to pay fees</TooltipContent>
            </Tooltip>
          )}
        </div>
      )}
    </div>
  )
}

export const AccountName: FC = ({ ...rest }) => {
  const { account } = useWallet()

  return (
    <div className="flex items-center gap-2 font-mono text-sm font-bold uppercase" {...rest}>
      {account?.address}
    </div>
  )
}
