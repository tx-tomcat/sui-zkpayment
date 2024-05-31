import Link from 'next/link'
import { FC } from 'react'

import { TransactionBlock } from '@mysten/sui.js/transactions'
import { useWallet } from '@suiet/wallet-kit'
import { toast } from 'react-hot-toast'

export const contractTxWithToast = async (
  signAndExecuteTransactionBlock,
  txb: TransactionBlock,
) => {
  return toast.promise(signAndExecuteTransactionBlock({ transactionBlock: txb }), {
    loading: 'Sending transaction…',
    success: (result) => <ContractTxSuccessToast {...result} />,
    error: (result) => <ContractTxErrorToast {...result} />,
  })
}

export const ContractTxSuccessToast: FC = (result) => {
  const subscanUrl = `https://suiscan.xyz/testnet/tx/${result.digest}`

  return (
    <div className="flex flex-col gap-0.5">
      <div>Transaction successful</div>
      <div className="text-xs text-gray-400">
        View on{' '}
        <Link href={subscanUrl} target="_blank" className="transition-all hover:text-white">
          Suiscan ↗
        </Link>
      </div>
    </div>
  )
}

export const ContractTxErrorToast: FC = ({ errorMessage }) => {
  let message: string
  switch (errorMessage) {
    case 'UserCancelled':
      message = 'Transaction cancelled'
      break
    case 'TokenBelowMinimum':
      message = 'Insufficient balance to pay for fees'
      break
    case 'ExtrinsicFailed':
      message = 'Transaction failed'
      break
    case 'Error':
      message = 'Transaction failed'
      break
    default:
      message = errorMessage ? `Transaction failed (${errorMessage})` : 'Transaction failed'
  }

  return (
    <div className="flex flex-col gap-0.5">
      <div>{message}</div>
    </div>
  )
}
