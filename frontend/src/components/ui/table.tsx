/* eslint-disable jsx-a11y/alt-text */
import { useEffect, useState } from 'react'

import { ContractIds } from '@/deployments/deployments'

import { fromBn } from 'evm-bn'
import toast from 'react-hot-toast'
import { twMerge } from 'tailwind-merge'

import BuyOrderModal from '@/app/components/buy-order-modal'
import { contractTxWithToast } from '@/utils/contract-tx-with-toast'

import Badge from './badge'
import { useWallet } from '@suiet/wallet-kit'
import { client } from '@/utils/cn'
import { ZKRamp } from '@/sui-client/zkramp/core/structs'
import { ZKRAMP_ID } from '@/utils/constants'
import { TransactionBlock } from '@mysten/sui.js/transactions'
import { claimOrder, ClaimOrderArgs } from '@/sui-client/zkramp/core/functions'

export default function Table() {
  const { account, connected} = useWallet()
  const [orders, setOrders] = useState<any>([])
  const [selectedOrder, setSelectedOrder] = useState<any>(null)
  const [claimedOrder, setClaimedOrder] = useState<any>(null)
  const [claimOrders, setClaimOrders] = useState<any>([])
  const [showBuyerModal, setShowBuyerModal] = useState(false)
  const { signAndExecuteTransactionBlock } = useWallet()

  const fetchAllOrders = async () => {
    const pool = await ZKRamp.r.fetch(client, ZKRAMP_ID)
   
    setOrders(
      pool.orderList.filter((order: any) => {
        return order.status != 1 && order.status != 2
      }),
    )
     setClaimOrders(pool.orderClaimList)
  }


  useEffect(() => {
    refresh()
  }, [])

  const refresh = async () => {
    await fetchAllOrders()
  }

  const getStatus = (order: any): number => {
    // const claimedOrder = claimOrders.filter((claimOrder: any) => {
    //   return claimOrder.orderIndex == order.id && claimOrder.status != 2
    // })

    // if (claimedOrder.length > 0) {
    //   return claimedOrder[0].status
    // }

    return order.status
  }

  const convertStatus = (status: number): string => {
    console.log(status)
    switch (status) {
      case 0:
        return 'Open'
      case 3:
        return 'Pending Buyer'
      case 4:
        return 'Pending Seller'
      case 1:
        return 'Filled'
      case 2:
        return 'Canceled'
      default:
        return 'Unknown'
    }
  }

  const createClaimOrder = async (order: any) => {
     if (!account || !connected) {
      toast.error('Wallet not connected. Try again…')
      return
    }
    const txb = new TransactionBlock()
    const orderArgs: ClaimOrderArgs = {
      orderId: order.orderId,
      ramp: ZKRAMP_ID,
      claimExpirationTime: BigInt(new Date().getTime() + 60 * 6000),
    }
    //     paymentKey,
    // depositAmount,
    // receiveAmount,
    // name: data.data.encryptedName,
    claimOrder(txb, orderArgs)

    // signAndExecuteTransactionBlock({
    //   transactionBlock: txb,
    // })

    await contractTxWithToast(signAndExecuteTransactionBlock, txb)
    setClaimedOrder({
      buyer: account.address,
      claimExpirationTime: new Date(new Date().getTime() + 60 * 60000),
      orderIndex: order.id,
      status: 3,
    })

    toast.success('Claim order created')
    await refresh()
  }

  const mockCreateOrder = async () => {
    await createClaimOrder(selectedOrder)
  }

  const selectOrder = (order: any) => {
    if (getStatus(order) == 0) {
      setSelectedOrder(order)
      setShowBuyerModal(true)
    }
  }

  return (
    <div className="w-full">
      {showBuyerModal && (
        <BuyOrderModal
          order={selectedOrder}
          claimedOrder={claimedOrder}
          onClose={() => setShowBuyerModal(false)}
          onClaimCreated={mockCreateOrder}
        />
      )}

      <div className="flow-root">
        <div className="-mx-4 -my-2 sm:-mx-6 lg:-mx-8">
          <div className="inline-block min-w-full py-2 align-middle sm:px-6 lg:px-8">
            <table className="min-w-full table-fixed border-spacing-x-10 divide-y divide-gray-300">
              <thead className="bg-surfaceHover">
                <tr>
                  <th
                    scope="col"
                    className="whitespace-pre py-3 pl-4 pr-3 text-left text-sm font-medium text-subtlest"
                  >
                    <a href="#" className="group inline-flex">
                      #
                    </a>
                  </th>
                  <th
                    scope="col"
                    className="whitespace-pre px-6 py-3 text-left text-sm font-medium text-subtlest"
                  >
                    <a href="#" className="group inline-flex">
                      Token
                    </a>
                  </th>
                  <th
                    scope="col"
                    className="whitespace-pre px-6 py-3 text-left text-sm font-medium text-subtlest"
                  >
                    <a href="#" className="group inline-flex">
                      Depositor
                    </a>
                  </th>
                  <th
                    scope="col"
                    className="whitespace-pre px-6 py-3 text-left text-sm font-medium text-subtlest"
                  >
                    <a href="#" className="group inline-flex">
                      Available Amount
                    </a>
                  </th>
                  <th
                    scope="col"
                    className="whitespace-pre px-6 py-3 text-left text-sm font-medium text-subtlest"
                  >
                    <a href="#" className="group inline-flex">
                      Price
                    </a>
                  </th>
                  <th
                    scope="col"
                    className="whitespace-pre px-6 py-3 text-left text-sm font-medium text-subtlest"
                  >
                    <a href="#" className="group inline-flex">
                      Status
                    </a>
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-200 bg-surface2">
                {orders.map((order: any) => {
                  console.log(orders)
                  return (
                    <tr
                      key={order.depositor}
                      onClick={() => selectOrder(order)}
                      className={twMerge(getStatus(order) == 0 && 'cursor-pointer')}
                    >
                      <td className="whitespace-nowrap py-4 pl-4 pr-3 text-sm font-medium text-subtlest">
                        {order.id}
                      </td>
                      <td className="flex whitespace-nowrap px-6 py-4 text-sm text-subtlest">
                        <img className="mr-2" src="/icons/azero.png" width={20} height={20} />
                        SUI
                      </td>
                      <td className="whitespace-nowrap px-6 py-4 text-sm text-subtlest">
                        {order.owner}
                      </td>
                      <td className="whitespace-nowrap px-6 py-4 text-sm text-subtlest">
                        {fromBn(order.amountToSend, 9)} SUI
                      </td>
                      <td className="whitespace-nowrap px-6 py-4 text-sm text-subtlest">
                        {order.amountToReceive} USD
                      </td>
                      <td className="whitespace-nowrap px-6 py-4 text-sm text-subtlest">
                        <Badge>{convertStatus(getStatus(order))}</Badge>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  )
}
