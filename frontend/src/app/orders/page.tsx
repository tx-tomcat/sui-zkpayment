'use client'

import { useState, useEffect } from 'react'

import { createOrder, CreateOrderArgs } from '@/sui-client/zkramp/core/functions'
import { XMarkIcon } from '@heroicons/react/24/outline'
import { TransactionBlock } from '@mysten/sui.js/transactions'
import { useWallet } from '@suiet/wallet-kit'
import Pusher from 'pusher-js'
import toast from 'react-hot-toast'

import { Button } from '@/components/ui/button'
import { client } from '@/utils/cn'
import { ZKRAMP_ID } from '@/utils/constants'
import { contractTxWithToast } from '@/utils/contract-tx-with-toast'

import Modal from '../../components/ui/modal'
import OrderTable from '../components/order-table'
import PlaceOrderForm from '../components/place-order-form'
import UploadReceiptModal from '../components/upload-receipt-modal'

export default function OrdersPage() {
  const [showPlaceOrderForm, setShowPlaceOrderForm] = useState(false)
  const [selectedOrderUploadReceipt, setSelectedOrderUploadReceipt] = useState<any>(false)
  const { signAndExecuteTransactionBlock } = useWallet()
  const [hackyWayToForceRerender, setHackyWayToForceRerender] = useState(0)

  const Title = () => {
    return (
      <div className="mt-16 flex w-full items-end justify-between gap-1">
        <h1 className="text-2xl font-extrabold leading-loose text-white">Orders</h1>
        <Button onClick={() => setShowPlaceOrderForm(true)}>Place An Order</Button>
      </div>
    )
  }

  const onCreateOrder = async (order: any) => {
    const txb = new TransactionBlock()

    const [coin] = txb.splitCoins(txb.gas, [txb.pure(order.depositAmount * Math.pow(10, 9))])
    const orderArgs: CreateOrderArgs = {
      hashName: order.name,
      paymentKey: order.paymentKey,
      ramp: ZKRAMP_ID,
      coin: coin,
      amountToReceive: order.receiveAmount,
    }

    createOrder(txb, orderArgs)

    await contractTxWithToast(signAndExecuteTransactionBlock, txb)
    setShowPlaceOrderForm(false)
    setHackyWayToForceRerender((prev) => prev + 1)
  }
  const customToast = (message: string, status: boolean) => {
    toast(
      (t) => (
        <span>
          {message}
          <XMarkIcon width={20} title="close" onClick={() => toast.dismiss(t.id)}></XMarkIcon>
        </span>
      ),
      {
        icon: status ? '🧡' : '🔥',
      },
    )
  }
  useEffect(() => {
    const pusher = new Pusher('db73ad3fbe4d7d11395f', {
      cluster: 'ap1',
    })

    const channel = pusher.subscribe('p2p')

    channel.bind('message', function (message: any) {
      if (message.status) {
        customToast(message.message, message.status)
      } else {
        customToast(message.message, message.status)
      }
    })
    return () => {
      pusher.unsubscribe('p2p')
    }
  }, [])
  return (
    <>
      <div className="container relative flex grow flex-col items-center justify-center px-4 py-10 md:px-8">
        {selectedOrderUploadReceipt && (
          <UploadReceiptModal
            selectedOrder={selectedOrderUploadReceipt}
            onClose={() => setSelectedOrderUploadReceipt(null)}
          />
        )}
        <main className="flex flex-col gap-8">
          <Title />
          <OrderTable
            hackyWayToForceRerender={hackyWayToForceRerender}
            onOpenUploadReceiptModal={setSelectedOrderUploadReceipt}
          />

          {showPlaceOrderForm && (
            <Modal>
              <PlaceOrderForm
                onSubmit={onCreateOrder}
                onClose={() => setShowPlaceOrderForm(false)}
              />
            </Modal>
          )}
        </main>
      </div>
    </>
  )
}
