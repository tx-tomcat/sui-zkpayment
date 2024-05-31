'use client'

import Link from 'next/link'
import { useEffect } from 'react'

import { XMarkIcon } from '@heroicons/react/24/outline'
import Pusher from 'pusher-js'
import { toast } from 'react-hot-toast'

import { Button } from '../components/ui/button'
import { HeroHexagons } from './components/hero-hexagons'

export default function HomePage() {
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
    console.log(channel)
    channel.bind('message', function (message: any) {
      console.log(message)
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
  const HeroText = () => {
    return (
      <div className="mt-16 flex flex-col items-center gap-6">
        <h1 className="max-w-2xl text-center text-3xl font-extrabold leading-9 text-white md:text-5xl md:leading-[60px]">
          Lightning-fast Fiat to SUI Transaction with the highest level of security
        </h1>
        <h2 className="max-w-2xl text-center text-xl font-normal leading-normal text-zinc-300 md:leading-7">
          See what we could build for you leverages zero-knowledge proofs to ensure your
          transactions remain private while providing unmatched efficiency in onramp/offramp
          solutions.
        </h2>
      </div>
    )
  }

  return (
    <>
      <div className="container relative flex grow flex-col items-center justify-center px-4 py-10 md:px-8">
        <main className="flex flex-col gap-8">
          <HeroText />
          <div className="mb-6 flex items-center justify-center gap-6 px-2 md:mb-0">
            <Button className="h-12 w-1/2 md:h-auto md:w-auto" variant="outline">
              <Link href="orders">Add Liquidity</Link>
            </Button>
            <Button className="h-12 w-1/2 md:h-auto md:w-auto" variant="default">
              <Link href="liquidity">Buy SUI</Link>
            </Button>
          </div>
          <HeroHexagons />
        </main>
      </div>
    </>
  )
}
