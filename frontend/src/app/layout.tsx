import { Metadata, Viewport } from 'next'
import { PropsWithChildren } from 'react'

import '@suiet/wallet-kit/style.css'
import { Analytics } from '@vercel/analytics/react'
import { GeistMono } from 'geist/font/mono'
import { GeistSans } from 'geist/font/sans'

import { ToastConfig } from '@/app/toast-config'
import { TooltipProvider } from '@/components/ui/tooltip'
import { env } from '@/config/environment'
import { cn } from '@/utils/cn'

import { Footer } from './components/Footer'
import { Background } from './components/background'
import { HomeTopBar } from './components/home-top-bar'
import './globals.css'
import ClientProviders from './providers'

export const viewport: Viewport = {
  themeColor: '#000000',
  colorScheme: 'dark',
}

export const metadata: Metadata = {
  title: 'Sui Overflow Hackathon',
  description: 'Sui Overflow Hackathon',
  metadataBase: new URL(env.url),
  robots: env.isProduction ? 'all' : 'noindex,nofollow',
  openGraph: {
    type: 'website',
    locale: 'en',
    url: env.url,
    siteName: 'Sui Overflow Hackathon',
    images: [],
  },
  twitter: {
    site: '@scio_xyz',
    creator: '@scio_xyz',
    card: 'summary_large_image',
  },
}

export default function RootLayout({ children }: PropsWithChildren) {
  return (
    <html lang="en" className={cn('dark', GeistSans.variable, GeistMono.variable)}>
      <body>
        <ClientProviders>
          <TooltipProvider>
            <HomeTopBar />
            {children}
          </TooltipProvider>
          <ToastConfig />
          <Background />
        </ClientProviders>
        <Footer />

        {!!env.isProduction && <Analytics />}
      </body>
    </html>
  )
}
