import Link from 'next/link'

export const Footer = () => {
  return (
    <footer>
      <div className="flex flex-col items-center justify-center gap-1 bg-[black] p-3 text-sm font-normal md:h-11 md:flex-row md:gap-4 md:p-2.5">
        <span className="font-medium">Made with 🧡 by James.</span>
      </div>
    </footer>
  )
}
