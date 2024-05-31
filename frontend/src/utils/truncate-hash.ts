import BigNumber from 'bignumber.js'

export const truncateHash = (hash: string | undefined, paddingLength = 6): string | undefined => {
  if (!hash?.length) return undefined
  if (hash.length <= paddingLength * 2 + 1) return hash
  return hash.replace(hash.substring(paddingLength, hash.length - paddingLength), '…')
}

export function formatNumber(number: number) {
  const bigNumber = new BigNumber(number)
  const formattedNumber = bigNumber.dividedBy(1e9).toFixed(3)
  const numberWithSeparator = Number(formattedNumber).toLocaleString()

  return numberWithSeparator
}
