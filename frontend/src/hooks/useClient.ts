import { getFullnodeUrl, SuiClient } from '@mysten/sui.js/client'

const client = new SuiClient({
  url: getFullnodeUrl('testnet'),
})
const useClient = (): SuiClient | null => {
  return client
}

export default useClient
