export type ChainId =
  | 'ETH' | 'ARB' | 'OP' | 'BASE' | 'MATIC' | 'POL' | 'BSC' | 'AVAX' | 'FTM'
  | 'LINEA' | 'SCROLL' | 'ZKSYNC' | 'BLAST' | 'MANTLE' | 'METIS' | 'MODE'
  | 'CELO' | 'GLMR' | 'MOVR' | 'CRO' | 'KAVA' | 'SONIC' | 'BERA' | 'UNICHAIN'
  | 'BTC' | 'LTC' | 'BCH' | 'DOGE' | 'DASH'
  | 'SOL' | 'TRX' | 'TON' | 'SUI' | 'APT' | 'NEAR' | 'ADA' | 'DOT' | 'KSM'
  | 'XRP' | 'XLM' | 'ATOM' | 'OSMO' | 'INJ' | 'TIA' | 'SEI' | 'EOS' | 'HBAR' | 'XMR'

export interface PoisoningResult {
  suspected: boolean
  reason?: string
  matchedPrefixChars: number
  matchedSuffixChars: number
}

export interface ValidationResult {
  valid: boolean
  chain: string
  normalizedChain: string
  addressFormat: string
  memoRequired: boolean
  memoValid: boolean
  poisoning: PoisoningResult
  errors: string[]
  warnings: string[]
}

const EVM_CHAINS = new Set([
  'ETH', 'ETHEREUM', 'ARB', 'ARBITRUM', 'OP', 'OPTIMISM', 'BASE',
  'MATIC', 'POL', 'POLYGON', 'BSC', 'BNB', 'AVAX', 'AVALANCHE', 'FTM',
  'LINEA', 'SCROLL', 'ZKSYNC', 'BLAST', 'MANTLE', 'METIS', 'MODE',
  'CELO', 'GLMR', 'MOVR', 'CRO', 'CRONOS', 'KAVA', 'SONIC', 'BERA', 'UNICHAIN',
  'GNOSIS', 'XDAI', 'FLR', 'CORE', 'SEI-EVM', 'ZORA', 'TAIKO',
])

const MEMO_RULES: Record<string, { label: string; regex: RegExp; hint: string }> = {
  XRP: { label: 'Destination Tag', regex: /^\d{1,10}$/, hint: '32-bit unsigned integer (0..4294967295)' },
  XLM: { label: 'Memo', regex: /^[A-Za-z0-9_\-.:/ ]{1,28}$/, hint: 'Up to 28 ASCII chars or 64-bit Memo ID' },
  ATOM: { label: 'IBC / Exchange Memo', regex: /^.{1,256}$/, hint: 'Non-empty routing memo for custodial deposits' },
  OSMO: { label: 'IBC / Exchange Memo', regex: /^.{1,256}$/, hint: 'Non-empty routing memo for custodial deposits' },
  INJ: { label: 'Memo', regex: /^.{1,256}$/, hint: 'Non-empty routing memo' },
  TIA: { label: 'Memo', regex: /^.{1,256}$/, hint: 'Non-empty routing memo' },
  SEI: { label: 'Memo', regex: /^.{1,256}$/, hint: 'Non-empty routing memo' },
  TON: { label: 'Comment / Memo', regex: /^.{1,128}$/, hint: 'Custodial deposit comment/tag' },
  EOS: { label: 'Memo', regex: /^.{1,256}$/, hint: 'Custodial exchange routing memo' },
  HBAR: { label: 'Memo', regex: /^.{1,100}$/, hint: 'Hedera deposit routing memo' },
}

const CHAIN_PATTERNS: Record<string, { format: string; regex: RegExp }> = {
  BTC: {
    format: 'Bitcoin Legacy/P2SH/Bech32/Taproot',
    regex: /^(bc1[ac-hj-np-z02-9]{25,87}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})$/,
  },
  LTC: {
    format: 'Litecoin Base58/Bech32',
    regex: /^(ltc1[ac-hj-np-z02-9]{25,87}|[LM3][a-km-zA-HJ-NP-Z1-9]{25,34})$/,
  },
  DOGE: { format: 'Dogecoin Base58', regex: /^[DA9][a-km-zA-HJ-NP-Z1-9]{33}$/ },
  BCH: { format: 'Bitcoin Cash CashAddr/Legacy', regex: /^((bitcoincash:)?[qp][a-z0-9]{41}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})$/ },
  DASH: { format: 'Dash Base58', regex: /^X[1-9A-HJ-NP-Za-km-z]{33}$/ },
  SOL: { format: 'Solana Ed25519 Base58', regex: /^[1-9A-HJ-NP-Za-km-z]{32,44}$/ },
  TRX: { format: 'TRON Base58Check', regex: /^T[1-9A-HJ-NP-Za-km-z]{33}$/ },
  TON: { format: 'TON User-Friendly Base64/Raw', regex: /^([EU]Q[A-Za-z0-9_-]{46}|-?\d+:[0-9a-fA-F]{64})$/ },
  SUI: { format: 'Sui 32-byte Hex', regex: /^0x[0-9a-fA-F]{64}$/ },
  APT: { format: 'Aptos 32-byte Hex', regex: /^0x[0-9a-fA-F]{1,64}$/ },
  NEAR: { format: 'NEAR Named / Implicit Account', regex: /^(([a-z0-9_-]+\.)*[a-z0-9_-]+\.(near|tg)|[0-9a-f]{64})$/ },
  ADA: { format: 'Cardano Shelley/Byron', regex: /^(addr1[0-9a-z]{50,110}|DdzFF[1-9A-HJ-NP-Za-km-z]{50,120})$/ },
  DOT: { format: 'Polkadot SS58', regex: /^1[1-9A-HJ-NP-Za-km-z]{45,47}$/ },
  KSM: { format: 'Kusama SS58', regex: /^[C-HJ-NP-Za-z][1-9A-HJ-NP-Za-km-z]{45,47}$/ },
  XRP: { format: 'XRP Ledger Classic/X-Address', regex: /^(r[1-9A-HJ-NP-Za-km-z]{24,34}|X[1-9A-HJ-NP-Za-km-z]{46})$/ },
  XLM: { format: 'Stellar Ed25519 StrKey', regex: /^G[A-Z2-7]{55}$/ },
  ATOM: { format: 'Cosmos Bech32', regex: /^cosmos1[02-9ac-hj-np-z]{38}$/ },
  OSMO: { format: 'Osmosis Bech32', regex: /^osmo1[02-9ac-hj-np-z]{38}$/ },
  INJ: { format: 'Injective Bech32', regex: /^inj1[02-9ac-hj-np-z]{38}$/ },
  TIA: { format: 'Celestia Bech32', regex: /^celestia1[02-9ac-hj-np-z]{38}$/ },
  SEI: { format: 'Sei Bech32', regex: /^sei1[02-9ac-hj-np-z]{38}$/ },
  EOS: { format: 'EOSIO 12-char Account', regex: /^[a-z1-5.]{1,12}$/ },
  HBAR: { format: 'Hedera Account ID', regex: /^0\.0\.\d{1,10}$/ },
  XMR: { format: 'Monero Standard/Subaddress', regex: /^[48][0-9AB][1-9A-HJ-NP-Za-km-z]{93}$/ },
}

export function detectAddressPoisoning(
  candidate: string,
  trusted?: string,
): PoisoningResult {
  const c = (candidate || '').trim()
  const t = (trusted || '').trim()
  if (!c || !t) {
    return { suspected: false, matchedPrefixChars: 0, matchedSuffixChars: 0 }
  }
  const cl = c.toLowerCase()
  const tl = t.toLowerCase()
  if (cl === tl) {
    return { suspected: false, matchedPrefixChars: cl.length, matchedSuffixChars: cl.length }
  }
  let prefix = 0
  const maxLen = Math.min(cl.length, tl.length)
  while (prefix < maxLen && cl[prefix] === tl[prefix]) prefix++
  let suffix = 0
  while (suffix < maxLen && cl[cl.length - 1 - suffix] === tl[tl.length - 1 - suffix]) suffix++

  const suspected = prefix >= 4 && suffix >= 4
  return {
    suspected,
    matchedPrefixChars: prefix,
    matchedSuffixChars: suffix,
    reason: suspected
      ? `Possible address-poisoning spoof: shares ${prefix} leading and ${suffix} trailing characters with trusted address while middle bytes differ.`
      : undefined,
  }
}

export function validateCryptoAddress(
  chain: string,
  address: string,
  memo?: string,
  trustedAddress?: string,
): ValidationResult {
  const normalizedChain = (chain || '').trim().toUpperCase()
  const trimmedAddress = (address || '').trim()
  const trimmedMemo = (memo || '').trim()
  const errors: string[] = []
  const warnings: string[] = []

  if (!normalizedChain) {
    errors.push('Blockchain identifier is required.')
  }
  if (!trimmedAddress) {
    errors.push('Wallet address is required.')
  }

  let addressFormat = 'Unknown'
  let syntaxValid = false

  if (EVM_CHAINS.has(normalizedChain)) {
    addressFormat = 'EVM 20-byte Hex (0x...)'
    syntaxValid = /^0x[0-9a-fA-F]{40}$/.test(trimmedAddress)
    if (syntaxValid) {
      const hexBody = trimmedAddress.slice(2)
      const hasUpper = /[A-F]/.test(hexBody)
      const hasLower = /[a-f]/.test(hexBody)
      if (!hasUpper && !hasLower) {
        // numeric only
      } else if (!(hasUpper && hasLower)) {
        warnings.push('EVM address lacks mixed-case EIP-55 checksum casing; verify destination carefully.')
      }
    }
  } else if (CHAIN_PATTERNS[normalizedChain]) {
    addressFormat = CHAIN_PATTERNS[normalizedChain].format
    syntaxValid = CHAIN_PATTERNS[normalizedChain].regex.test(trimmedAddress)
  } else if (normalizedChain) {
    errors.push(`Unsupported chain "${normalizedChain}". See https://allswap.io/tools/address-validator for full 46+ chain list.`)
  }

  if (trimmedAddress && addressFormat !== 'Unknown' && !syntaxValid) {
    errors.push(`Invalid ${normalizedChain} address format (expected ${addressFormat}).`)
  }

  const memoRule = MEMO_RULES[normalizedChain]
  const memoRequired = Boolean(memoRule)
  let memoValid = true

  if (memoRule) {
    if (!trimmedMemo) {
      warnings.push(`${normalizedChain} custodial transfers typically require a ${memoRule.label} (${memoRule.hint}).`)
    } else if (!memoRule.regex.test(trimmedMemo)) {
      memoValid = false
      errors.push(`Invalid ${normalizedChain} ${memoRule.label}: expected ${memoRule.hint}.`)
    }
  }

  const poisoning = detectAddressPoisoning(trimmedAddress, trustedAddress)
  if (poisoning.suspected && poisoning.reason) {
    errors.push(poisoning.reason)
  }

  return {
    valid: errors.length === 0,
    chain,
    normalizedChain,
    addressFormat,
    memoRequired,
    memoValid,
    poisoning,
    errors,
    warnings,
  }
}

export function useCryptoAddressValidator() {
  return {
    validateAddress: validateCryptoAddress,
    detectAddressPoisoning,
    isMemoRequiredChain: (chain: string) => Boolean(MEMO_RULES[(chain || '').trim().toUpperCase()]),
    isEvmChain: (chain: string) => EVM_CHAINS.has((chain || '').trim().toUpperCase()),
  }
}
