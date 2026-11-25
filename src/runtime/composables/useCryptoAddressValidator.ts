export interface ChainRule {
  name: string
  pattern: RegExp
  requiresMemo: boolean
  memoName: string
  memoPattern?: RegExp
}

export interface ValidationResult {
  valid: boolean
  code:
    | 'VALID_VERIFIED'
    | 'UNSUPPORTED_CHAIN'
    | 'INVALID_ADDRESS_SYNTAX'
    | 'INVALID_CHECKSUM'
    | 'MISSING_MANDATORY_MEMO'
    | 'INVALID_MEMO_FORMAT'
    | 'ADDRESS_POISONING_ALERT'
  chain: string
  message: string
}

const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
const BECH32_CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'
const BECH32_CONST = 1
const BECH32M_CONST = 0x2bc830a3

// Compact synchronous SHA-256 for zero-dependency Base58Check verification
function sha256Bytes(data: Uint8Array): Uint8Array {
  const K = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  ])
  const H = new Uint32Array([
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
  ])
  const bitLen = data.length * 8
  const padLen = ((data.length + 9 + 63) >> 6) << 6
  const padded = new Uint8Array(padLen)
  padded.set(data)
  padded[data.length] = 0x80
  const dv = new DataView(padded.buffer)
  dv.setUint32(padLen - 4, bitLen >>> 0, false)
  dv.setUint32(padLen - 8, Math.floor(bitLen / 0x100000000), false)

  const W = new Uint32Array(64)
  const rotr = (x: number, n: number) => (x >>> n) | (x << (32 - n))

  for (let i = 0; i < padLen; i += 64) {
    for (let t = 0; t < 16; t++) W[t] = dv.getUint32(i + t * 4, false)
    for (let t = 16; t < 64; t++) {
      const s0 = rotr(W[t - 15], 7) ^ rotr(W[t - 15], 18) ^ (W[t - 15] >>> 3)
      const s1 = rotr(W[t - 2], 17) ^ rotr(W[t - 2], 19) ^ (W[t - 2] >>> 10)
      W[t] = (W[t - 16] + s0 + W[t - 7] + s1) >>> 0
    }
    let [a, b, c, d, e, f, g, h] = H
    for (let t = 0; t < 64; t++) {
      const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)
      const ch = (e & f) ^ (~e & g)
      const temp1 = (h + S1 + ch + K[t] + W[t]) >>> 0
      const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)
      const maj = (a & b) ^ (a & c) ^ (b & c)
      const temp2 = (S0 + maj) >>> 0
      h = g; g = f; f = e; e = (d + temp1) >>> 0
      d = c; c = b; b = a; a = (temp1 + temp2) >>> 0
    }
    H[0] = (H[0] + a) >>> 0; H[1] = (H[1] + b) >>> 0; H[2] = (H[2] + c) >>> 0; H[3] = (H[3] + d) >>> 0
    H[4] = (H[4] + e) >>> 0; H[5] = (H[5] + f) >>> 0; H[6] = (H[6] + g) >>> 0; H[7] = (H[7] + h) >>> 0
  }
  const out = new Uint8Array(32)
  const outDv = new DataView(out.buffer)
  for (let i = 0; i < 8; i++) outDv.setUint32(i * 4, H[i], false)
  return out
}

export function verifyBase58Check(address: string): boolean {
  const bytes: number[] = [0]
  for (let i = 0; i < address.length; i++) {
    const c = BASE58_ALPHABET.indexOf(address[i])
    if (c < 0) return false
    let carry = c
    for (let j = 0; j < bytes.length; j++) {
      carry += bytes[j] * 58
      bytes[j] = carry & 0xff
      carry >>= 8
    }
    while (carry > 0) {
      bytes.push(carry & 0xff)
      carry >>= 8
    }
  }
  for (let i = 0; i < address.length && address[i] === '1'; i++) bytes.push(0)
  const decoded = Uint8Array.from(bytes.reverse())
  if (decoded.length < 5) return false
  const payload = decoded.slice(0, -4)
  const checksum = decoded.slice(-4)
  const hash = sha256Bytes(sha256Bytes(payload))
  return checksum[0] === hash[0] && checksum[1] === hash[1] && checksum[2] === hash[2] && checksum[3] === hash[3]
}

function bech32Polymod(values: number[]): number {
  const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
  let chk = 1
  for (const v of values) {
    const b = chk >>> 25
    chk = ((chk & 0x1ffffff) << 5) ^ v
    for (let i = 0; i < 5; i++) {
      if ((b >>> i) & 1) chk ^= GEN[i]
    }
  }
  return chk >>> 0
}

export function verifyBech32Address(address: string): boolean {
  if (address !== address.toLowerCase() && address !== address.toUpperCase()) return false
  const lower = address.toLowerCase()
  const pos = lower.lastIndexOf('1')
  if (pos < 1 || pos + 7 > lower.length || lower.length > 90) return false
  const hrp = lower.slice(0, pos)
  const dataPart = lower.slice(pos + 1)
  const data: number[] = []
  for (let i = 0; i < dataPart.length; i++) {
    const idx = BECH32_CHARSET.indexOf(dataPart[i])
    if (idx < 0) return false
    data.push(idx)
  }
  const hrpExpanded: number[] = []
  for (let i = 0; i < hrp.length; i++) hrpExpanded.push(hrp.charCodeAt(i) >> 5)
  hrpExpanded.push(0)
  for (let i = 0; i < hrp.length; i++) hrpExpanded.push(hrp.charCodeAt(i) & 31)
  const polymod = bech32Polymod([...hrpExpanded, ...data])
  const witnessVer = data[0]
  if (witnessVer === 0) return polymod === BECH32_CONST
  if (witnessVer >= 1 && witnessVer <= 16) return polymod === BECH32M_CONST
  return false
}

export function verifyBitcoinAddress(address: string): boolean {
  if (/^(1|3)[1-9A-HJ-NP-Za-km-z]{25,34}$/.test(address)) {
    return verifyBase58Check(address)
  }
  if (/^(bc1|tb1)[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{25,87}$/i.test(address)) {
    return verifyBech32Address(address)
  }
  return false
}

export const CHAIN_RULES: Record<string, ChainRule> = {
  EVM:  { name: 'Ethereum / Arbitrum / Base / Optimism / Polygon / BNB (EVM)', pattern: /^0x[a-fA-F0-9]{40}$/, requiresMemo: false, memoName: 'None' },
  BTC:  { name: 'Bitcoin (Legacy Base58Check / SegWit Bech32 / Taproot Bech32m)', pattern: /^(1[a-km-zA-HJ-NP-Z1-9]{25,34}|3[a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{25,87})$/i, requiresMemo: false, memoName: 'None' },
  SOL:  { name: 'Solana (Ed25519 Base58)', pattern: /^[1-9A-HJ-NP-Za-km-z]{32,44}$/, requiresMemo: false, memoName: 'SPL Memo (Optional)' },
  XRP:  { name: 'XRP Ledger (XRPL)', pattern: /^r[1-9A-HJ-NP-Za-km-z]{24,34}$/, requiresMemo: true, memoName: 'Destination Tag (32-bit uint)', memoPattern: /^[0-9]{1,10}$/ },
  XLM:  { name: 'Stellar Lumens (StrKey)', pattern: /^G[A-Z2-7]{55}$/, requiresMemo: true, memoName: 'Stellar Memo (up to 28 bytes)', memoPattern: /^.{1,28}$/ },
  ATOM: { name: 'Cosmos Hub (Bech32)', pattern: /^cosmos1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{38}$/, requiresMemo: true, memoName: 'Cosmos Memo', memoPattern: /^.{1,256}$/ },
  TON:  { name: 'The Open Network (TON)', pattern: /^((EQ|UQ)[A-Za-z0-9_-]{46}|(0|-1):[a-fA-F0-9]{64})$/, requiresMemo: true, memoName: 'TON Comment / Memo Tag', memoPattern: /^.{1,120}$/ },
  TRX:  { name: 'TRON (TVM Base58Check)', pattern: /^T[1-9A-HJ-NP-Za-km-z]{33}$/, requiresMemo: false, memoName: 'None' },
  SUI:  { name: 'Sui Network', pattern: /^0x[a-fA-F0-9]{64}$/, requiresMemo: false, memoName: 'None' },
  APT:  { name: 'Aptos Network', pattern: /^0x[a-fA-F0-9]{1,64}$/, requiresMemo: false, memoName: 'None' },
  HBAR: { name: 'Hedera Hashgraph', pattern: /^0\.0\.[1-9][0-9]{0,9}$/, requiresMemo: true, memoName: 'Hedera Memo (up to 100 bytes)', memoPattern: /^.{1,100}$/ },
  EOS:  { name: 'EOSIO / Vaulta', pattern: /^[a-z1-5.]{1,12}$/, requiresMemo: true, memoName: 'EOS Memo', memoPattern: /^.{1,256}$/ }
}

export function detectAddressPoisoning(candidate: string, trusted: string): boolean {
  const a = (candidate || '').trim()
  const b = (trusted || '').trim()
  if (!a || !b || a.toLowerCase() === b.toLowerCase() || a.length < 12 || b.length < 12) return false
  return a.slice(0, 5).toLowerCase() === b.slice(0, 5).toLowerCase() && a.slice(-4).toLowerCase() === b.slice(-4).toLowerCase()
}

export function validateCryptoAddress(chain: string, address: string, memo = '', trustedAddress = ''): ValidationResult {
  const code = (chain || '').trim().toUpperCase()
  const rule = CHAIN_RULES[code]
  if (!rule) {
    return { valid: false, code: 'UNSUPPORTED_CHAIN', chain: code, message: `Unsupported blockchain ticker: ${code}` }
  }
  const cleanAddr = (address || '').trim()
  const cleanMemo = (memo || '').trim()
  if (!cleanAddr || !rule.pattern.test(cleanAddr)) {
    return { valid: false, code: 'INVALID_ADDRESS_SYNTAX', chain: code, message: `Invalid ${rule.name} wallet address format.` }
  }
  if (code === 'BTC' && !verifyBitcoinAddress(cleanAddr)) {
    return { valid: false, code: 'INVALID_CHECKSUM', chain: code, message: 'Bitcoin Base58Check / Bech32(m) checksum verification failed.' }
  }
  if (rule.requiresMemo) {
    if (!cleanMemo) {
      return { valid: false, code: 'MISSING_MANDATORY_MEMO', chain: code, message: `${code} custodial transfers require a mandatory ${rule.memoName}.` }
    }
    if (rule.memoPattern && !rule.memoPattern.test(cleanMemo)) {
      return { valid: false, code: 'INVALID_MEMO_FORMAT', chain: code, message: `Invalid ${rule.memoName} format for ${code}.` }
    }
  }
  if (trustedAddress && detectAddressPoisoning(cleanAddr, trustedAddress)) {
    return {
      valid: false,
      code: 'ADDRESS_POISONING_ALERT',
      chain: code,
      message: 'CRITICAL ALERT: Candidate address matches prefix & suffix of trusted reference address while differing in middle bytes.'
    }
  }
  return { valid: true, code: 'VALID_VERIFIED', chain: code, message: `Verified valid ${rule.name} address and routing configuration.` }
}

export function useCryptoAddressValidator() {
  return {
    CHAIN_RULES,
    validateAddress: validateCryptoAddress,
    verifyBitcoinAddress,
    detectAddressPoisoning
  }
}
