# nuxt-crypto-address-validator

Zero-dependency **Nuxt 3 & Nuxt 4** module, auto-imported composable (`useCryptoAddressValidator`), and Nitro server utility for multi-chain cryptocurrency wallet address syntax validation, mandatory **Memo / Destination Tag** routing checks, and **address-poisoning** lookalike defense across **46+ blockchains**.

Maintained by [AllSwap Security Labs](https://allswap.io) and built to power interactive verification workflows alongside the [AllSwap Online Address & Memo Validator](https://allswap.io/tools/address-validator).

## Features

- **Nuxt 3 & Nuxt 4 Ready:** Compatible with `nuxt >= 3.0.0` via `@nuxt/kit` (`defineNuxtModule`) with TypeScript support out of the box.
- **Zero Runtime Dependencies:** Pure TypeScript syntax, casing/checksum heuristics, memo enforcement, and lookalike screening.
- **46+ Blockchains Supported:** Covers EVM L1/L2 networks, UTXO chains (Bitcoin, Litecoin, Dogecoin, Bitcoin Cash, Dash), Solana, TRON, TON, Sui, Aptos, Cardano, Polkadot, NEAR, Monero, and Cosmos/IBC ecosystems.
- **Mandatory Memo / Destination Tag Guardrails:** Prevents silent deposit loss on custodial-routed networks (**XRP**, **XLM**, **ATOM**, **OSMO**, **INJ**, **TIA**, **SEI**, **TON**, **EOS**, **HBAR**).
- **Address-Poisoning Defense:** `detectAddressPoisoning(candidate, trusted)` flags spoofed addresses sharing leading/trailing characters (`>= 4` prefix and `>= 4` suffix chars) while differing in middle bytes.
- **Client & Nitro Server Support:** Auto-imports `useCryptoAddressValidator()` in Vue components and `validateCryptoAddress` in Nitro server routes.

## Installation

```bash
npm install nuxt-crypto-address-validator
# or
pnpm add nuxt-crypto-address-validator
```

## Setup in `nuxt.config.ts`

```ts
export default defineNuxtConfig({
  modules: [
    'nuxt-crypto-address-validator',
  ],
  cryptoAddressValidator: {
    strictChecksum: true,
    enablePoisoningDetection: true,
    requireMemoOnTaggedChains: true,
  },
})
```

## Usage in Vue 3 / Nuxt Components

```vue
<script setup lang="ts">
const { validateAddress, detectAddressPoisoning } = useCryptoAddressValidator()

const chain = ref('XRP')
const destinationAddress = ref('rEb8TK3gBgk5auZkwc6sHnwrGVJH8DuaLh')
const destinationTag = ref('104728591')
const trustedAddress = ref('')

const validation = computed(() =>
  validateAddress(
    chain.value,
    destinationAddress.value,
    destinationTag.value,
    trustedAddress.value,
  ),
)

const spoofingCheck = computed(() =>
  detectAddressPoisoning(destinationAddress.value, trustedAddress.value),
)
</script>

<template>
  <div class="validator-card">
    <p>Valid: {{ validation.valid }} ({{ validation.addressFormat }})</p>
    <p v-if="validation.memoRequired">Memo / Tag Required: Yes</p>
    <p v-if="spoofingCheck.suspected" class="warning">
      {{ spoofingCheck.reason }}
    </p>
  </div>
</template>
```

## Supported Blockchains (46+ Networks)

| Ecosystem / Family | Supported Chains & Tickers | Address Format / Standard | Memo / Tag Guard |
| --- | --- | --- | --- |
| **EVM L1 & L2s (24+)** | `ETH`, `ARB`, `OP`, `BASE`, `MATIC`, `POL`, `BSC`, `AVAX`, `FTM`, `LINEA`, `SCROLL`, `ZKSYNC`, `BLAST`, `MANTLE`, `METIS`, `MODE`, `CELO`, `GLMR`, `MOVR`, `CRO`, `KAVA`, `SONIC`, `BERA`, `UNICHAIN`, `GNOSIS`, `ZORA`, `TAIKO` | `0x` 20-byte Hex (EIP-55 check) | Optional |
| **UTXO Networks (5)** | `BTC`, `LTC`, `BCH`, `DOGE`, `DASH` | Legacy, P2SH, Bech32/Taproot, CashAddr | No |
| **Memo-Tagged Networks (10)** | `XRP`, `XLM`, `ATOM`, `OSMO`, `INJ`, `TIA`, `SEI`, `TON`, `EOS`, `HBAR` | Classic/X-Address, StrKey, Bech32, TON, Account ID | **Yes (Warn/Validate)** |
| **Non-EVM L1s (8+)** | `SOL`, `TRX`, `SUI`, `APT`, `NEAR`, `ADA`, `DOT`, `KSM`, `XMR` | Ed25519 Base58, Base58Check, 32-byte Hex, SS58, Shelley | No |

## Related Tools & Documentation

- **Live Online Validator:** [AllSwap Address & Memo Validator](https://allswap.io/tools/address-validator)
- **Protocol Homepage:** [AllSwap Non-Custodial Cross-Chain Aggregator](https://allswap.io)
- **Developer Docs:** [AllSwap Integration & Security Docs](https://allswap.io/docs)
- **Core CLI & C# / Node Library:** [multichain-memo-address-validator](https://github.com/zhangglnuo-art/multichain-memo-address-validator)

## License

[MIT License](./LICENSE) — Copyright (c) 2026 [AllSwap Security Labs](https://allswap.io)
