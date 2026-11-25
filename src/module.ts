import {
  defineNuxtModule,
  createResolver,
  addImportsDir,
  addServerImportsDir,
} from '@nuxt/kit'

export interface ModuleOptions {
  /**
   * Enable strict EIP-55 / Bech32 checksum enforcement when mixed-case is present.
   * @default true
   */
  strictChecksum?: boolean
  /**
   * Enable prefix+suffix similarity screening for address-poisoning defense.
   * @default true
   */
  enablePoisoningDetection?: boolean
  /**
   * Require destination Memo / Tag on custodial-routed chains (XRP, XLM, ATOM, TON, EOS, HBAR).
   * @default true
   */
  requireMemoOnTaggedChains?: boolean
}

export default defineNuxtModule<ModuleOptions>({
  meta: {
    name: 'nuxt-crypto-address-validator',
    configKey: 'cryptoAddressValidator',
    compatibility: {
      nuxt: '>=3.0.0',
    },
  },
  defaults: {
    strictChecksum: true,
    enablePoisoningDetection: true,
    requireMemoOnTaggedChains: true,
  },
  setup(options, nuxt) {
    const resolver = createResolver(import.meta.url)

    nuxt.options.runtimeConfig.public.cryptoAddressValidator = {
      strictChecksum: options.strictChecksum ?? true,
      enablePoisoningDetection: options.enablePoisoningDetection ?? true,
      requireMemoOnTaggedChains: options.requireMemoOnTaggedChains ?? true,
    }

    // Register auto-imported Vue 3 / Nuxt 3 & 4 composables
    addImportsDir(resolver.resolve('./runtime/composables'))

    // Register Nitro server-side validation utilities
    addServerImportsDir(resolver.resolve('./runtime/server/utils'))
  },
})
