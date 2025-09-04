<script setup>
import { ref, computed, reactive, onMounted } from 'vue'
import auth from './useAuth.js'

const passphrase = ref('demo-password-123')
const activeTab = ref('sign')

const demoData = reactive({
  // Signing
  signText: 'Hello, cryptographic world!',
  signResult: null,

  // Verification 
  verifyText: '',
  verifySignature: '',
  verifyPublicKey: '',
  verifyResult: null,

  // Encryption (self)
  encryptText: 'My secret diary entry...',
  encryptResult: null,
  decryptResult: null,

  // P2P messaging
  peerPublicKey: '',
  p2pMessage: 'Secret message to peer',
  p2pResult: null,
  p2pChannel: null,
  p2pDecrypted: null,

  // Identity
  masterKey: null,
  derivedKeys: []
})

const tabs = [
  { id: 'sign', name: 'Sign', icon: '📝' },
  { id: 'verify', name: 'Verify', icon: '🔍' },
  { id: 'encrypt', name: 'Encrypt', icon: '🔒' },
  { id: 'p2p', name: 'P2P', icon: '🤝' }
]

const login = async () => {
  await auth.login(passphrase.value)
  if (auth.authenticated) {
    passphrase.value = ''
    activeTab.value = 'sign'
  }
}

const logout = async () => {
  await auth.logout()
}

const signDemo = async () => {
  try {
    demoData.signResult = await auth.sign(demoData.signText)
    // Auto-populate verify fields
    demoData.verifyText = demoData.signText
    demoData.verifySignature = demoData.signResult.signature
    demoData.verifyPublicKey = demoData.signResult.publicKey
  } catch (error) {
    console.error('Sign failed:', error)
  }
}

const verifyDemo = async () => {
  try {
    // Fill from latest sign/auth if missing
    const sig = (demoData.verifySignature || demoData.signResult?.signature || '').trim().toLowerCase()
    const pkIn = (demoData.verifyPublicKey || auth.publicKey || '').trim().toLowerCase()

    if (!sig || !pkIn) {
      demoData.verifyResult = { valid: false }
      console.warn('Missing signature or public key for verification')
      return
    }

    demoData.verifyResult = await auth.verify(
      demoData.verifyText,
      sig,
      pkIn
    )
  } catch (error) {
    console.error('Verify failed:', error)
  }
}

const encryptDemo = async () => {
  try {
    demoData.encryptResult = await auth.encrypt(demoData.encryptText)
  } catch (error) {
    console.error('Encrypt failed:', error)
  }
}

const decryptDemo = async () => {
  if (!demoData.encryptResult) return
  try {
    demoData.decryptResult = await auth.decrypt(
      demoData.encryptResult.ciphertext,
      demoData.encryptResult.nonce
    )
  } catch (error) {
    console.error('Decrypt failed:', error)
  }
}

const setupP2P = async () => {
  if (!demoData.peerPublicKey) return
  try {
    // Minimal secure channel using recipient's public key with X25519 + XChaCha20-Poly1305
    demoData.p2pChannel = {
      async send(message) {
        const res = await auth.encrypt(message, demoData.peerPublicKey)
        return {
          from: auth.publicKey,
          ciphertext: res.ciphertext,
          nonce: res.nonce,
          algorithm: res.algorithm
        }
      }
    }
  } catch (error) {
    console.error('P2P setup failed:', error)
  }
}

const sendP2P = async () => {
  if (!demoData.p2pChannel) return
  try {
    demoData.p2pResult = await demoData.p2pChannel.send(demoData.p2pMessage)
    demoData.p2pDecrypted = null
  } catch (error) {
    console.error('P2P send failed:', error)
  }
}

const decryptP2P = async () => {
  const env = demoData.p2pResult
  if (!env) return
  try {
    // Decrypt using sender's public key and provided algorithm (xchacha20poly1305-x25519)
    const res = await auth.decrypt(env.ciphertext, env.nonce, env.from, env.algorithm)
    demoData.p2pDecrypted = res.decrypted
  } catch (error) {
    console.error('P2P decrypt failed:', error)
  }
}

const showMasterKey = async () => {
  try {
    demoData.masterKey = await auth.getMasterKey()
  } catch (error) {
    console.error('Export failed:', error)
  }
}

const deriveCustomKey = async () => {
  try {
    const context = `app_${Date.now()}`
    const result = await auth.deriveKey(context, 32)
    demoData.derivedKeys.push({
      context,
      key: result.derivedKey.slice(0, 32) + '...'
    })
  } catch (error) {
    console.error('Key derivation failed:', error)
  }
}

const copy = (text) => {
  navigator.clipboard.writeText(text)
}

async function createPK() {
  auth.passKeyAuth(await window.prompt('Enter your new passkey username'))
}

onMounted(() => {
  auth.recall()
})
</script>

<template lang="pug">
.min-h-screen.bg-stone-200.p-4.font-mono

  .max-w-2xl.mx-auto
    .text-center.mb-8.flex.flex-col.gap-2
      .flex.flex-col.gap-4.items-center.justify-center
        img.w-30(src="/logo.svg")
        .text-4xl.font-bold HashKeys

      .text-gray-500 Reactive cryptography for web-apps and p2p identity

    .rounded-xl(v-if="!auth.authenticated")
      .text-center.flex.flex-col.items-center.gap-4
        .flex.flex-wrap.gap-4
          button.p-2.rounded-lg.hover-bg-blue-400.bg-blue-500.transition(
            type="button" 
            @click="createPK()"
            :disabled="auth.loading"
            ) 🫆   Create PassKey
          button.p-2.rounded-lg.hover-bg-blue-400.bg-blue-500.transition(
            type="button" 
            @click="auth.passKeyLogin()"
            :disabled="auth.loading"
            ) 🫆   Use PassKey
        form.flex.flex-col.items-center.gap-3.max-w-sm.mx-auto(@submit.prevent.stop="login")
          input.text-center.px-4.py-3.border.rounded-lg.focus-ring(
          v-model="passphrase" 
            type="password" 
            placeholder="Enter passphrase"
            @keyup.enter="login"
            :disabled="auth.loading"
          )
          .flex
            button.p-2.rounded-lg.hover-bg-green-400.bg-green-500.transition(
              type="submit"
              :disabled="auth.loading"
              )  {{ auth.loading ? 'Logging in...' : 'Login' }}

        .text-red-500.mt-2(v-if="auth.error") {{ auth.error }}


    .flex.flex-col.gap-4(v-else)
      .p-0
        div
          .flex.p-2.gap-2
            h4.text-lg.font-medium.flex-auto Cryptographic Identity 
            button.py-1.px-2.text-white.rounded-lg.bg-red-800.hover-bg-red-500.active-bg-red-400.ml-auto(
              @click="logout"
            ) 🚪 Logout
          .bg-gray-50.border.rounded-lg.p-4
            .grid.grid-cols-1.md-grid-cols-2.gap-4
              div
                .text-sm.text-gray-600 Identity Hash:
                .font-mono.text-xs.mt-1.break-all {{ auth.identity }}
              div
                .text-sm.text-gray-600 Public Key:
                .font-mono.text-xs.mt-1.break-all {{ auth.publicKey }}
              div
                .text-sm.text-gray-600 Curve:
                .font-mono.text-xs.mt-1 {{ auth.curve || 'ed25519' }}
              div
                .text-sm.text-gray-600 Encryption Key:
                .font-mono.text-xs.mt-1.break-all {{ auth.encryptionKey || 'Same as public key' }}

      .p-4.flex.flex-col.gap-4
        .flex.items-center.justify-between.mb-3
          h4.text-lg.font-medium Master Key Export
          button.px-4.py-2.bg-yellow-600.text-white.rounded-lg.hover-bg-yellow-700(
            @click="showMasterKey"
          ) 🔑 Reveal Master Key

        div(v-if="demoData.masterKey")
          .bg-yellow-50.border.border-yellow-200.rounded-lg.p-4
            .font-medium.text-yellow-800 ⚠️ Keep this secret and safe!
            .mt-2
              .font-mono.text-xs.bg-white.p-3.rounded.break-all {{ demoData.masterKey }}
              button.mt-2.px-3.py-1.bg-blue-600.text-white.rounded.hover-bg-blue-700(
                @click="copy(demoData.masterKey)"
              ) 📋 Copy

        // Key Derivation
        div
          .flex.items-center.justify-between.mb-3
            h4.text-lg.font-medium Key Derivation
            button.px-4.py-2.bg-green-600.text-white.rounded-lg.hover-bg-green-700(
              @click="deriveCustomKey"
            ) ➕ Derive New Key

          .space-y-2(v-if="demoData.derivedKeys.length")
            div.bg-gray-50.border.rounded-lg.p-3(
              v-for="(key, i) in demoData.derivedKeys" :key="i"
            )
              .text-sm.text-gray-600 Context: 
                code {{ key.context }}
              .font-mono.text-xs.mt-1 {{ key.key }}



      .flex.flex-wrap.gap-2.mb-6.justify-center
        button.px-4.py-2.rounded-lg.transition.font-medium(
          v-for="tab in tabs" :key="tab.id"
          @click="activeTab = tab.id"
          :class="activeTab === tab.id ? 'bg-blue-600 text-white shadow-lg' : 'bg-white hover-bg-blue-50'"
        ) {{ tab.icon }} {{ tab.name }}


      // Tab Content
      .bg-white.rounded-xl.shadow-lg.p-6

        // Signing Tab
        div(v-show="activeTab === 'sign'")
          h3.text-2xl.mb-4 ✍️ Digital Signatures
          .space-y-4
            div
              label.block.font-medium.mb-2 Message to Sign:
              textarea.w-full.p-3.border.rounded-lg.resize-none(
                v-model="demoData.signText" 
                rows="3"
                placeholder="Enter message to sign..."
              )

            button.px-6.py-2.bg-green-600.text-white.rounded-lg.hover-bg-green-700(
              @click="signDemo"
            ) 🖊️ Sign Message

            div(v-if="demoData.signResult")
              .bg-green-50.border.border-green-200.rounded-lg.p-4
                .font-medium.text-green-800 ✅ Signature Created
                .mt-2.space-y-2
                  div
                    .text-sm.text-gray-600 Signature:
                    .font-mono.text-xs.bg-gray-100.p-2.rounded.break-all {{ demoData.signResult.signature }}
                  div  
                    .text-sm.text-gray-600 Public Key:
                    .font-mono.text-xs.bg-gray-100.p-2.rounded.break-all {{ demoData.signResult.publicKey }}

        // Verify Tab  
        div(v-show="activeTab === 'verify'")
          h3.text-2xl.mb-4 ✅ Signature Verification
          .space-y-4
            div
              label.block.font-medium.mb-2 Message:
              textarea.w-full.p-3.border.rounded-lg(v-model="demoData.verifyText" rows="2")

            div
              label.block.font-medium.mb-2 Signature:
              input.w-full.p-3.border.rounded-lg.font-mono.text-xs(
                v-model="demoData.verifySignature"
                placeholder="Paste signature bech32 igsg..."
              )

            div
              label.block.font-medium.mb-2 Public Key:
              input.w-full.p-3.border.rounded-lg.font-mono.text-xs(
                v-model="demoData.verifyPublicKey"
                placeholder="Paste public key bech32 igpk... (or leave empty to use yours)"
              )

            button.px-6.py-2.bg-blue-600.text-white.rounded-lg.hover-bg-blue-700(
              @click="verifyDemo"
            ) 🔍 Verify Signature

            div(v-if="demoData.verifyResult !== null")
              .border.rounded-lg.p-4(
                :class="demoData.verifyResult.valid ? 'bg-green-50 border-green-200' : 'bg-red-50 border-red-200'"
              )
                .font-medium(
                  :class="demoData.verifyResult.valid ? 'text-green-800' : 'text-red-800'"
                ) {{ demoData.verifyResult.valid ? '✅ Valid Signature' : '❌ Invalid Signature' }}

        // Encryption Tab
        div(v-show="activeTab === 'encrypt'")  
          h3.text-2xl.mb-4 🔒 Data Encryption
          .space-y-4
            div
              label.block.font-medium.mb-2 Data to Encrypt:
              textarea.w-full.p-3.border.rounded-lg(
                v-model="demoData.encryptText" 
                rows="3"
                placeholder="Enter sensitive data..."
              )

            .flex.gap-2
              button.px-6.py-2.bg-purple-600.text-white.rounded-lg.hover-bg-purple-700(
                @click="encryptDemo"
              ) 🔐 Encrypt

              button.px-6.py-2.bg-orange-600.text-white.rounded-lg.hover-bg-orange-700(
                @click="decryptDemo"
                :disabled="!demoData.encryptResult"
              ) 🔓 Decrypt

            div(v-if="demoData.encryptResult")
              .bg-blue-50.border.border-blue-200.rounded-lg.p-4
                .font-medium.text-blue-800 🔐 Encrypted Data
                .mt-2.space-y-2
                  div
                    .text-sm.text-gray-600 Cipher:
                    .font-mono.text-xs.bg-white.p-2.rounded.break-all {{ demoData.encryptResult.ciphertext.slice(0, 100) }}...
                  div
                    .text-sm.text-gray-600 Nonce:
                    .font-mono.text-xs.bg-white.p-2.rounded {{ demoData.encryptResult.nonce }}

            div(v-if="demoData.decryptResult")
              .bg-green-50.border.border-green-200.rounded-lg.p-4
                .font-medium.text-green-800 ✅ Decrypted Data
                .mt-2.bg-white.p-3.rounded.font-mono {{ demoData.decryptResult.decrypted }}

        // P2P Tab
        div(v-show="activeTab === 'p2p'")
          h3.text-2xl.mb-4 🤝 P2P Secure Channel
          .space-y-4
            div
              label.block.font-medium.mb-2 Peer's Public Key:
              input.w-full.p-3.border.rounded-lg.font-mono.text-xs(
                v-model="demoData.peerPublicKey"
                placeholder="Paste peer's public key (igpk... or igek...) for E2E encryption..."
              )
              .text-sm.text-gray-500.mt-1 Your public key: 
                code.bg-gray-100.px-1.rounded {{ auth.publicKey?.slice(0, 20) }}...
                button.ml-2.text-blue-600.hover-underline(@click="copy(auth.publicKey)") copy

            button.px-6.py-2.bg-indigo-600.text-white.rounded-lg.hover-bg-indigo-700(
              @click="setupP2P"
              :disabled="!demoData.peerPublicKey"
            ) 🔗 Setup Secure Channel

            div(v-if="demoData.p2pChannel")
              .bg-green-50.border.border-green-200.rounded-lg.p-4.mb-4
                .font-medium.text-green-800 ✅ Secure channel established!

              div
                label.block.font-medium.mb-2 Secret Message:
                textarea.w-full.p-3.border.rounded-lg(
                  v-model="demoData.p2pMessage"
                  rows="2"
                  placeholder="Enter message to encrypt for peer..."
                )

              .flex.gap-2
                button.px-6.py-2.bg-pink-600.text-white.rounded-lg.hover-bg-pink-700(
                  @click="sendP2P"
                ) 📤 Encrypt Message

                button.px-6.py-2.bg-emerald-600.text-white.rounded-lg.hover-bg-emerald-700(
                  @click="decryptP2P"
                  :disabled="!demoData.p2pResult"
                ) 📥 Decrypt Envelope

              div(v-if="demoData.p2pResult")
                .bg-pink-50.border.border-pink-200.rounded-lg.p-4.mt-4
                  .font-medium.text-pink-800 📦 Encrypted Message Envelope
                  .mt-2.space-y-2
                    div
                      .text-sm.text-gray-600 From:
                      .font-mono.text-xs.bg-white.p-1.rounded {{ demoData.p2pResult.from.slice(0, 20) }}...
                    div
                      .text-sm.text-gray-600 Encrypted Payload:
                      .font-mono.text-xs.bg-white.p-2.rounded.break-all {{ demoData.p2pResult.ciphertext.slice(0, 60) }}...

              div(v-if="demoData.p2pDecrypted")
                .bg-emerald-50.border.border-emerald-200.rounded-lg.p-4.mt-4
                  .font-medium.text-emerald-800 ✅ Decrypted P2P Message
                  .mt-2.bg-white.p-3.rounded.font-mono {{ demoData.p2pDecrypted }}


      .text-center.mt-8.text-gray-500.text-sm
        p Powered by 
          a.text-blue-600.hover-underline(href="https://paulmillr.com/noble/" target="_blank") Noble Cryptography
          |  • Local-first • Zero-trust • Open Source

</template>

<style>
.hover-scale-105:hover {
  transform: scale(1.05);
}

.focus-ring:focus {
  @apply ring-2 ring-blue-500 ring-offset-2 outline-none;
}

.transition {
  transition: all 0.2s ease;
}
</style>