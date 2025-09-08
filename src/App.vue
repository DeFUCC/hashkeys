<script setup>
import { ref, computed, reactive, onMounted } from 'vue'
import { useAuth } from './useAuth.js'
import { useStorage } from '@vueuse/core'
import { version } from '../package.json'

const passphrase = ref(' Your long passphrase to derive a key from it or your previously exported master key')
const activeTab = useStorage('activeTab', 'sign')

const auth = useAuth('hd')

const Alice = useAuth('hd')

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

  // P2P: local Alice demo
  toAliceMessage: 'Hello Alice! \\\o/',
  toAliceEnvelope: null,
  toAliceDecryptedByAlice: null,
  fromAliceMessage: 'Hi! Alice here. Nice to meet you!',
  fromAliceEnvelope: null,
  fromAliceDecryptedByMe: null,

  // Identity
  masterKey: null,
  derivedKeys: []
})

const tabs = [
  { id: 'sign', name: 'Sign/Verify', icon: '📝' },
  { id: 'encrypt', name: 'Encrypt/Decrypt', icon: '🔒' },
  { id: 'p2p', name: 'P2P', icon: '🤝' }
]

const login = () => {
  auth.login(passphrase.value)
  if (auth.authenticated) {
    passphrase.value = ''
    activeTab.value = 'sign'
  }
}



const signDemo = async () => {
  try {
    demoData.signResult = await auth.sign({ message: demoData.signText })
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

    demoData.verifyResult = await auth.verify({ message: demoData.verifyText, signature: sig, publicKey: pkIn })
  } catch (error) {
    console.error('Verify failed:', error)
  }
}

const encryptDemo = async () => {
  try {
    demoData.encryptResult = await auth.encrypt({ data: demoData.encryptText })
  } catch (error) {
    console.error('Encrypt failed:', error)
  }
}

const decryptDemo = async () => {
  if (!demoData.encryptResult) return
  try {
    demoData.decryptResult = await auth.decrypt({
      ciphertext: demoData.encryptResult.ciphertext,
      nonce: demoData.encryptResult.nonce
    })
  } catch (error) {
    console.error('Decrypt failed:', error)
  }
}

const showMasterKey = async () => {
  try {
    demoData.masterKey = await auth.getMasterKey()
  } catch (error) {
    console.error('Export failed:', error)
  }
}

async function deriveCustomKey(context) {
  if (!context) return
  try {
    const result = await auth.deriveKey({ context, length: 32 })
    demoData.derivedKeys.push({
      context,
      key: result.derivedKey
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

const customApp = ref('')


async function sendToAlice() {
  if (!auth.authenticated || !Alice.encryptionKey) return
  try {
    const env = await auth.encrypt({ data: demoData.toAliceMessage, recipientPublicKey: Alice.encryptionKey })
    demoData.toAliceEnvelope = { ...env, senderPublicKey: auth.encryptionKey }
    demoData.toAliceDecryptedByAlice = null
  } catch (e) {
    console.error('sendToAlice failed:', e)
  }
}

async function aliceDecryptLast() {
  const env = demoData.toAliceEnvelope
  if (!env) return
  try {
    const res = await Alice.decrypt(env)
    demoData.toAliceDecryptedByAlice = res.decrypted
  } catch (e) {
    console.error('aliceDecryptLast failed:', e)
  }
}

async function aliceReply() {
  if (!Alice.authenticated || !auth.publicKey) return
  try {
    const env = await Alice.encrypt({ data: demoData.fromAliceMessage, recipientPublicKey: auth.encryptionKey })
    demoData.fromAliceEnvelope = { ...env, senderPublicKey: Alice.encryptionKey }
    demoData.fromAliceDecryptedByMe = null
  } catch (e) {
    console.error('aliceReply failed:', e)
  }
}

async function decryptFromAlice() {
  const env = demoData.fromAliceEnvelope
  if (!env) return
  try {
    const res = await auth.decrypt(env)
    demoData.fromAliceDecryptedByMe = res.decrypted
  } catch (e) {
    console.error('decryptFromAlice failed:', e)
  }
}

const shares = ref(4)
const threshold = ref(3)
const splitKey = ref([])
const reKey = ref('')

async function splitSecret() {

  splitKey.value = await auth.getSplitKey({ shares: shares.value, threshold: threshold.value })

}

async function combineKey() {
  reKey.value = await auth.combineKey({ shares: [...splitKey.value] })
}


</script>

<template lang="pug">
.min-h-screen.bg-stone-200.p-4.font-mono

  .max-w-2xl.mx-auto
    .text-center.mb-8.flex.flex-col.gap-2
      .flex.flex-col.gap-4.items-center.justify-center
        img.w-30(src="/logo.svg")
        .text-4xl.font-bold HashKeys

      .text-gray-500 Reactive cryptography for web-apps and p2p identity



    .rounded(v-if="!auth.authenticated")
      .text-center.flex.flex-col.items-center.gap-4
        .flex.flex-wrap.gap-4
          button.hover-bg-yellow-300.bg-yellow-400.transition(
            type="button" 
            @click="createPK()"
            :disabled="auth.loading"
            ) Create Passkey
          button.hover-bg-orange-300.bg-orange-400.transition(
            type="button" 
            @click="auth.passKeyLogin()"
            :disabled="auth.loading"
            ) Use Passkey
        p - or -
        form.flex.flex-col.items-center.gap-3.max-w-sm.w-full(@submit.prevent.stop="login")
          textarea.w-full.text-center.px-4.py-3.border.focus-ring(
          v-model="passphrase" 
            rows="5"
            type="password" 
            placeholder="Enter passphrase"
            @keyup.enter="login"
            :disabled="auth.loading"
          )
          .flex
            button.hover-bg-green-400.bg-green-500.transition(
              type="submit"
              :disabled="auth.loading"
              )  {{ auth.loading ? 'Deriving...' : 'Derive a key' }}

        .text-red-500.mt-2(v-if="auth.error") {{ auth.error }}

        .flex.flex-col.gap-2.bg-white.border.rounded.p-5.text-left.max-w-2xl.mt-6
          h3.text-xl.font-semibold.mb-2 🚀 Get started
          p.text-gray-600.mb-3 Small, reactive crypto toolkit for Vue apps and local-first P2P identity.
          .flex.flex-wrap.gap-3.mb-4
            a.bg-black.text-white.p-2.rounded.hover-opacity-85.flex.items-center.gap-2(target="_blank" href="https://www.npmjs.com/package/hashkeys")
              .i-lucide-box
              span NPM/hashkeys
            a.bg-gray-800.text-white.px-3.py-1.rounded.hover-opacity-85.flex.items-center.gap-2(target="_blank" href="https://github.com/DeFUCC/hashkeys")
              .i-lucide-github
              span DeFUCC/hashkeys
            a.bg-gray-800.text-white.px-3.py-1.rounded.hover-opacity-85.flex.items-center.gap-2(target="_blank" href="https://www.youtube.com/watch?v=88_xE85LZO0")
              .i-lucide-youtube
              span Watch video
          h4.text-xl.font-medium.mb-1 Install
          pre.bg-gray-200.p-3.rounded.text-sm.overflow-x-auto.select-all npm i hashkeys
          pre.bg-gray-200.p-3.rounded.text-sm.overflow-x-auto.select-all.
            import { useAuth } from 'hashkeys'
            const auth = useAuth('hk') // optional custom namespace - 2 lowercase letters
            await auth.login('your passphrase or hkmk1…')
          h4.text-xl.font-medium.mb-1 Basics
          pre.bg-gray-200.p-3.rounded.text-sm.overflow-x-auto.
            // Sign and verify
            const { signature, publicKey } = await auth.sign({message: 'hello world'});
            const { valid } = await auth.verify({message: 'hello world', signature, publicKey});
          pre.bg-gray-200.p-3.rounded.text-sm.overflow-x-auto.
            // Encrypt for yourself, then decrypt
            const { ciphertext, nonce } = await auth.encrypt({data: 'my secret'});
            const { decrypted } = await auth.decrypt({ciphertext, nonce});
          pre.bg-gray-200.p-3.rounded.text-sm.overflow-x-auto.
            // P2P: encrypt to a peer (X25519), then peer decrypts
            const {ciphertext, nonce} = await auth.encrypt({data: 'hi peer', recipientPublicKey:'hkek1…'}); // recipient's encryption key
            // send to peer: include your sender key for E2E
            // on the receiver:
            const msg = await auth.decrypt({ ciphertext, nonce, senderPublicKey: auth.encryptionKey })


    .flex.flex-col.gap-4(v-else)
      .flex.gap-2
        h4.text-lg.font-medium.flex-auto Cryptographic Identity 
        button.text-white.bg-red-800.hover-bg-red-500.active-bg-red-400.ml-auto(
          @click="auth.logout()"
        ) Exit
      .bg-gray-50.border.p-4
        .grid.grid-cols-1.md-grid-cols-2.gap-4
          div
            .text-sm.text-gray-600 Identity Hash:
            .font-mono.text-sm.mt-1.break-all {{ auth.identity }}
          div
            .text-sm.text-gray-600 Public Key:
            .font-mono.text-sm.mt-1.break-all {{ auth.publicKey }}
          div
            .text-sm.text-gray-600 Curve:
            .font-mono.text-sm.mt-1 {{ auth.curve || 'ed25519' }}
          div
            .text-sm.text-gray-600 Encryption Key:
            .font-mono.text-sm.mt-1.break-all {{ auth.encryptionKey || 'Same as public key' }}

      .flex.flex-col.gap-4
        .flex.items-center.justify-between
          h4.text-lg.font-medium Master Key Export
          button.bg-yellow-600.text-white.hover-bg-yellow-700.gap-2.flex(
            @click="demoData.masterKey ? demoData.masterKey = null : showMasterKey()"
          ) 
            span {{ demoData.masterKey ? "^" : "v" }}
            span Key Backup

        .flex.flex-col.gap-2(v-if="demoData.masterKey")

          .bg-yellow-50.border.border-yellow-200.p-4
            .font-medium.text-yellow-800 ⚠️ Keep this secret and safe!
            .mt-2
              .font-mono.text-sm.bg-white.p-4.rounded.break-all.select-all.overflow-hidden.blur-10.hover-blur-0.transition-2000 {{ demoData.masterKey }}
              button.mt-2.bg-blue-600.text-white.rounded.active-bg-blue-500.hover-bg-blue-700(
                @click="copy(demoData.masterKey)"
              ) 📋 Copy

          .bg-green-50.border.border-green-200.p-4.gap-2(v-show="activeTab === 'sign'")
            label 
              .text-lg Shares: {{ shares }}
              input(type="range" v-model="shares" min="2" max="12")
            label Threshold
              input(type="range" v-model="threshold" min="2" :max="shares")
            button(@click="splitSecret") SPLIT
            .flex-col.flex.gap-8
              .flex.p-1.break-all(v-for="share in splitKey" :key="share") {{ share }}

            button(@click="combineKey") Combine
            .text-sm {{ reKey }}


        .flex.items-center.justify-between.gap-2
          h4.text-lg.font-medium Key Derivation
          input.min-w-2px.p-2(v-model="customApp" placeholder="Your context name")
          button.bg-green-600.text-white.hover-bg-green-700.disabled-op-50(
            @click="deriveCustomKey(customApp)" :disabled="!customApp"
          ) New App Key

        .space-y-2(v-if="demoData.derivedKeys.length")
          div.bg-gray-50.border.p-3(
            v-for="(key, i) in demoData.derivedKeys" :key="i"
            )
            .text-sm.text-gray-600 Context: 
              code {{ key.context }}
            .font-mono.text-sm.py-4.overflow-x-scroll {{ key.key }}



      .flex.flex-wrap.gap-2.mb-6.justify-stretch.w-full
        button.transition.font-medium.flex-auto(
          v-for="tab in tabs" :key="tab.id"
          @click="activeTab = tab.id"
          :class="activeTab === tab.id ? 'bg-blue-600 text-white shadow-lg' : 'bg-white hover-bg-blue-50'"
          ) {{ tab.icon }} {{ tab.name }}


      // Tab Content
      .bg-white.shadow-lg.p-6

        .flex.flex-col.gap-2(v-show="activeTab === 'sign'")
          h3.text-2xl.mb-4 ✍️ Digital Signatures
          .space-y-4
            div
              label.block.font-medium.mb-2 Message to Sign:
              textarea.w-full.p-3.border.resize-none(
                v-model="demoData.signText" 
                rows="3"
                placeholder="Enter message to sign..."
              )

            button.bg-green-600.text-white.hover-bg-green-700(
              @click="signDemo"
            ) 🖊️ Sign Message

            div(v-if="demoData.signResult")
              .bg-green-50.border.border-green-200.p-4
                .font-medium.text-green-800 ✅ Signature Created
                .mt-2.space-y-2
                  div
                    .text-sm.text-gray-600 Signature:
                    .font-mono.text-sm.bg-gray-100.p-2.rounded.break-all {{ demoData.signResult.signature }}
                  div  
                    .text-sm.text-gray-600 Public Key:
                    .font-mono.text-sm.bg-gray-100.p-2.rounded.break-all {{ demoData.signResult.publicKey }}


          h3.text-2xl.mb-4 ✅ Signature Verification
          .space-y-4
            div
              label.block.font-medium.mb-2 Message:
              textarea.w-full.p-3.border(v-model="demoData.verifyText" rows="2")

            div
              label.block.font-medium.mb-2 Signature:
              input.w-full.p-3.border.font-mono.text-sm(
                v-model="demoData.verifySignature"
                placeholder="Paste signature bech32 hksg..."
              )

            div
              label.block.font-medium.mb-2 Public Key:
              input.w-full.p-3.border.font-mono.text-sm(
                v-model="demoData.verifyPublicKey"
                placeholder="Paste public key bech32 hkpk... (or leave empty to use yours)"
              )

            button.bg-blue-600.text-white.hover-bg-blue-700(
              @click="verifyDemo"
            ) 🔍 Verify Signature

            div(v-if="demoData.verifyResult !== null")
              .border.p-4(
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
              textarea.w-full.p-3.border(
                v-model="demoData.encryptText" 
                rows="3"
                placeholder="Enter sensitive data..."
              )

            .flex.gap-2
              button.px-6.py-2.bg-purple-600.text-white.hover-bg-purple-700(
                @click="encryptDemo"
              ) 🔐 Encrypt

              button.px-6.py-2.bg-orange-600.text-white.hover-bg-orange-700(
                @click="decryptDemo"
                :disabled="!demoData.encryptResult"
              ) 🔓 Decrypt

            div(v-if="demoData.encryptResult")
              .bg-blue-50.border.border-blue-200.p-4
                .font-medium.text-blue-800 🔐 Encrypted Data
                .mt-2.space-y-2
                  div
                    .text-sm.text-gray-600 Cipher:
                    .font-mono.text-sm.bg-white.p-2.rounded.break-all {{ demoData.encryptResult.ciphertext }}
                  div
                    .text-sm.text-gray-600 Nonce:
                    .font-mono.text-sm.bg-white.p-2.rounded {{ demoData.encryptResult.nonce }}

            div(v-if="demoData.decryptResult")
              .bg-green-50.border.border-green-200.p-4
                .font-medium.text-green-800 ✅ Decrypted Data
                .mt-2.bg-white.p-3.rounded.font-mono {{ demoData.decryptResult.decrypted }}

        .flex.flex-col.gap-4(v-show="activeTab === 'p2p'")
          h3.text-2xl.mb-4 🤝 P2P Secure Channel

          h3.text-xl.mt-8.mb-2 🧪 Local Alice (second account)
          .bg-gray-50.border.p-4.rounded
            .flex.flex-wrap.items-center.gap-2
              button.bg-slate-800.text-white.hover-bg-slate-700(:disabled="Alice.loading || Alice.authenticated" @click="Alice.login(`alice-secret`)" v-if="!Alice.authenticated") ▶️ Spawn Alice
              span.text-sm.text-gray-600(v-if="Alice.loading") Starting Alice…
            .mt-3.grid.grid-cols-1.gap-2(v-if="Alice.authenticated")
              div
                .text-sm.text-gray-600 Alice Identity:
                .font-mono.text-sm.mt-1.break-all {{ Alice.identity }}
              div
                .text-sm.text-gray-600 Alice Public Key:
                .font-mono.text-sm.mt-1.break-all {{ Alice.publicKey }}
              div
                .text-sm.text-gray-600 Alice Encryption Key:
                .font-mono.text-sm.mt-1.break-all {{ Alice.encryptionKey }}

          h4.text-lg.font-medium You ➜ Alice

          textarea.w-full.p-3.border(v-model="demoData.toAliceMessage" rows="2" placeholder="Type a message for Alice")
          .flex.gap-2
            button.bg-pink-600.text-white.hover-bg-pink-700(:disabled="!Alice.authenticated" @click="sendToAlice") 📤 Encrypt to Alice
            button.bg-emerald-600.text-white.hover-bg-emerald-700(:disabled="!demoData.toAliceEnvelope" @click="aliceDecryptLast") 🧩 Alice decrypts
          div(v-if="demoData.toAliceEnvelope")
            .text-sm.text-gray-600 Envelope to Alice:
            .font-mono.text-sm.bg-white.p-2.rounded.break-all {{ demoData.toAliceEnvelope.ciphertext }}
          div(v-if="demoData.toAliceDecryptedByAlice")
            .bg-emerald-50.border.border-emerald-200.p-3.rounded ✅ Alice read: {{ demoData.toAliceDecryptedByAlice }}

          h4.text-lg.font-medium Alice ➜ You
          .space-y-2
            textarea.w-full.p-3.border(v-model="demoData.fromAliceMessage" rows="2" placeholder="Alice's message to you")
            .flex.gap-2
              button.bg-indigo-600.text-white.hover-bg-indigo-700(:disabled="!Alice.authenticated" @click="aliceReply") 💬 Alice sends
              button.bg-orange-600.text-white.hover-bg-orange-700(:disabled="!demoData.fromAliceEnvelope" @click="decryptFromAlice") 📨 You decrypt
            div(v-if="demoData.fromAliceEnvelope")
              .text-sm.text-gray-600 Envelope from Alice:
              .font-mono.text-sm.bg-white.p-2.rounded.break-all {{ demoData.fromAliceEnvelope.ciphertext }}
            div(v-if="demoData.fromAliceDecryptedByMe")
              .bg-blue-50.border.border-blue-200.p-3.rounded ✅ You read: {{ demoData.fromAliceDecryptedByMe }}



  .text-center.mt-4.text-gray-500.text-sm
    p v.{{ version }} Powered by 
      a.text-blue-600.hover-underline(href="https://paulmillr.com/noble/" target="_blank") Noble Cryptography
      |  • Local-first • Zero-trust • Open Source

</template>

<style lang="postcss">
#app,
html,
body {
  @apply overscroll-y-none;
}

pre {
  @apply max-w-90vw min-w-none
}

.hover-scale-105:hover {
  transform: scale(1.05);
}

.focus-ring:focus {
  @apply ring-2 ring-blue-500 ring-offset-2 outline-none;
}

.transition {
  transition: all 0.2s ease;
}

#app button {
  @apply py-2 px-4 shadow-sm hover-shadow-lg transition;
}
</style>