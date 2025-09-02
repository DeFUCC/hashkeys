import { createApp, vaporInteropPlugin } from "vue";
import App from "./App.vue";

import '@unocss/reset/tailwind.css'
import 'uno.css'

import { createRouter, createWebHashHistory } from "vue-router";


createApp(App)
  .use(vaporInteropPlugin)
  .mount("#app");
