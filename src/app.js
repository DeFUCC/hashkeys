import { createApp, vaporInteropPlugin } from "vue";
import App from "./App.vue";

import '@unocss/reset/tailwind.css'
import 'uno.css'


createApp(App)
  .use(vaporInteropPlugin)
  .mount("#app");
