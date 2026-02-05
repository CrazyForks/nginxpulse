import { createApp } from 'vue';
import App from './App.vue';
import router from './router';
import Vant from 'vant';
import 'vant/lib/index.css';
import { getCurrentLocale, i18n, setLocale } from '@/i18n';
import { getMobileBasePathWithSlash } from '@/utils';

import '@/styles/vendor.scss';
import '@/styles/index.scss';
import './styles/mobile.scss';

const app = createApp(App);
app.use(i18n);
app.use(router);
const initialLocale = getCurrentLocale();
app.use(Vant);
setLocale(initialLocale, false);
app.mount('#app');

const isPwaEnabled = (() => {
  const value = (window as unknown as Record<string, unknown>).__NGINXPULSE_MOBILE_PWA_ENABLED__;
  if (typeof value === 'boolean') {
    return value;
  }
  if (typeof value === 'string') {
    return value.toLowerCase() === 'true';
  }
  return false;
})();

if (import.meta.env.PROD && 'serviceWorker' in navigator && isPwaEnabled) {
  window.addEventListener('load', () => {
    const scope = getMobileBasePathWithSlash();
    navigator.serviceWorker.register(`${scope}sw.js`, { scope });
  });
}
