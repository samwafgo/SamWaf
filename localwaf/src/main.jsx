import Vue from 'vue';
import VueRouter from 'vue-router';
import { sync } from 'vuex-router-sync';
import TDesign from 'tdesign-vue';
import VueClipboard from 'vue-clipboard2';
import axiosInstance from '@/utils/request';
import App from './App.vue';
import router from './router';
import zhConfig from 'tdesign-vue/es/locale/zh_CN';
// import enConfig from 'tdesign-vue/es/locale/en_US'; // 英文多语言配置

import 'tdesign-vue/es/style/index.css';
import '@/style/index.less';

import './permission';
import store from './store';

Vue.use(VueRouter);
Vue.use(TDesign);
Vue.use(VueClipboard);

Vue.component('t-page-header');

Vue.prototype.$request = axiosInstance;

const originPush = VueRouter.prototype.push;
VueRouter.prototype.push = function push(location) {
  return originPush.call(this, location).catch((err) => err);
};

const originReplace = VueRouter.prototype.replace;
VueRouter.prototype.replace = function replace(location) {
  return originReplace.call(this, location).catch((err) => err);
};

Vue.config.productionTip = false;
sync(store, router);
new Vue({
  router,
  store,
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  render: (h) => (
    <div>
      {/* 可以通过config-provider提供全局（多语言、全局属性）配置，如 
      <t-config-provider globalConfig={enConfig}> */}
      <t-config-provider globalConfig={zhConfig}>
        <App />
      </t-config-provider>
    </div>
  ),
}).$mount('#app');
