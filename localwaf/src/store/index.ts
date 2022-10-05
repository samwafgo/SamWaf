import Vue from 'vue';
import Vuex from 'vuex';
import user from './modules/user';
import notification from './modules/notification';
import setting from './modules/setting';
import permission from './modules/permission';
import tabRouter from './modules/tab-router'; // 多标签管理

Vue.use(Vuex);

const store = new Vuex.Store({
  strict: import.meta.env.MODE === 'release',
  modules: {
    user,
    setting,
    notification,
    permission,
    tabRouter,
  },
});

export default store;
