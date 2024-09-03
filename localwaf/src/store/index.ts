import Vue from 'vue';
import Vuex from 'vuex';
import user from './modules/user';
import notification from './modules/notification';
import attacklog from './modules/attacklog';
import version from './modules/versioninfo';
import setting from './modules/setting';
import permission from './modules/permission';
import tabRouter from './modules/tab-router'; // 多标签管理
import language from './modules/language';
Vue.use(Vuex);

const store = new Vuex.Store({
  strict: import.meta.env.MODE === 'release',
  modules: {
    user,
    setting,
    notification,
    attacklog,
    version,
    permission,
    tabRouter,
    language,
  },
});

export default store;
