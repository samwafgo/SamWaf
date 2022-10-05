import { TOKEN_NAME } from '@/config/global';

const InitUserInfo = {
  roles: [],
};

// 定义的state初始值
const state = {
  token: localStorage.getItem(TOKEN_NAME) || 'main_token', // 默认token不走权限
  userInfo: InitUserInfo,
};

const mutations = {
  setToken(state, token) {
    localStorage.setItem(TOKEN_NAME, token);
    state.token = token;
  },
  removeToken(state) {
    localStorage.removeItem(TOKEN_NAME);
    state.token = '';
  },
  setUserInfo(state, userInfo) {
    state.userInfo = userInfo;
  },
};

const getters = {
  token: (state) => state.token,
  roles: (state) => state.userInfo?.roles,
};

const actions = {
  async login({ commit }, userInfo) {
    const mockLogin = async (userInfo) => {
      // 登录请求流程
      console.log(userInfo);
      // const { account, password } = userInfo;
      // if (account !== 'td') {
      //   return {
      //     code: 401,
      //     message: '账号不存在',
      //   };
      // }
      // if (['main_', 'dev_'].indexOf(password) === -1) {
      //   return {
      //     code: 401,
      //     message: '密码错误',
      //   };
      // }
      // const token = {
      //   main_: 'main_token',
      //   dev_: 'dev_token',
      // }[password];
      return {
        code: 200,
        message: '登陆成功',
        data: 'main_token',
      };
    };

    const res = await mockLogin(userInfo);
    if (res.code === 200) {
      commit('setToken', res.data);
    } else {
      throw res;
    }
  },
  async getUserInfo({ commit, state }) {
    const mockRemoteUserInfo = async (token) => {
      if (token === 'main_token') {
        return {
          name: 'td_main',
          roles: ['ALL_ROUTERS'],
        };
      }
      return {
        name: 'td_dev',
        roles: ['UserIndex', 'DashboardBase', 'login'],
      };
    };

    const res = await mockRemoteUserInfo(state.token);

    commit('setUserInfo', res);
  },
  async logout({ commit }) {
    commit('removeToken');
    commit('setUserInfo', InitUserInfo);
  },
};

export default {
  namespaced: true,
  state,
  mutations,
  actions,
  getters,
};
