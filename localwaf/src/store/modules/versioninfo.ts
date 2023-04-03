export interface versionItem {
  version: string;
  version_name: string;
  version_release: string;
}
// 定义的state初始值
const state: { version: versionItem } = {
  version: {
    version:"",
    version_name:"",
    version_release:"",
  },
};

const mutations = {
  setVersionData(state, data) {
    // eslint-disable-next-line no-param-reassign
    state.version= data;
  },
};

const getters = {
  getversion:(state) => state.version
};

const actions = {};

export default {
  namespaced: true,
  state,
  mutations,
  actions,
  getters,
};
