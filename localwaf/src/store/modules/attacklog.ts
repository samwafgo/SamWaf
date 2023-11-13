export interface msgAttack {
  currentpage: number;
  searchData: msgAttackSearchData;
}
export interface msgAttackSearchData {
  rule: string;
  action: string;
  src_ip: string;
  host_code: string;
  status_code: string;
}
// 定义的state初始值
const state: { msgData: Array<msgAttack> } = {
  msgData: undefined,
};

const mutations = {
  setAttackMsgData(state, data) {
    // eslint-disable-next-line no-param-reassign
    state.msgData= data;
  },
  addMsgData(state, data) {
    // eslint-disable-next-line no-param-reassign
    state.msgData.push(data) ;
  },
};

const getters = {
  getBeforeData: (state) => state.msgData,
};

const actions = {
  async setAttackMsgData({ commit }, attacklog) {
    commit('setAttackMsgData', attacklog);
  },
};

export default {
  namespaced: true,
  state,
  mutations,
  actions,
  getters,
};
