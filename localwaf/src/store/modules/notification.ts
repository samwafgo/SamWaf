export interface msgDataItem {
  message_id: string;
  message_data: string;
  message_type: string;
  message_unread_status: boolean;
  message_datetime: string;
}
// 定义的state初始值
const state: { msgData: Array<msgDataItem> } = {
  msgData: [  ],
};

const mutations = {
  setMsgData(state, data) {
    // eslint-disable-next-line no-param-reassign
    state.msgData= data;
  },
  addMsgData(state, data) {
    // eslint-disable-next-line no-param-reassign
    state.msgData.push(data) ;
  },
};

const getters = {
  unreadMsg: (state) => state.msgData.filter((item) => item.message_unread_status),
  readMsg: (state) => state.msgData.filter((item) => !item.message_unread_status),
};

const actions = {};

export default {
  namespaced: true,
  state,
  mutations,
  actions,
  getters,
};
