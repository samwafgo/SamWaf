export interface msgDataItem {
  id: string;
  content: string;
  type: string;
  status: boolean;
  collected: boolean;
  date: string;
  quality: string;
}
// 定义的state初始值
const state: { msgData: Array<msgDataItem> } = {
  msgData: [
    {
      id: '123',
      content: '腾讯大厦一楼改造施工项目 已通过审核！',
      type: '合同动态',
      status: true,
      collected: false,
      date: '2021-01-01 08:00',
      quality: 'high',
    },
    {
      id: '124',
      content: '三季度生产原材料采购项目 开票成功！',
      type: '票务动态',
      status: true,
      collected: false,
      date: '2021-01-01 08:00',
      quality: 'low',
    },
    {
      id: '125',
      content: '2021-01-01 10:00的【国家电网线下签约】会议即将开始，请提前10分钟前往 会议室1 进行签到！',
      type: '会议通知',
      status: true,
      collected: false,
      date: '2021-01-01 08:00',
      quality: 'middle',
    },
    {
      id: '126',
      content: '一季度生产原材料采购项目 开票成功！',
      type: '票务动态',
      status: true,
      collected: false,
      date: '2021-01-01 08:00',
      quality: 'low',
    },
    {
      id: '127',
      content: '二季度生产原材料采购项目 开票成功！',
      type: '票务动态',
      status: true,
      collected: false,
      date: '2021-01-01 08:00',
      quality: 'low',
    },
    {
      id: '128',
      content: '三季度生产原材料采购项目 开票成功！',
      type: '票务动态',
      status: true,
      collected: false,
      date: '2021-01-01 08:00',
      quality: 'low',
    },
  ],
};

const mutations = {
  setMsgData(state, data) {
    // eslint-disable-next-line no-param-reassign
    state.msgData = data;
  },
};

const getters = {
  unreadMsg: (state) => state.msgData.filter((item) => item.status),
  readMsg: (state) => state.msgData.filter((item) => !item.status),
};

const actions = {};

export default {
  namespaced: true,
  state,
  mutations,
  actions,
  getters,
};
