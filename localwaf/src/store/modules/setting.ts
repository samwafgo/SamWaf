/* eslint-disable no-param-reassign */
import STYLE_CONFIG from '@/config/style';
import { COLOR_TOKEN, ColorSeries, ColorToken, LIGHT_CHART_COLORS, DARK_CHART_COLORS } from '@/config/color';

// 定义的state初始值
const state = {
  ...STYLE_CONFIG,
  showSettingPanel: false,
  colorList: COLOR_TOKEN,
  chartColors: LIGHT_CHART_COLORS,
};

type IInitStateType = typeof state;

export interface IStateType extends IInitStateType {
  isAsideFooter: boolean;
  showSettingPanel: boolean;
}

// 定义的state的初始值方法，传入state或者额外的方法，然后利用 vuex 的双向数据驱动进行值的改变
// 可通过this.$store.commit(' ')调用，但是触发的是同步事件
const mutations = {
  update(state: IStateType, payload: IStateType) {
    state.showBreadcrumb = payload.showBreadcrumb;
    state.mode = payload.mode;
    state.layout = payload.layout;
    state.isSidebarCompact = payload.isSidebarCompact;
    state.splitMenu = payload.splitMenu;
    state.isFooterAside = payload.isFooterAside;
    state.isSidebarFixed = payload.isSidebarFixed;
    state.isHeaderFixed = payload.isHeaderFixed;
    state.showHeader = payload.showHeader;
    state.showFooter = payload.showFooter;
    state.backgroundTheme = payload.backgroundTheme;
    state.brandTheme = payload.brandTheme;
    state.isUseTabsRouter = payload.isUseTabsRouter;
  },
  toggleSidebarCompact(state: IStateType) {
    state.isSidebarCompact = !state.isSidebarCompact;
  },
  toggleUseTabsRouter(state: IStateType) {
    state.isUseTabsRouter = !state.isUseTabsRouter;
  },
  showSidebarCompact(state: IStateType, payload: boolean) {
    state.isSidebarCompact = payload;
  },
  toggleSettingPanel(state: IStateType, payload: boolean) {
    state.showSettingPanel = payload;
  },
  addColor(state: IStateType, payload: ColorSeries) {
    state.colorList = { ...state.colorList, ...payload };
  },
  changeChartColor(state: IStateType, payload: ColorToken) {
    state.chartColors = { ...payload };
  },
};

const getters = {
  showHeader: (state: IStateType) => state.showHeader,
  showSidebar: (state: IStateType) => state.layout !== 'top',
  showSidebarLogo: (state: IStateType) => state.layout === 'side',
  showHeaderLogo: (state: IStateType) => state.layout !== 'side',
  showFooter: (state: IStateType) => state.showFooter,
  isUseTabsRouter: (state: IStateType) => state.isUseTabsRouter,
  mode: (state: IStateType) => {
    if (state.mode === 'auto') {
      const media = window.matchMedia('(prefers-color-scheme:dark)');
      if (media.matches) {
        return 'dark';
      }
      return 'light';
    }
    return state.mode;
  },
};

const actions = {
  changeTheme({ commit, dispatch }, payload: IStateType) {
    dispatch('changeMode', payload);
    dispatch('changeBrandTheme', payload);
    commit('update', payload);
  },
  changeMode({ commit }, payload: IStateType) {
    let theme = payload.mode;
    if (payload.mode === 'auto') {
      const media = window.matchMedia('(prefers-color-scheme:dark)');
      if (media.matches) {
        theme = 'dark';
      } else {
        theme = 'light';
      }
    }
    const isDarkMode = theme === 'dark';

    document.documentElement.setAttribute('theme-mode', isDarkMode ? 'dark' : '');

    commit('changeChartColor', isDarkMode ? DARK_CHART_COLORS : LIGHT_CHART_COLORS);
  },
  changeBrandTheme(_: { state: IStateType }, payload: IStateType) {
    const { brandTheme } = payload;

    document.documentElement.setAttribute('theme-color', brandTheme);
  },
};

export default {
  namespaced: true,
  state,
  mutations,
  actions,
  getters,
};
