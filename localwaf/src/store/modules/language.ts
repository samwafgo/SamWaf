// store/modules/language.ts
import { Module } from 'vuex';
import { RootState } from '@/store';

interface LanguageState {
  currentLanguage: string;
}

const getInitialLanguage = (): string => {
  const savedLanguage = localStorage.getItem('lang');
  return savedLanguage || 'zh_CN'; // 默认语言
};

const state: LanguageState = {
  currentLanguage: getInitialLanguage(),
};

const mutations = {
  SET_LANGUAGE(state: LanguageState, language: string) {
    state.currentLanguage = language;
    localStorage.setItem('lang', language); // 保存到 localStorage
  },
};

const actions = {
  switchLanguage({ commit }: { commit: Function }, language: string) {
    commit('SET_LANGUAGE', language);
  },
};

const getters = {
  currentLanguage: (state: LanguageState) => state.currentLanguage,
};

const language: Module<LanguageState, RootState> = {
  namespaced: true,
  state,
  mutations,
  actions,
  getters,
};

export default language;
