import Vue from "vue";
import VueI18n from "vue-i18n";
import zh_CN from "./zh_CN";
import en_US from "./en_US";
Vue.use(VueI18n);

const i18n = new VueI18n({
  locale: localStorage.getItem("lang") || "zh_CN", // 语言标识
  messages: {
    zh_CN, // 中文语言包
    en_US, // 英文语言包
  },
});

export default i18n;
