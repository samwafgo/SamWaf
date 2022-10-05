<template>
  <div>
    <template v-if="setting.layout === 'side'">
      <t-layout key="side">
        <t-aside><layout-sidebar /></t-aside>
        <t-layout>
          <t-header><layout-header /></t-header>
          <t-content><layout-content /></t-content>
        </t-layout>
      </t-layout>
    </template>
    <template v-else-if="setting.layout === 'top'">
      <t-layout key="top">
        <t-header> <layout-header /></t-header>
        <t-content><layout-content /></t-content>
      </t-layout>
    </template>
    <template v-else>
      <t-layout key="mix">
        <t-header><layout-header /></t-header>
        <t-layout>
          <t-aside><layout-sidebar /></t-aside>
          <t-content><layout-content /></t-content>
        </t-layout>
      </t-layout>
    </template>
    <setting />
  </div>
</template>

<script lang="ts">
import Vue from 'vue';
import { mapGetters } from 'vuex';

import LayoutHeader from './components/LayoutHeader.vue';
import LayoutContent from './components/LayoutContent.vue';
import LayoutSidebar from './components/LayoutSidebar.vue';
import Setting from './setting.vue';

import { prefix } from '@/config/global';
import { SettingType } from '@/interface';

import '@/style/layout.less';

const name = `${prefix}-base-layout`;

export default Vue.extend({
  name,
  components: {
    LayoutHeader,
    LayoutContent,
    LayoutSidebar,
    Setting,
  },
  computed: {
    ...mapGetters({
      tabRouterList: 'tabRouter/tabRouterList',
    }),
    setting(): SettingType {
      return this.$store.state.setting;
    },
  },
  watch: {
    $route(newRoute) {
      // 监听路由变化往多标签新增
      const {
        path,
        meta: { title },
        name,
      } = newRoute;
      this.$store.commit('tabRouter/appendTabRouterList', { path, title, name, isAlive: true });
    },
  },
  // 如果不需要持久化标签页可以注释掉created和destroyed的内容
  created() {
    window.addEventListener('beforeunload', this.setTabRouterListCache);
  },
  destroyed() {
    window.removeEventListener('beforeunload', this.setTabRouterListCache);
  },
  mounted() {
    const {
      path,
      meta: { title },
      name,
    } = this.$route;

    if (localStorage.getItem('tabRouterList')) this.getTabRouterListCache();
    this.$store.commit('tabRouter/appendTabRouterList', { path, title, name, isAlive: true });
  },
  methods: {
    getTabRouterListCache() {
      this.$store.commit('tabRouter/initTabRouterList', JSON.parse(localStorage.getItem('tabRouterList')));
    },
    setTabRouterListCache() {
      localStorage.setItem('tabRouterList', JSON.stringify(this.tabRouterList));
    },
  },
});
</script>
