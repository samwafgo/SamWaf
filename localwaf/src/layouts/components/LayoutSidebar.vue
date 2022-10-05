<template>
  <side-nav
    v-if="showSidebar"
    :showLogo="showSidebarLogo"
    :layout="setting.layout"
    :isFixed="setting.isSidebarFixed"
    :menu="sideMenu"
    :theme="mode"
    :isCompact="setting.isSidebarCompact"
    :maxLevel="setting.splitMenu ? 2 : 3"
  />
</template>

<script lang="ts">
import Vue from 'vue';
import { mapGetters } from 'vuex';
import SideNav from './SideNav.vue';

import { SettingType } from '@/interface';

export default Vue.extend({
  name: 'LayoutSidebar',
  components: {
    SideNav,
  },
  computed: {
    ...mapGetters({
      showSidebar: 'setting/showSidebar',
      showSidebarLogo: 'setting/showSidebarLogo',
      mode: 'setting/mode',
      menuRouters: 'permission/routers',
    }),
    setting(): SettingType {
      return this.$store.state.setting;
    },
    sideMenu() {
      const { layout, splitMenu } = this.$store.state.setting;
      let { menuRouters } = this;
      if (layout === 'mix' && splitMenu) {
        menuRouters.forEach((menu) => {
          if (this.$route.path.indexOf(menu.path) === 0) {
            menuRouters = menu.children.map((subMenu) => ({ ...subMenu, path: `${menu.path}/${subMenu.path}` }));
          }
        });
      }
      return menuRouters;
    },
  },
});
</script>
<style lang="less" scoped></style>
