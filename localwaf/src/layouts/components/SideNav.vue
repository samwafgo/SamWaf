<template>
  <div :class="sideNavCls">
    <t-menu
      width="232px"
      :class="menuCls"
      :theme="theme"
      :value="active"
      :collapsed="collapsed"
      :defaultExpanded="defaultExpanded"
    >
      <template #logo>
        <span v-if="showLogo" :class="`${prefix}-side-nav-logo-wrapper`" @click="() => handleNav('/dashboard/base')">
          <component :is="getLogo" :class="`${prefix}-side-nav-logo-${collapsed ? 't' : 'tdesign'}-logo`" />
        </span>
      </template>
      <menu-content :navData="menu" />
      <template #operations>
        <span class="version-container"> {{ !collapsed && '网站安全' }} {{ getversion.version_name  }}
        <span v-if="getversion.version_release=='false'" style="color:red"> 调试</span></span>
      </template>
    </t-menu>
    <div :class="`${prefix}-side-nav-placeholder${collapsed ? '-hidden' : ''}`"></div>
  </div>
</template>

<script lang="ts">
import Vue from 'vue';
import { mapState, mapGetters } from 'vuex';
import { prefix } from '@/config/global';
import { ClassName } from '@/interface';
import Logo from '@/assets/assets-t-logo.svg';
import LogoFull from '@/assets/assets-logo-full.svg';

import MenuContent from './MenuContent.vue';
import pgk from '../../../package.json';
import { SysVersionApi } from '@/apis/sysinfo';
const MIN_POINT = 992 - 1;

export default Vue.extend({
  name: 'sideNav',
  components: {
    MenuContent,
  },
  props: {
    menu: Array,
    showLogo: {
      type: Boolean,
      default: true,
    },
    isFixed: {
      type: Boolean,
      default: true,
    },
    layout: String,
    headerHeight: {
      type: String,
      default: '64px',
    },
    theme: {
      type: String,
      default: 'light',
    },
    isCompact: {
      type: Boolean,
      default: false,
    },
    maxLevel: {
      type: Number,
      default: 3,
    },
  },
  data() {
    return {
      prefix,
      pgk,
    };
  },
  computed: {
    ...mapState('version', ['version']),
    ...mapGetters('version', ['getversion']),
    defaultExpanded() {
      const path = this.active;
      const parentPath = path.substring(0, path.lastIndexOf('/'));
      return parentPath === '' ? [] : [parentPath];
    },
    iconName(): string {
      return this.$store.state.setting.isSidebarCompact ? 'menu-fold' : 'menu-unfold';
    },
    collapsed(): boolean {
      return this.$store.state.setting.isSidebarCompact;
    },
    sideNavCls(): Array<ClassName> {
      return [
        `${this.prefix}-sidebar-layout`,
        {
          [`${this.prefix}-sidebar-compact`]: this.isCompact,
        },
      ];
    },
    menuCls(): Array<ClassName> {
      return [
        `${this.prefix}-side-nav`,
        {
          [`${this.prefix}-side-nav-no-logo`]: !this.showLogo,
          [`${this.prefix}-side-nav-no-fixed`]: !this.isFixed,
          [`${this.prefix}-side-nav-mix-fixed`]: this.layout === 'mix' && this.isFixed,
        },
      ];
    },
    layoutCls(): Array<ClassName> {
      return [`${this.prefix}-side-nav-${this.layout}`, `${this.prefix}-sidebar-layout`];
    },
    active(): string {
      if (!this.$route.path) {
        return '';
      }
      return this.$route.path
        .split('/')
        .filter((_item: string, index: number) => index <= this.maxLevel && index > 0)
        .map((item: string) => `/${item}`)
        .join('');
    },
    getLogo() {
      if (this.collapsed) {
        return Logo;
      }
      return LogoFull;

    },
  },
  mounted() {
    this.autoCollapsed();
    this.loadversion()
    window.onresize = () => {
      this.autoCollapsed();
    };
  },
  methods: {
    changeCollapsed(): void {
      this.$store.commit('setting/toggleSidebarCompact');
    },
    autoCollapsed(): void {
      const isCompact = window.innerWidth <= MIN_POINT;
      this.$store.commit('setting/showSidebarCompact', isCompact);
    },
    handleNav(url: string) {
      this.$router.push(url);
    },
    loadversion(){
      let that = this;
      SysVersionApi().then((res) => {
            let resdata = res
            console.log(resdata)
            if (resdata.code === 0) {
              console.log(resdata.data)
              that.$store.commit('version/setVersionData', resdata.data);
            }
          })
          .catch((e: Error) => {
            console.log(e);
      })
    },
  },
});
</script>
