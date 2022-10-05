<template>
  <transition name="fade" mode="out-in">
    <keep-alive :include="this.aliveViews">
      <router-view v-if="!this.isRefreshing" />
    </keep-alive>
  </transition>
</template>
<script lang="ts">
import { mapGetters } from 'vuex';

export default {
  computed: {
    ...mapGetters({
      tabRouterList: 'tabRouter/tabRouterList',
      isRefreshing: 'tabRouter/isRefreshing',
      isUseTabsRouter: 'setting/isUseTabsRouter',
    }),
    aliveViews() {
      return this.tabRouterList.filter((route) => route.isAlive).map((route) => route.name);
    },
  },
};
</script>
<style lang="less" scoped>
@import '@/style/variables';

.fade-leave-active,
.fade-enter-active {
  transition: opacity @anim-duration-slow @anim-time-fn-easing;
}
.fade-enter,
.fade-leave-to {
  opacity: 0;
}
</style>
