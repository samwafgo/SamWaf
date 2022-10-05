<template>
  <div>
    <template v-for="item in list">
      <template v-if="!item.children || !item.children.length || item.meta?.single">
        <t-menu-item
          :key="item.path"
          v-if="getHref(item)"
          :href="getHref(item)?.[0]"
          :name="item.path"
          :value="item.meta?.single ? item.redirect : item.path"
        >
          <template #icon>
            <t-icon v-if="typeof item.icon === 'string' && item.icon" :name="item.icon" />
            <renderFnIcon :item="item" />
          </template>
          {{ item.title }}
        </t-menu-item>
        <t-menu-item
          :key="item.path"
          v-else
          :name="item.path"
          :value="item.meta?.single ? item.redirect : item.path"
          :to="item.path"
        >
          <template #icon>
            <t-icon v-if="typeof item.icon === 'string' && item.icon" :name="item.icon" />
            <renderFnIcon :item="item" />
          </template>
          {{ item.title }}
        </t-menu-item>
      </template>
      <t-submenu v-else :name="item.path" :value="item.path" :title="item.title" :key="item.path">
        <template #icon>
          <t-icon v-if="typeof item.icon === 'string' && item.icon" :name="item.icon" />
          <renderFnIcon :item="item" />
        </template>
        <menu-content v-if="item.children" :nav-data="item.children" />
      </t-submenu>
    </template>
  </div>
</template>

<script lang="ts">
import Vue, { PropType } from 'vue';

import { prefix } from '@/config/global';
import { MenuRoute } from '@/interface';

const getMenuList = (list: MenuRoute[], basePath?: string): MenuRoute[] => {
  if (!list) {
    return [];
  }
  return list
    .map((item) => {
      const path = basePath ? `${basePath}/${item.path}` : item.path;
      return {
        path,
        title: item.meta?.title,
        icon: item.meta?.icon || '',
        children: getMenuList(item.children, path),
        meta: item.meta,
        redirect: item.redirect,
      };
    })
    .filter((item) => item.meta && item.meta.hidden !== true);
};

Vue.component('renderFnIcon', {
  props: {
    item: {
      type: Object as PropType<MenuRoute>,
      required: true,
    },
  },
  // 遵循最小改动的原则，这里仍然使用 createElement
  render(createElement) {
    if (typeof this.item.icon === 'function' || (this.item.icon && typeof this.item.icon.render === 'function')) {
      return createElement(this.item.icon, {
        class: 't-icon',
      });
    }
    return undefined;
  },
});

export default Vue.extend({
  name: 'MenuContent',
  props: {
    navData: Array,
  },
  data() {
    return {
      prefix,
    };
  },
  computed: {
    list(): Array<MenuRoute> {
      return getMenuList(this.navData);
    },
  },
  methods: {
    getHref(item: MenuRoute) {
      return item.path.match(/(http|https):\/\/([\w.]+\/?)\S*/);
    },
  },
});
</script>
