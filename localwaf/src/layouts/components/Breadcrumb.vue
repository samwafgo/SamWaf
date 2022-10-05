<template>
  <t-breadcrumb :max-item-width="'150'" class="tdesign-breadcrumb">
    <t-breadcrumbItem v-for="item in crumbs" :key="item.to" :to="item.to">
      {{ item.title }}
    </t-breadcrumbItem>
  </t-breadcrumb>
</template>

<script lang="ts">
import Vue from 'vue';

export default Vue.extend({
  name: 'TdesignStarterBreadcrumb',
  props: {
    isVisible: Boolean,
  },
  computed: {
    crumbs() {
      const pathArray = this.$route.path.split('/');
      pathArray.shift();

      const breadcrumbs = pathArray.reduce((breadcrumbArray, path, idx) => {
        breadcrumbArray.push({
          path,
          to: breadcrumbArray[idx - 1] ? `/${breadcrumbArray[idx - 1].path}/${path}` : `/${path}`,
          title: this.$route.matched[idx].meta.title || path,
        });
        return breadcrumbArray;
      }, []);
      return breadcrumbs;
    },
  },
});
</script>
<style scoped>
.tdesign-breadcrumb {
  margin-bottom: 8px;
}
</style>
