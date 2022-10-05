<template>
  <router-view :class="[mode]" />
</template>

<script>
import Vue from 'vue';
import config from '@/config/style';

export default Vue.extend({
  computed: {
    mode() {
      return this.$store.getters['setting/mode'];
    },
  },
  mounted() {
    this.$store.dispatch('setting/changeTheme', { ...config });
  },
});
</script>
