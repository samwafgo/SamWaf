<template>
  <t-card>
    <common-table />
  </t-card>
</template>
<script lang="ts">
import CommonTable from '../components/CommonTable.vue';

export default {
  name: 'ListFilter',
  components: {
    CommonTable,
  },
};
</script>
