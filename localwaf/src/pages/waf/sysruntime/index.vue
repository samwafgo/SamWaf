<template>
  <div>
    <t-card class="list-card-container">
      <t-list :split="true">
        <t-list-item v-for="runtime in runtimes">
          <t-list-item-meta :title="runtime.name" >
            <template #description="{ row }">
              <pre>{{runtime.value}}</pre>
            </template>
          </t-list-item-meta>
        </t-list-item>
      </t-list>

    </t-card>
  </div>
</template>
<script lang="ts">
  import Vue from 'vue';
  import {
    SearchIcon
  } from 'tdesign-icons-vue';
  import {
    wafStatRuntimeSysinfoapi
  } from '@/apis/stats';


  export default Vue.extend({
    name: 'ListBase',
    components: {
    },
    data() {
      return {
        runtimes: [],
      };
    },
    computed: {
    },
    mounted() {
      this.loadRunTimeSysinfo()
    },

    methods: {
      loadRunTimeSysinfo(){
        wafStatRuntimeSysinfoapi("").then((res)=>{
          console.log(res)
          this.runtimes = res.data
        }).catch().finally()
      },
    },
  });
</script>

<style lang="less" scoped>
  @import '@/style/variables';

  .payment-col {
    display: flex;

    .trend-container {
      display: flex;
      align-items: center;
      margin-left: 8px;
    }
  }

  .left-operation-container {
    padding: 0 0 6px 0;
    margin-bottom: 16px;

    .selected-count {
      display: inline-block;
      margin-left: 8px;
      color: var(--td-text-color-secondary);
    }
  }

  .search-input {
    width: 360px;
  }

  .t-button+.t-button {
    margin-left: @spacer;
  }
</style>
