<template>
  <result title="系统维护中" tip="系统维护中，请稍后再试" type="maintenance">
    <t-button theme="default" @click="() => $router.push('/')">返回首页</t-button>
  </result>
</template>

<script>
import result from '@/components/result/index.vue';

export default {
  name: 'ResultMaintenance',
  components: { result },
};
</script>
