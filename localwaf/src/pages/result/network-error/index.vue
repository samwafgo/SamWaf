<template>
  <result title="网络异常" tip="网络异常，请稍后再试" type="wifi">
    <div>
      <t-button @click="() => $router.push('/')">重新加载</t-button>
      <t-button theme="default" @click="() => $router.push('/')">返回首页</t-button>
    </div>
  </result>
</template>

<script>
import result from '@/components/result/index.vue';

export default {
  name: 'ResultNetworkError',
  components: { result },
};
</script>
<style lang="less" scoped>
@import '@/style/variables.less';

.t-button + .t-button {
    margin-left: @spacer;
 }
</style>