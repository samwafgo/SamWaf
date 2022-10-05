<template>
  <result title="403 Forbidden" tip="抱歉，您无权限访问此页面，企业微信联系创建者xiaolaoshi">
    <t-button @click="() => $router.push('/')">返回首页</t-button>
  </result>
</template>

<script>
import result from '@/components/result/index.vue';

export default {
  name: 'Result403',
  components: { result },
};
</script>
