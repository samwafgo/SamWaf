<template>
  <div class="result-fail">
    <error-circle-icon class="result-fail-icon" />
    <div class="result-fail-title">创建失败</div>
    <div class="result-fail-describe">抱歉，您的项目创建失败，企业微信联系检查创建者权限，或返回修改。</div>
    <div>
      <t-button @click="() => this.$router.push('/form/base')">返回修改</t-button>
      <t-button theme="default" @click="() => this.$router.push('/form/base')">返回首页</t-button>
    </div>
  </div>
</template>

<script>
import { ErrorCircleIcon } from 'tdesign-icons-vue';

export default {
  name: 'ResultFail',
  components: {
    ErrorCircleIcon,
  },
};
</script>

<style lang="less" scoped>
@import '@/style/variables.less';
.result-fail {
  display: flex;
  flex-direction: column;
  justify-content: center;
  align-items: center;
  height: 75vh;

  &-icon {
    font-size: 72px;
    color: var(--td-text-color-secondary);
  }

  &-title {
    margin-top: 28px;
    font-size: 20px;
    color: var(--td-text-color-primary);
    text-align: center;
    line-height: 28px;
    font-weight: 500;
  }

  &-describe {
    margin: 8px 0 32px;
    font-size: 14px;
    color: var(--td-text-color-secondary);
    line-height: 22px;
  }
  .t-button + .t-button {
    margin-left: @spacer;
 }
}
</style>
