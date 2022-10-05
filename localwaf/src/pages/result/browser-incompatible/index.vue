<template>
  <result title="浏览器版本低" tip="抱歉，您正在使用的浏览器版本过低，无法打开当前网页。" type="ie">
    <div class="result-slot-container">
      <t-button class="result-button" @click="() => $router.push('/')">返回首页</t-button>
      <div class="recommend-container">
        <div>TDesign Starter 推荐以下主流浏览器</div>
        <div class="recommend-browser">
          <div>
            <thumbnail class="browser-icon" url="https://tdesign.gtimg.com/starter/result-page/chorme.png" />
            <div>Chrome</div>
          </div>
          <div>
            <thumbnail class="browser-icon" url="https://tdesign.gtimg.com/starter/result-page/qq-browser.png" />
            <div>QQ Browser</div>
          </div>
        </div>
      </div>
    </div>
  </result>
</template>

<script>
import Result from '@/components/result/index.vue';
import Thumbnail from '@/components/thumbnail/index.vue';

export default {
  name: 'ResultBrowserIncompatible',
  components: { Result, Thumbnail },
};
</script>

<style lang="less" scoped>
@import '@/style/variables.less';

.result-slot-container {
  position: relative;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: space-between;
  color: var(--td-text-color-secondary);
}

.recommend-container {
  position: absolute;
  display: flex;
  align-items: center;
  justify-content: space-between;
  top: 175px;
  padding: 24px 48px;
  width: 640px;
  background: var(--td-bg-color-container);
  box-shadow: 0px 1px 2px var(--td-shadow-1);
  border-radius: 3px;
}

.recommend-browser {
  display: flex;

  > div {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: space-between;
    height: 70px;
  }

  > div + div {
    margin-left: 40px;
  }
}

.browser-icon {
  width: 36.67px;
  height: 36.67px;
}
</style>
