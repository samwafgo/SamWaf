<template>
  <div class="detail-base">
    <t-card title="基本信息">
      <div class="info-block">
        <div v-for="(item, index) in baseInfoData" :key="index" class="info-item">
          <h1>{{ item.name }}</h1>
          <span
            :class="{
              ['inProgress']: item.type && item.type.value === 'inProgress',
              ['pdf']: item.type && item.type.value === 'pdf',
            }"
          >
            <i v-if="item.type && item.type.key === 'contractStatus'" />
            {{ item.value }}
          </span>
        </div>
      </div>
    </t-card>

    <t-card title="变更记录" class="container-base-margin-top">
      <t-steps class="detail-base-info-steps" layout="vertical" theme="dot" :current="1">
        <t-step-item title="上传合同附件" content="这里是提示文字" />
        <t-step-item title="修改合同金额" content="这里是提示文字" />
        <t-step-item title="新建合同" content="2020-12-01 15:00:00 管理员-李川操作" />
      </t-steps>
    </t-card>
  </div>
</template>
<script>
import { prefix } from '@/config/global';
import model from '@/service/service-detail-base';

export default {
  name: 'DetailBase',
  data() {
    return {
      prefix,
      baseInfoData: model.getBaseInfoData(),
    };
  },
  methods: {},
};
</script>
<style lang="less" scoped>
@import './index';
</style>
