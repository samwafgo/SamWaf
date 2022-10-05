<template>
  <div class="result-container">
    <div class="result-bg-img">
      <component :is="dynamicComponent"></component>
    </div>
    <div class="result-title">{{ title }}</div>
    <div class="result-tip">{{ tip }}</div>
    <slot />
  </div>
</template>
<script lang="ts">
import Vue from 'vue';

import Result403Icon from '@/assets/assets-result-403.svg';
import Result404Icon from '@/assets/assets-result-404.svg';
import Result500Icon from '@/assets/assets-result-500.svg';
import ResultIeIcon from '@/assets/assets-result-ie.svg';
import ResultWifiIcon from '@/assets/assets-result-wifi.svg';
import ResultMaintenanceIcon from '@/assets/assets-result-maintenance.svg';

export default Vue.extend({
  name: 'Result',
  props: {
    bgUrl: {
      type: String,
      default: '',
    },
    title: {
      type: String,
      default: '',
    },
    tip: {
      type: String,
      default: '',
    },
    type: {
      type: String,
      default: '',
    },
  },
  computed: {
    dynamicComponent() {
      switch (this.type) {
      case '403':
        return Result403Icon;
      case '404':
        return Result404Icon;
      case '500':
        return Result500Icon;
      case 'ie':
        return ResultIeIcon;
      case 'wifi':
        return ResultWifiIcon;
      case 'maintenance':
        return ResultMaintenanceIcon;
      default:
        return Result403Icon;
      }
    },
  },
});
</script>
<style lang="less" scoped>
@import '@/style/variables';

.result {
  &-link {
    color: var(--td-brand-color);
    text-decoration: none;
    cursor: pointer;

    &:hover {
      color: var(--td-brand-color);
    }

    &:active {
      color: var(--td-brand-color);
    }

    &--active {
      color: var(--td-brand-color);
    }

    &:focus {
      text-decoration: none;
    }
  }

  &-container {
    min-height: 400px;
    height: 75vh;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    padding: 24px;
  }

  &-bg-img {
    width: 200px;
    color: var(--td-brand-color);
  }

  &-title {
    font-style: normal;
    font-weight: 500;
    margin-top: 8px;
    color: var(--td-text-color-primary);
    font-size: @font-size-xl;
    line-height: @text-line-height-xl;
  }

  &-tip {
    margin: 8px 0 32px;
    font-size: @font-size-base;
    color: var(--td-text-color-secondary);
    line-height: @text-line-height-base;
  }
}

</style>
