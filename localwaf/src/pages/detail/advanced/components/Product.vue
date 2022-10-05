<template>
  <div class="operator-block operator-gap">
    <div class="operator-content">
      <div class="operator-title">
        <cart-icon class="operator-title-icon" />
        <h1>{{ data.name }}</h1>
        <div class="operator-title-subtitle">
          {{ data.subtitle }}
        </div>
        <div class="operator-title-tags">
          <t-tag class="operator-title-tag" theme="success" size="small">
            {{ data.size }}
          </t-tag>
          <t-tag class="operator-title-tag" size="small">
            {{ data.cpu }}
          </t-tag>
          <t-tag class="operator-title-tag" size="small">
            {{ data.memory }}
          </t-tag>
        </div>
      </div>
      <div class="operator-item">
        <span class="operator-item-info">{{ data.info }}</span>
        <chevron-right-icon class="operator-item-icon" size="small" />
      </div>
    </div>
    <div class="operator-footer">
      <span class="operator-footer-percentage">{{ data.use }} / {{ data.stock }}（台）</span>
      <t-progress
        class="operator-progress"
        theme="line"
        :percentage="(data.use / data.stock) * 100"
        :label="false"
        :color="data.use / data.stock < 0.5 ? '#E24D59' : ''"
        :track-color="data.use / data.stock < 0.5 ? 'var(--td-error-color-1)' : 'var(--td-brand-color-1)'"
      />
    </div>
  </div>
</template>

<script lang="ts">
import Vue from 'vue';
import { ChevronRightIcon, CartIcon } from 'tdesign-icons-vue';

export default Vue.extend({
  components: {
    ChevronRightIcon,
    CartIcon,
  },
  props: {
    data: {
      type: Object,
      default: () => ({}),
    },
  },
});
</script>

<style lang="less" scoped>
@import '@/style/variables.less';

.operator-gap {
  margin-left: 20px;
}

.operator-block {
  position: relative;
  background-color: var(--td-bg-color-container);
  border: 1px solid var(--td-component-border);
  border-radius: 3px;

  .operator-content {
    padding: 20px 32px 24px 32px;
    height: 256px;

    .operator-title-icon {
      background: var(--td-brand-color-1);
      color: var(--td-brand-color);
      font-size: 56px;
      padding: 14px;
      border-radius: 100%;
    }

    .operator-title {
      margin-bottom: 25px;
      position: relative;

      h1 {
        display: inline-block;
        font-weight: 500;
        font-size: 24px;
        color: var(--td-text-color-primary);
      }

      &-subtitle {
        display: block;
        font-weight: 400;
        font-size: 14px;
        width: 60%;
        color: var(--td-text-color-placeholder);
      }

      &-tag {
        margin-right: 4px;
        margin-top: 8px;
        margin-left: unset;
        border: unset;
      }

      &-icon {
        position: absolute;
        top: 0px;
        right: 0px;
      }

      svg {
        circle {
          fill: var(--td-brand-color-2);
        }

        path {
          fill: var(--td-brand-color);
        }
      }
    }

    .operator-item {
      position: relative;
      padding-top: 8px;
      padding-bottom: 8px;

      &-info {
        display: inline-block;
        width: 60%;
        text-align: left;
        font-size: 14px;
        color: var(--td-text-color-placeholder);
      }

      &-icon {
        position: absolute;
        bottom: 8px;
        right: 0;
        color: var(--td-text-color-disabled);
      }
    }
  }

  .operator-footer {
    position: absolute;
    width: 100%;
    bottom: 0px;
    left: 0;

    .t-progress--thin {
      display: unset;
    }

    &-percentage {
      position: absolute;
      bottom: 15px;
      right: 32px;
      color: var(--td-text-color-placeholder);
    }
  }
}
</style>
