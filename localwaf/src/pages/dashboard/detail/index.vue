<template>
  <div class="dashboard-detail">
    <t-card title="本月采购申请情况" class="dashboard-detail-card">
      <t-row :gutter="[16, 16]">
        <t-col v-for="(item, index) in PANE_LIST_DATA" :key="index" :xs="6" :xl="3">
          <t-card :class="['dashboard-list-card']" :description="item.title">
            <div class="dashboard-list-card__number">{{ item.number }}</div>
            <div class="dashboard-list-card__text">
              <div class="dashboard-list-card__text-left">
                环比
                <trend class="icon" :type="item.upTrend ? 'up' : 'down'" :describe="item.upTrend || item.downTrend" />
              </div>
              <chevron-right-icon />
            </div>
          </t-card>
        </t-col>
      </t-row>
    </t-card>
    <t-row :gutter="[16, 16]" class="row-margin">
      <t-col :xs="12" :xl="9">
        <t-card :class="{ 'dashboard-detail-card': true }" title="采购商品申请趋势" subtitle="(件)">
          <template #actions>
            <t-date-range-picker
              style="width: 250px"
              :default-value="LAST_7_DAYS"
              theme="primary"
              mode="date"
              @change="onMaterialChange"
            />
          </template>
          <div id="lineContainer" ref="lineContainer" style="width: 100%; height: 410px"></div>
        </t-card>
      </t-col>
      <t-col :xs="12" :xl="3">
        <product-card
          v-for="(item, index) in PRODUCT_LIST"
          :key="index"
          :product="item"
          :class="{ 'row-margin': index !== 0 }"
        />
      </t-col>
    </t-row>
    <t-card :class="{ 'dashboard-detail-card': true }" title="采购商品满意度分布" class="row-margin">
      <template #actions>
        <t-date-range-picker
          style="display: inline-block; margin-right: 8px; width: 250px"
          :defaultValue="LAST_7_DAYS"
          theme="primary"
          mode="date"
          @change="onSatisfyChange"
        >
        </t-date-range-picker>
        <t-button>导出数据</t-button>
      </template>
      <div id="scatterContainer" style="width: 100%; height: 374px"></div>
    </t-card>
  </div>
</template>
<script lang="ts">
import { GridComponent, TooltipComponent, LegendComponent } from 'echarts/components';
import { LineChart, ScatterChart } from 'echarts/charts';
import { CanvasRenderer } from 'echarts/renderers';
import * as echarts from 'echarts/core';
import { mapState } from 'vuex';
import { ChevronRightIcon } from 'tdesign-icons-vue';

import Trend from '@/components/trend/index.vue';
import ProductCard from '@/components/product-card/index.vue';

import { LAST_7_DAYS } from '@/utils/date';
import { changeChartsTheme } from '@/utils/color';

import { PANE_LIST_DATA, PRODUCT_LIST } from '@/service/service-detail';
import { getFolderLineDataSet, getScatterDataSet } from './index';

echarts.use([GridComponent, LegendComponent, TooltipComponent, LineChart, ScatterChart, CanvasRenderer]);

export default {
  name: 'DashboardDetail',
  components: { Trend, ProductCard, ChevronRightIcon },
  data() {
    return {
      PANE_LIST_DATA,
      PRODUCT_LIST,
      dashboardBase: '',
      lineContainer: '',
      scatterContainer: '',
      lineChart: '',
      scatterChart: '',
      productList: [
        {
          description: 'SSL证书又叫服务器证书，腾讯云为您提供证书的一站式服务，包括免费、付费证书的申请、管理及部',
          index: 1,
          isSetup: true,
          name: 'SSL证书',
          type: 4,
        },
      ],
      LAST_7_DAYS,
    };
  },
  computed: {
    ...mapState('setting', ['brandTheme', 'mode']),
  },
  watch: {
    brandTheme() {
      changeChartsTheme([this.lineChart, this.scatterChart]);
    },
    mode() {
      this.renderCharts();
    },
  },
  mounted() {
    this.$nextTick(() => {
      this.updateContainer();
    });
    this.renderCharts();
  },
  methods: {
    /** 采购商品满意度选择 */
    onSatisfyChange(value: string) {
      const { chartColors } = this.$store.state.setting;

      this.scatterChart.setOption(getScatterDataSet({ dateTime: value, ...chartColors }));
    },
    /** 采购商品申请趋势选择 */
    onMaterialChange(value: string) {
      const { chartColors } = this.$store.state.setting;

      this.lineChart.setOption(getFolderLineDataSet({ dateTime: value, ...chartColors }));
    },
    updateContainer() {
      this.lineChart.resize?.({
        width: this.lineContainer.clientWidth,
        height: this.lineContainer.clientHeight,
      });
      this.scatterChart.resize?.({
        width: this.scatterContainer.clientWidth,
        height: this.scatterContainer.clientHeight,
      });
    },
    renderCharts() {
      const { chartColors } = this.$store.state.setting;

      if (!this.lineContainer) {
        this.lineContainer = document.getElementById('lineContainer');
      }
      this.lineChart = echarts.init(this.lineContainer);
      this.lineChart.setOption(getFolderLineDataSet({ ...chartColors }));

      window.addEventListener('resize', this.updateContainer, false);

      if (!this.scatterContainer) {
        this.scatterContainer = document.getElementById('scatterContainer');
      }
      this.scatterChart = echarts.init(this.scatterContainer);
      this.scatterChart.setOption(getScatterDataSet({ ...chartColors }));
    },
  },
};
</script>
<style lang="less" scoped>
@import '@/style/variables.less';

.row-margin {
  margin-top: 16px;
}

// 统一增加8px;
.dashboard-detail-card {
  padding: 8px;

  /deep/ .t-card__title {
    font-size: 20px;
    font-weight: 500;
  }

  /deep/ .t-card__actions {
    display: flex;
    align-items: center;
  }
}

.dashboard-list-card {
  display: flex;
  flex-direction: column;
  flex: 1;
  height: 170px;
  padding: 8px;

  /deep/ .t-card__header {
    padding-bottom: 8px;
  }

  /deep/ .t-card__body {
    flex: 1;
    display: flex;
    flex-direction: column;
    justify-content: space-between;
  }

  &.dark {
    &:hover {
      background: var(--td-gray-color-14);
      cursor: pointer;
    }
  }

  &.light {
    &:hover {
      background: var(--td-gray-color-14);
      cursor: pointer;
    }
  }

  &__number {
    font-size: 36px;
    line-height: 44px;
    color: var(--td-text-color-primary);
  }

  &__text {
    display: flex;
    flex-direction: row;
    align-items: center;
    justify-content: space-between;
    font-size: 14px;
    color: var(--td-text-color-placeholder);
    text-align: left;
    line-height: 18px;

    &-left {
      display: flex;

      .icon {
        margin: 0 8px;
      }
    }
  }
}
</style>
