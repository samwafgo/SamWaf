<template>
  <t-card>
    <t-row>
      <t-col :xs="12" :xl="9">
        <t-card
          :bordered="false"
          title="出入库概览"
          subtitle="(件)"
          :class="{ 'dashboard-overview-card': true, 'overview-panel': true }"
        >
          <template #actions>
            <t-date-range-picker
              class="card-date-picker-container"
              theme="primary"
              mode="date"
              :default-value="LAST_7_DAYS"
              @change="onStokeDataChange"
            />
          </template>
          <div
            id="stokeContainer"
            style="width: 100%; height: 351px"
            ref="stokeContainer"
            class="dashboard-chart-container"
          ></div>
        </t-card>
      </t-col>
      <t-col :xs="12" :xl="3">
        <t-card :bordered="false" :class="{ 'dashboard-overview-card': true, 'export-panel': true }">
          <template #actions>
            <t-button>导出数据</t-button>
          </template>
          <t-row>
            <t-col :xs="6" :xl="12">
              <t-card :bordered="false" subtitle="本月出库总计（件）" class="inner-card">
                <div class="inner-card__content">
                  <div class="inner-card__content-title">1726</div>
                  <div class="inner-card__content-footer">
                    自从上周以来
                    <trend class="trend-tag" type="down" :is-reverse-color="false" describe="20.3%" />
                  </div>
                </div>
              </t-card>
            </t-col>
            <t-col :xs="6" :xl="12">
              <t-card :bordered="false" subtitle="本月入库总计（件）" class="inner-card">
                <div class="inner-card__content">
                  <div class="inner-card__content-title">226</div>
                  <div class="inner-card__content-footer">
                    自从上周以来
                    <trend class="trend-tag" type="down" :is-reverse-color="false" describe="20.3%" />
                  </div>
                </div>
              </t-card>
            </t-col>
          </t-row>
        </t-card>
      </t-col>
    </t-row>
  </t-card>
</template>
<script>
import { TooltipComponent, LegendComponent, GridComponent } from 'echarts/components';
import { BarChart } from 'echarts/charts';
import { CanvasRenderer } from 'echarts/renderers';
import * as echarts from 'echarts/core';
import { mapState } from 'vuex';

import { constructInitDataset } from '../index';
import { changeChartsTheme } from '@/utils/color';
import { LAST_7_DAYS } from '@/utils/date';
import Trend from '@/components/trend/index.vue';

import { PANE_LIST, SALE_TEND_LIST, BUY_TEND_LIST, SALE_COLUMNS, BUY_COLUMNS } from '@/service/service-base';

echarts.use([TooltipComponent, LegendComponent, GridComponent, BarChart, CanvasRenderer]);

export default {
  name: 'Overview',
  components: {
    Trend,
  },
  data() {
    return {
      panelList: PANE_LIST,
      buyTendList: BUY_TEND_LIST,
      saleTendList: SALE_TEND_LIST,
      saleColumns: SALE_COLUMNS,
      buyColumns: BUY_COLUMNS,
      LAST_7_DAYS,
    };
  },
  computed: {
    ...mapState('setting', ['brandTheme', 'mode']), // 这里需要用到主题色和主题模式的全局配置
  },
  watch: {
    brandTheme() {
      changeChartsTheme([this.stokeChart]);
    },
    mode() {
      [this.stokeChart].forEach((item) => {
        item.dispose();
      });
      this.renderCharts();
    },
  },
  mounted() {
    this.$nextTick(() => {
      this.updateContainer();
    });

    window.addEventListener('resize', this.updateContainer, false);
    this.renderCharts();
  },

  methods: {
    /** 出入库概览日期更新 */
    onStokeDataChange(checkedValues) {
      const { chartColors } = this.$store.state.setting;

      this.stokeChart.setOption(constructInitDataset({ dateTime: checkedValues, ...chartColors }));
    },
    updateContainer() {
      this.stokeChart.resize({
        // 根据父容器的大小设置大小
        width: this.stokeContainer.clientWidth,
        height: this.stokeContainer.clientHeight,
      });
    },
    renderCharts() {
      const { chartColors } = this.$store.state.setting;
      // 出入库概览
      if (!this.stokeContainer) this.stokeContainer = document.getElementById('stokeContainer');

      this.stokeChart = echarts.init(this.stokeContainer);
      this.stokeChart.setOption(constructInitDataset({ dateTime: LAST_7_DAYS, ...chartColors }));
    },
  },
};
</script>

<style lang="less" scoped>
@import '@/style/variables.less';

.dashboard-overview-card {
  /deep/ .t-card__header {
    padding-bottom: 24px;
  }

  /deep/ .t-card__title {
    font-size: 20px;
    font-weight: 500;
  }

  &.overview-panel {
    border-right: none;
  }

  &.export-panel {
    border-left: none;
  }
}

.inner-card {
  padding: 24px 0;

  /deep/ .t-card__header {
    padding-bottom: 0;
  }

  &__content {
    &-title {
      font-size: 36px;
      line-height: 44px;
    }

    &-footer {
      display: flex;
      align-items: center;
      line-height: 22px;
      color: var(--td-text-color-placeholder);

      .trend-tag {
        margin-left: 4px;
      }
    }
  }
}
</style>
