<template>
  <t-row :gutter="[16, 16]">
    <t-col :xs="6" :xl="3" v-for="(item, index) in panelList" :key="item.title">
      <t-card
        :title="item.title"
        :style="{ height: '168px' }"
        :class="{ 'dashboard-item': true, 'dashboard-item--main-color': index == 0 }"
        @click.native="jumpLog(index)"
      >
        <div class="dashboard-item-top">
          <span :style="{ fontSize: `${resizeTime * 36}px` }">{{ item.number }}</span>
        </div>
        <div class="dashboard-item-left">
          <div
            v-if="index === 0"
            id="moneyContainer"
            class="dashboard-chart-container"
            :style="{ width: `${resizeTime * 120}px`, height: `${resizeTime * 66}px` }"
          ></div>
          <div
            v-else-if="index === 1"
            id="refundContainer"
            class="dashboard-chart-container"
            :style="{ width: `${resizeTime * 120}px`, height: `${resizeTime * 42}px` }"
          ></div>
          <span v-else-if="index === 2" :style="{ marginTop: `-24px` }">
            <usergroup-icon />
          </span>
          <span v-else :style="{ marginTop: '-24px' }">
            <file-icon />
          </span>
        </div>
        <template #footer>
          <div class="dashboard-item-bottom">
            <div class="dashboard-item-block">
              较昨天
              <trend
                class="dashboard-item-trend"
                :type="item.upTrend ? 'up' : 'down'"
                :is-reverse-color="index === 0"
                :describe="item.upTrend || item.downTrend"
              />
            </div>
            <chevron-right-icon />
          </div>
        </template>
      </t-card>
    </t-col>
  </t-row>
</template>
<script lang="ts">
import { LineChart, BarChart } from 'echarts/charts';
import * as echarts from 'echarts/core';
import { CanvasRenderer } from 'echarts/renderers';
import { UsergroupIcon, FileIcon, ChevronRightIcon } from 'tdesign-icons-vue';
import { mapState } from 'vuex';

import Trend from '@/components/trend/index.vue';

import { constructInitDashboardDataset } from '../index';
import { changeChartsTheme } from '@/utils/color';
//import { PANE_LIST } from '@/service/service-base';
  import {
    wafstatsumdayapi
  } from '@/apis/stats';
echarts.use([LineChart, BarChart, CanvasRenderer]);

export default {
  name: 'TopPanel',
  components: {
    Trend,
    UsergroupIcon,
    FileIcon,
    ChevronRightIcon,
  },
  data() {
    return {
      resizeTime: 1,
      panelList: [],
    };
  },
  computed: {
    ...mapState('setting', ['brandTheme', 'mode']), // 这里需要用到主题色和主题模式的全局配置
  },
  watch: {
    brandTheme() {
      changeChartsTheme([this.refundChart]);
    },
    mode() {
      [this.moneyCharts, this.refundChart].forEach((item) => {
        item.dispose();
      });
      this.renderCharts();
    },
  },
  created() {

    this.getWafStat()
  },
  mounted() {
    this.$nextTick(() => {
      this.updateContainer();
    });

    window.addEventListener('resize', this.updateContainer, false);
    this.renderCharts();
  },

  methods: {
    jumpLog(title){
      console.log(title)
      switch (title){
        case 0: //今日攻击数量
          this.$router.push({
        		path: '/waf/wafattacklog',
        		query: {
        			action: "阻止"
        		}
        	});
          break;
        case 1: //今天总访问量
        this.$router.push({
        	path: '/waf/wafattacklog',
        	query: {

        	}
        });break;
        case 2: //今天异常IP（个）
        this.$router.push({
        	path: '/waf/wafattacklog',
        	query: {
        		action: "禁止"
        	}
        });
        break;
        default:
          break;
      }


    },
    getWafStat() {
      let that = this
      wafstatsumdayapi()
        .then((res) => {
          let resdata = res
          console.log(resdata)
          if (resdata.code === 0) {

            //const { list = [] } = resdata.data.list;

            that.wafstat_data = resdata.data;
            that.panelList.push({
              title:  this.$t('dashboard.counter.today_of_attack_count') ,
              number: that.wafstat_data.AttackCountOfToday,
              upTrend: '0%',
              leftType: 'echarts-line',
            })
            that.panelList.push({
              title: this.$t('dashboard.counter.all_visit_count') ,
              number: that.wafstat_data.VisitCountOfToday,
              upTrend: '0%',
              leftType: 'echarts-line',
            })
            that.panelList.push({
              title:this.$t('dashboard.counter.not_normal_visit_count'),
              number: that.wafstat_data.IllegalIpCountOfToday,
              upTrend: '0%',
              leftType: 'echarts-line',
            })
           /* that.panelList.push({
              title: '今天正常IP（个）',
              number: that.wafstat_data.NormalIpCountOfToday,
              upTrend: '0%',
              leftType: 'echarts-line',
            })*/
            that.panelList.push({
              title: this.$t('dashboard.counter.qps'),
              number: that.wafstat_data.CurrentQps,
              upTrend: '0%',
              leftType: 'echarts-line',
            })
          }
        })
        .catch((e: Error) => {
          console.log(e);
        })
        .finally(() => {});
    },
    updateContainer() {
      if (document.documentElement.clientWidth >= 1400 && document.documentElement.clientWidth < 1920) {
        this.resizeTime = (document.documentElement.clientWidth / 2080).toFixed(2);
      } else if (document.documentElement.clientWidth < 1080) {
        this.resizeTime = (document.documentElement.clientWidth / 1080).toFixed(2);
      } else {
        this.resizeTime = 1;
      }
    },

    renderCharts() {
      const { chartColors } = this.$store.state.setting;
    },
  },
};
</script>

<style lang="less" scoped>
@import '@/style/variables.less';

.dashboard-item {
  padding: 8px;

  /deep/ .t-card__footer {
    padding-top: 0;
  }

  /deep/ .t-card__title {
    font-size: 14px;
    font-weight: 500;
  }

  /deep/ .t-card__body {
    display: flex;
    flex-direction: column;
    justify-content: space-between;
    flex: 1;
    position: relative;
  }

  &:hover {
    cursor: pointer;
  }

  &-top {
    display: flex;
    flex-direction: row;
    align-items: flex-start;

    > span {
      display: inline-block;
      color: var(--td-text-color-primary);
      font-size: 36px;
      line-height: 44px;
    }
  }

  &-bottom {
    display: flex;
    flex-direction: row;
    justify-content: space-between;
    align-items: center;

    > .t-icon {
      cursor: pointer;
    }
  }

  &-block {
    display: flex;
    align-items: center;
    justify-content: center;
    line-height: 22px;
    color: var(--td-text-color-placeholder);
  }

  &-trend {
    margin-left: 8px;
  }

  &-left {
    position: absolute;
    top: 0;
    right: 32px;

    > span {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      width: 56px;
      height: 56px;
      background: var(--td-brand-color-1);
      border-radius: 50%;

      .t-icon {
        font-size: 24px;
        color: var(--td-brand-color);
      }
    }
  }

  // 针对第一个卡片需要反色处理
  &--main-color {
    background: var(--td-brand-color);
    color: var(--td-text-color-primary);

    /deep/ .t-card__title,
    .dashboard-item-top span,
    .dashboard-item-bottom {
      color: var(--td-text-color-anti);
    }

    .dashboard-item-block {
      color: var(--td-text-color-anti);
      opacity: 0.6;
    }

    .dashboard-item-bottom {
      color: var(--td-text-color-anti);
    }
  }
}
</style>
