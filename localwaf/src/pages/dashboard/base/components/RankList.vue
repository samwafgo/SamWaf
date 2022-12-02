<template>
  <t-row :gutter="[16, 16]">
    <t-col :xs="12" :xl="6">
      <t-card title="IP攻击排名" class="dashboard-rank-card">
        <template #actions>
          <t-radio-group default-value="dateVal">
            <t-radio-button value="dateVal">本周</t-radio-button>
            <t-radio-button value="monthVal">近三个月</t-radio-button>
          </t-radio-group>
        </template>
        <t-table :data="attackNowList" :columns="attackColumns" rowKey="IP">
          <template #index="{ rowIndex }">
            <span :class="getRankClass(rowIndex)">
              {{ rowIndex + 1 }}
            </span>
          </template>
         <!-- <span slot="growUp" slot-scope="{ row }">
            <trend :type="row.growUp > 0 ? 'up' : 'down'" :describe="Math.abs(row.growUp)" />
          </span> -->
          <!-- <template #operation="slotProps">
            <a class="link" @click="rehandleClickOp(slotProps)">详情</a>
          </template> -->
        </t-table>
      </t-card>
    </t-col>
    <t-col :xs="12" :xl="6">
      <t-card title="IP访问排名" class="dashboard-rank-card">
        <template #actions>
          <t-radio-group default-value="dateVal">
            <t-radio-button value="dateVal">本周</t-radio-button>
            <t-radio-button value="monthVal">近三个月</t-radio-button>
          </t-radio-group>
        </template>
        <t-table :data="normalNowList" :columns="normalColumns" rowKey="productName">
          <template #index="{ rowIndex }">
            <span :class="getRankClass(rowIndex)">
              {{ rowIndex + 1 }}
            </span>
          </template>
        <!--  <span slot="growUp" slot-scope="{ row }">
            <trend :type="row.growUp > 0 ? 'up' : 'down'" :describe="Math.abs(row.growUp)" />
          </span>
          <template #operation="slotProps">
            <a class="link" @click="rehandleClickOp(slotProps)">详情</a>
          </template> -->
        </t-table>
      </t-card>
    </t-col>
  </t-row>
</template>
<script lang="ts">
import Trend from '@/components/trend/index.vue';
import { SALE_TEND_LIST, BUY_TEND_LIST, Attack_IP_COLUMNS, Normal_IP_COLUMNS } from '@/service/service-base';
import { LAST_7_DAYS } from '@/utils/date';
import {
  wafstatsumdaytopiprangeapi
} from '@/apis/stats';

export default {
  name: 'RankList',
  components: {
    Trend,
  },
  data() {
    return {
      buyTendList: BUY_TEND_LIST,
      saleTendList: SALE_TEND_LIST,
      attackColumns: Attack_IP_COLUMNS,
      normalColumns: Normal_IP_COLUMNS,
      rangeStartDay:0,//开始时间
      rangeEndDay:0,//结束时间
      attackNowList : [],
      normalNowList : [],
    };
  },
  mounted() {
    this.rangeStartDay = LAST_7_DAYS[0].replace(/-/g,"")
    this.rangeEndDay = LAST_7_DAYS[1].replace(/-/g,"")
    this.loadTopIp()
  },
  methods: {
    loadTopIp(){
        wafstatsumdaytopiprangeapi({'start_day':this.rangeStartDay,'end_day':this.rangeEndDay})
          .then((res) => {
            let resdata = res
            console.log(resdata.data)
            this.attackNowList = resdata.data.AttackIPOfRange
            this.normalNowList = resdata.data.NormalIPOfRange



            }
            ).catch((e: Error) => {
            console.log(e);
          })
          .finally(() => {})
    },
    rehandleClickOp(val) {
      console.log(val);
    },
    getRankClass(index) {
      return ['dashboard-rank__cell', { 'dashboard-rank__cell--top': index < 3 }];
    },
  },
};
</script>

<style lang="less" scoped>
@import '@/style/variables.less';

.dashboard-rank-card {
  padding: 8px;

  /deep/ .t-card__header {
    padding-bottom: 24px;
  }

  /deep/ .t-card__title {
    font-size: 20px;
    font-weight: 500;
  }
}

.dashboard-rank__cell {
  display: inline-flex;
  width: 24px;
  height: 24px;
  border-radius: 50%;
  color: white;
  font-size: 14px;
  background-color: var(--td-gray-color-5);
  align-items: center;
  justify-content: center;
  font-weight: 700;

  &--top {
    background: var(--td-brand-color);
  }
}
</style>
