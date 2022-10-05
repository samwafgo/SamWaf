<template>
  <t-row :gutter="[16, 16]">
    <t-col :xs="12" :xl="6">
      <t-card title="销售订单排名" class="dashboard-rank-card">
        <template #actions>
          <t-radio-group default-value="dateVal">
            <t-radio-button value="dateVal">本周</t-radio-button>
            <t-radio-button value="monthVal">近三个月</t-radio-button>
          </t-radio-group>
        </template>
        <t-table :data="saleTendList" :columns="saleColumns" rowKey="productName">
          <template #index="{ rowIndex }">
            <span :class="getRankClass(rowIndex)">
              {{ rowIndex + 1 }}
            </span>
          </template>
          <span slot="growUp" slot-scope="{ row }">
            <trend :type="row.growUp > 0 ? 'up' : 'down'" :describe="Math.abs(row.growUp)" />
          </span>
          <template #operation="slotProps">
            <a class="link" @click="rehandleClickOp(slotProps)">详情</a>
          </template>
        </t-table>
      </t-card>
    </t-col>
    <t-col :xs="12" :xl="6">
      <t-card title="采购订单排名" class="dashboard-rank-card">
        <template #actions>
          <t-radio-group default-value="dateVal">
            <t-radio-button value="dateVal">本周</t-radio-button>
            <t-radio-button value="monthVal">近三个月</t-radio-button>
          </t-radio-group>
        </template>
        <t-table :data="buyTendList" :columns="buyColumns" rowKey="productName">
          <template #index="{ rowIndex }">
            <span :class="getRankClass(rowIndex)">
              {{ rowIndex + 1 }}
            </span>
          </template>
          <span slot="growUp" slot-scope="{ row }">
            <trend :type="row.growUp > 0 ? 'up' : 'down'" :describe="Math.abs(row.growUp)" />
          </span>
          <template #operation="slotProps">
            <a class="link" @click="rehandleClickOp(slotProps)">详情</a>
          </template>
        </t-table>
      </t-card>
    </t-col>
  </t-row>
</template>
<script>
import Trend from '@/components/trend/index.vue';
import { SALE_TEND_LIST, BUY_TEND_LIST, SALE_COLUMNS, BUY_COLUMNS } from '@/service/service-base';

export default {
  name: 'RankList',
  components: {
    Trend,
  },
  data() {
    return {
      buyTendList: BUY_TEND_LIST,
      saleTendList: SALE_TEND_LIST,
      saleColumns: SALE_COLUMNS,
      buyColumns: BUY_COLUMNS,
    };
  },
  methods: {
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
