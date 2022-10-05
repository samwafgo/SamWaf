<template>
  <div class="detail-advanced">
    <t-card title="基本信息" class="advanced-card">
      <div class="info-block">
        <div v-for="(item, index) in baseInfoData" :key="index" class="info-item">
          <h1>{{ item.name }}</h1>
          <span
            :class="{
              ['inProgress']: item.type && item.type.value === 'inProgress',
              ['pdf']: item.type && item.type.value === 'pdf',
            }"
          >
            <i v-if="item.type && item.type.key === 'contractStatus'"></i>
            {{ item.value }}
          </span>
        </div>
      </div>
    </t-card>

    <!-- 发票进度 -->
    <t-card title="发票进度" class="container-base-margin-top">
      <t-row :class="prefix + '-operator-row row-padding'" justify="space-between">
        <template>
          <t-steps :current="updateCurrent">
            <t-step-item title="申请提交" content="已于12月21日提交"></t-step-item>
            <t-step-item title="电子发票" content="预计1～3个工作日"></t-step-item>
            <t-step-item title="发票已邮寄" content="电子发票开出后7个工作日内联系"></t-step-item>
            <t-step-item title="完成" content></t-step-item>
          </t-steps>
        </template>
      </t-row>
    </t-card>

    <!-- 产品目录 -->
    <t-card title="产品目录" class="container-base-margin-top">
      <template slot="option">
        <t-radio-group default-value="dateVal" @change="onAlertChange">
          <t-radio-button value="dateVal">季度</t-radio-button>
          <t-radio-button value="monthVal">月份</t-radio-button>
        </t-radio-group>
      </template>

      <t-row :gutter="16" class="product-block-container">
        <t-col :xl="4">
          <div class="product-add">
            <div class="product-sub">
              <add-icon class="product-sub-icon" />
              <span>新增产品</span>
            </div>
          </div>
        </t-col>
        <t-col v-for="(item, index) in PRODUCT_LIST" :key="index" :xl="4">
          <product :data="item" />
        </t-col>
      </t-row>
    </t-card>

    <!-- 产品采购明细 -->
    <t-card title="产品采购明细" class="container-base-margin-top">
      <t-table
        :columns="columns"
        :data="data"
        :pagination="pagination"
        :hover="hover"
        size="large"
        row-key="index"
        @sort-change="sortChange"
        @change="rehandleChange"
      >
        <template #pdName="{ row }">
          <span>
            {{ row.pdName }}
            <t-tag v-if="row.pdType" size="small">{{ row.pdType }}</t-tag>
          </span>
        </template>

        <template #purchaseNum="{ row }">
          <span>
            {{ row.purchaseNum }}
            <t-tag v-if="row.purchaseNum > 50" theme="danger" variant="light" size="small">超预算</t-tag>
          </span>
        </template>

        <template #op="slotProps">
          <a class="t-button-link" @click="listClick(slotProps)">管理</a>
          <a class="t-button-link" @click="deleteClickOp(slotProps)">删除</a>
        </template>
        <order-descending-icon slot="op-column" />
      </t-table>
    </t-card>

    <t-dialog header="基本信息" :visible.sync="visible" @confirm="onConfirm">
      <div slot="body">
        <div class="dialog-info-block">
          <div v-for="(item, index) in baseInfoData" :key="index" class="info-item">
            <h1>{{ item.name }}</h1>
            <span
              :class="{
                ['inProgress']: item.type && item.type.value === 'inProgress',
                ['pdf']: item.type && item.type.value === 'pdf',
              }"
            >
              <i v-if="item.type && item.type.key === 'contractStatus'"></i>
              {{ item.value }}
            </span>
          </div>
        </div>
      </div>
    </t-dialog>
  </div>
</template>
<script lang="ts">
import { TableChangeContext, TableChangeData, TableSort } from 'tdesign-vue';
import { OrderDescendingIcon, AddIcon } from 'tdesign-icons-vue';
import { prefix } from '@/config/global';
import model from '@/service/service-advance';
import Product from './components/Product.vue';

const PRODUCT_LIST = [
  {
    name: 'MacBook Pro 2021',
    subTitle: 'MacBook Pro 2021',
    size: '13.3 英寸',
    cpu: 'Apple M1',
    memory: 'RAM 16GB',
    info: '最高可选配 16GB 内存 · 最高可选配 2TB 存储设备 电池续航最长达 18 小时',
    use: 1420,
    stock: 1500,
  },
  {
    name: 'Surface Laptop Go',
    subTitle: '微软（Microsoft Corporation）',
    size: '12.4 英寸',
    cpu: 'Core i7',
    memory: 'RAM 16GB',
    info: '常规使用 Surface，续航时间最长可达13小时 随时伴您工作',
    use: 120,
    stock: 2000,
  },
];

/** 高级详情 */
export default {
  name: 'DetailAdvanced',
  components: { Product, OrderDescendingIcon, AddIcon },
  data() {
    return {
      data: [],
      prefix,
      updateCurrent: 0,
      columns: model.getTableColumns(),
      baseInfoData: model.getBaseInfoData(),
      bordered: true,
      hover: true,
      visible: false,
      pagination: {
        defaultPageSize: 10,
        total: 100,
        defaultCurrent: 1,
        pageSizeOptions: [],
      },
      PRODUCT_LIST,
    };
  },
  async mounted() {
    // 模拟进度
    setInterval(() => {
      if (this.updateCurrent > 5) {
        this.updateCurrent = -1;
      }
      this.updateCurrent += 1;
    }, 2000);

    this.$request
      .get('/api/get-purchase-list')
      .then((res: { code: number; data: Record<string, any> }) => {
        if (res.code === 0) {
          const { list = [] } = res.data;
          this.data = list;
          this.pagination = {
            ...this.pagination,
            total: list.length,
          };
        }
      })
      .catch((e: Error) => {
        console.log(e);
      });
  },
  methods: {
    onAlertChange(val: string): void {
      console.log(val);
    },
    sortChange(val: TableSort): void {
      console.log(val);
    },
    rehandleChange(
      changeParams: TableChangeData,
      triggerAndData: TableChangeContext<Array<Record<string, string>>>,
    ): void {
      console.log('统一Change', changeParams, triggerAndData);
    },
    listClick(e: any): void {
      console.log(e);
      this.visible = true;
    },
    deleteClickOp(e: any): void {
      console.log(e, 'e');
      this.data.splice(e.rowIndex, 1);
    },
    onConfirm(): void {
      this.visible = false;
    },
  },
};
</script>
<style lang="less" scoped>
@import './index';
</style>
