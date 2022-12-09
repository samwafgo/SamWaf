<template>
  <div>

    <t-card class="list-card-container">
      <t-row justify="space-between">
        <t-form
          ref="form"
          :data="searchformData"
          :label-width="80"
          colon
          :style="{ marginBottom: '8px' }"
        >
          <t-row>
            <t-col :span="10">
              <t-row :gutter="[16, 24]">
                <t-col :flex="1">
                  <t-form-item label="规则名称" name="rule">
                    <t-input
                      v-model="searchformData.rule"
                      class="form-item-content"
                      type="search"
                      placeholder="请输入规则名称"
                      :style="{ minWidth: '134px' }"
                    />
                  </t-form-item>
                </t-col>
                <t-col :flex="1">
                  <t-form-item label="访问状态" name="action">
                    <t-select
                      v-model="searchformData.action"
                      class="form-item-content`"
                      :options="action_options"
                      placeholder="请选择防御状态"
                    />
                  </t-form-item>
                </t-col>
                <t-col :flex="1">
                  <t-form-item label="访问IP" name="src_ip">
                    <t-input
                      v-model="searchformData.src_ip"
                      class="form-item-content"
                      placeholder="请输入访问IP"
                      :style="{ minWidth: '100px' }"
                    />
                  </t-form-item>
                </t-col>
              </t-row>
            </t-col>

            <t-col :span="2" class="operation-container">
              <t-button theme="primary"  :style="{ marginLeft: '8px' }" @click="getList('all')"> 查询 </t-button>
              <t-button type="reset" variant="base" theme="default"> 重置 </t-button>
            </t-col>
          </t-row>
        </t-form>
      </t-row>

      <div class="table-container">
        <t-table
        table-layout: auto
          :columns="columns"
          :data="data"
          :rowKey="rowKey"
          :verticalAlign="verticalAlign"
          :hover="hover"
          :pagination="pagination"
          :selected-row-keys="selectedRowKeys"
          :loading="dataLoading"
          @page-change="rehandlePageChange"
          @change="rehandleChange"
          @select-change="rehandleSelectChange"
          :headerAffixedTop="true"
          :headerAffixProps="{ offsetTop: offsetTop, container: getContainer }"
        >


          <template #op="slotProps">
            <a class="t-button-link" @click="handleClickDetail(slotProps)">详情</a>
            <a class="t-button-link" @click="handleClickDelete(slotProps)">删除</a>
          </template>
        </t-table>
      </div>
    </t-card>
    <t-dialog
      header="确认删除当前所选合同？"
      :body="confirmBody"
      :visible.sync="confirmVisible"
      @confirm="onConfirmDelete"
      :onCancel="onCancel"
    >
    </t-dialog>
  </div>
</template>
<script lang="ts">
import Vue from 'vue';
import { SearchIcon } from 'tdesign-icons-vue';
import Trend from '@/components/trend/index.vue';
import { prefix } from '@/config/global';
import {attacklogList} from '@/apis/waflog/attacklog';

import { CONTRACT_STATUS, CONTRACT_STATUS_OPTIONS, CONTRACT_TYPES, CONTRACT_PAYMENT_TYPES } from '@/constants';

export default Vue.extend({
  name: 'ListBase',
  components: {
    SearchIcon,
    Trend,
  },
  data() {
    return {
      action_options: [{
          label: '阻止',
          value: '阻止'
        },
        {
          label: '放行',
          value: '放行'
        },
        {
          label: '禁止',
          value: '禁止'
        },
      ],
      CONTRACT_STATUS,
      CONTRACT_STATUS_OPTIONS,
      CONTRACT_TYPES,
      CONTRACT_PAYMENT_TYPES,
      prefix,
      dataLoading: false,
      data: [],
      selectedRowKeys: [1, 2],
      value: 'first',
      columns: [
        {
          title: '时间',
          width: 200,
          ellipsis: true,
          colKey: 'create_time',
        },
        {
          title: '域名',
          align: 'left',
          width: 250,
          ellipsis: true,
          colKey: 'host', 
        },

        {
          title: '访客IP',
          width: 150,
          ellipsis: true,
          colKey: 'src_ip',
        },
        {
          title: '放行结果',
          width: 120,
          ellipsis: true,
          colKey: 'action',
        },
        {
          title: '触发规则',
          align: 'left',
          width: 150,
          ellipsis: true,
          colKey: 'rule', 
        },
        {
          title: '访问url',
          width: 200,
          ellipsis: true,
          colKey: 'url',
        },
        {
          title: '国家',
          width: 150,
          ellipsis: true,
          colKey: 'country',
        },
        {
          title: '省',
          width: 150,
          ellipsis: true,
          colKey: 'province',
        },{
          title: '市',
          width: 150,
          ellipsis: true,
          colKey: 'city',
        },
        {
          title: '请求类型',
          width: 150,
          ellipsis: true,
          colKey: 'method',
        },

        {
          align: 'left',
          fixed: 'right',
          width: 200,
          colKey: 'op',
          title: '操作',
        },
      ],
      rowKey: 'REQ_UUID',
      tableLayout: 'auto',
      verticalAlign: 'top',
      hover: true,
      rowClassName: (rowKey: string) => `${rowKey}-class`,
      // 与pagination对齐
      pagination: {
        total: 0,
        current: 1,
        pageSize:10
      },
      searchValue: '',
      confirmVisible: false,
      deleteIdx: -1,
      //顶部搜索
      searchformData:{
          rule:"",
          action:"",
          src_ip:""
      },
    };
  },
  computed: {
    confirmBody() {
      if (this.deleteIdx > -1) {
        const { name } = this.data?.[this.deleteIdx];
        return `删除后，${name}的所有合同信息将被清空，且无法恢复`;
      }
      return '';
    },
    offsetTop() {
      return this.$store.state.setting.isUseTabsRouter ? 48 : 0;
    },
  },
  mounted() {
    this.getList("")
  },

  methods: {
    getList(keyword){

      let that = this
      if(keyword!=undefined && keyword=="all"){
          that.pagination.current = 1
      }
      this.$request
        .post('/waflog/attack/list', {

             pageSize: that.pagination.pageSize,
             pageIndex: that.pagination.current,
             ...that.searchformData
          },
        )
        .then((res) => {
          let resdata = res
          console.log(resdata)
          if (resdata.code === 0) {

            //const { list = [] } = resdata.data.list;

            this.data = resdata.data.list;
            this.pagination = {
              ...this.pagination,
              total: resdata.data.total,
            };
          }
        })
        .catch((e: Error) => {
          console.log(e);
        })
        .finally(() => {
          this.dataLoading = false;
        });
      this.dataLoading = true;
    },
    getContainer() {
      return document.querySelector('.tdesign-starter-layout');
    },
    rehandlePageChange(curr, pageInfo) {
      console.log('分页变化', curr, pageInfo);
      this.pagination.current = curr.current
      if(this.pagination.pageSize != curr.pageSize){
          this.pagination.current = 1
          this.pagination.pageSize = curr.pageSize
      }
      this.getList("")
    },
    rehandleSelectChange(selectedRowKeys: number[]) {
      this.selectedRowKeys = selectedRowKeys;
    },
    rehandleChange(changeParams, triggerAndData) {
      console.log('统一Change', changeParams, triggerAndData);
    },
    handleClickDetail(e) {
      console.log(e)
      const { req_uuid } = e.row
      console.log(req_uuid)
      /* this.$router.push(
      {name:'WafAttackLogDetail',params: {
          req_uuid: req_uuid,
        },
      }, */
      this.$router.push(
      {
        path:'/waf/wafattacklogdetail',
        query: {
          req_uuid: req_uuid,
        },
      },
    );
    },
    handleSetupContract() {
      this.$router.push('/form/base');
    },
    handleClickDelete(row: { rowIndex: any }) {
      this.deleteIdx = row.rowIndex;
      this.confirmVisible = true;
    },
    onConfirmDelete() {
      // 真实业务请发起请求
      this.data.splice(this.deleteIdx, 1);
      this.pagination.total = this.data.length;
      const selectedIdx = this.selectedRowKeys.indexOf(this.deleteIdx);
      if (selectedIdx > -1) {
        this.selectedRowKeys.splice(selectedIdx, 1);
      }
      this.confirmVisible = false;
      this.$message.success('删除成功');
      this.resetIdx();
    },
    onCancel() {
      this.resetIdx();
    },
    resetIdx() {
      this.deleteIdx = -1;
    },
  },
});
</script>

<style lang="less" scoped>
@import '@/style/variables';

.payment-col {
  display: flex;

  .trend-container {
    display: flex;
    align-items: center;
    margin-left: 8px;
  }
}

.left-operation-container {
  padding: 0 0 6px 0;
  margin-bottom: 16px;

  .selected-count {
    display: inline-block;
    margin-left: 8px;
    color: var(--td-text-color-secondary);
  }
}

.search-input {
  width: 360px;
}

.t-button + .t-button {
    margin-left: @spacer;
 }
</style>
