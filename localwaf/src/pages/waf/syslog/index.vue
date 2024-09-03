<template>
  <div>
    <t-card class="list-card-container">
      <t-row justify="space-between">
        <div class="left-operation-container">
        </div>
        <t-input v-model="searchValue" class="search-input" :placeholder="$t('page.syslog.syslog')" clearable>
          <template #suffix-icon>
            <search-icon size="20px" />
          </template>
        </t-input>
      </t-row>
      <div class="table-container">
        <t-table :columns="columns" :data="data" :rowKey="rowKey" :verticalAlign="verticalAlign" :hover="hover"
          :pagination="pagination" :selected-row-keys="selectedRowKeys" :loading="dataLoading"
          @page-change="rehandlePageChange" @change="rehandleChange" @select-change="rehandleSelectChange"
          :headerAffixedTop="true" :headerAffixProps="{ offsetTop: offsetTop, container: getContainer }">
          <template #op="slotProps">
            <a class="t-button-link" @click="handleClickEdit(slotProps)">{{ $t('common.details') }}</a>
          </template>
        </t-table>
      </div>
      <div>
      <router-view></router-view>
      </div>
    </t-card>

    <t-dialog :header="$t('common.details')" :visible.sync="editFormVisible" :width="680" :footer="false">
      <div slot="body">
        <t-form :data="formEditData" ref="form" :rules="rules" :labelWidth="100">
          <t-form-item :label="$t('page.syslog.label_op_type')" name="op_type">
            <t-input :style="{ width: '480px' }" v-model="formEditData.op_type" ></t-input>
          </t-form-item>

          <t-form-item :label="$t('page.syslog.label_op_content')" name="op_content">
            <t-textarea :style="{ width: '480px' }" v-model="formEditData.op_content"  name="op_content">
            </t-textarea>
          </t-form-item>
          <t-form-item style="float: right">
            <t-button variant="outline" @click="onClickCloseEditBtn">{{ $t('common.close') }}</t-button>
          </t-form-item>
        </t-form>
      </div>
    </t-dialog>

  </div>
</template>
<script lang="ts">
  import Vue from 'vue';
  import {
    SearchIcon
  } from 'tdesign-icons-vue';
  import Trend from '@/components/trend/index.vue';
  import {
    prefix
  } from '@/config/global';
  import {
    sys_log_list_api
  } from '@/apis/syslog';


  import {
    SSL_STATUS,
    GUARD_STATUS,
    CONTRACT_STATUS,
    CONTRACT_STATUS_OPTIONS,
    CONTRACT_TYPES,
    CONTRACT_PAYMENT_TYPES
  } from '@/constants';

  const INITIAL_DATA = {
    login_account: '',
    op_type: '',
    op_content: '',
  };
  export default Vue.extend({
    name: 'ListBase',
    components: {
      SearchIcon,
      Trend,
    },
    data() {
      return {
        addFormVisible: false,
        editFormVisible: false,
        formEditData: {
          ...INITIAL_DATA
        },
        rules: {
        },
        textareaValue: '',
        prefix,
        dataLoading: false,
        data: [], //列表数据信息
        detail_data: [], //加载详情信息用于编辑
        selectedRowKeys: [],
        value: 'first',
        columns: [
          {
            title: this.$t('page.syslog.label_op_type'),
            width: 200,
            ellipsis: true,
            colKey: 'op_type',
          },
          {
            title: this.$t('page.syslog.label_op_content'),
            width: 200,
            ellipsis: true,
            colKey: 'op_content',
          },
          {
            title: this.$t('common.create_time'),
            width: 200,
            ellipsis: true,
            colKey: 'create_time',
          },
          {
            align: 'left',
            width: 200,
            colKey: 'op',
            title: this.$t('common.op'),
          },
        ],
        rowKey: 'code',
        tableLayout: 'auto',
        verticalAlign: 'top',
        hover: true,
        rowClassName: (rowKey: string) => `${rowKey}-class`,
        pagination: {
          total: 0,
          current: 1,
          pageSize: 10
        },
        searchValue: '',
        //索引区域
        deleteIdx: -1,
      };
    },
    computed: {
      offsetTop() {
        return this.$store.state.setting.isUseTabsRouter ? 48 : 0;
      },
    },
    mounted() {
      this.getList("")
      this.loadHostList()
    },

    methods: {
      loadHostList(){
      },
      getList(keyword) {
        let that = this
        this.$request
          .get('/sys_log/list', {
            params: {
              pageSize: that.pagination.pageSize,
              pageIndex: that.pagination.current,
              op_type: '',
              op_content: '',
            }
          })
          .then((res) => {
            let resdata = res
            console.log(resdata)
            if (resdata.code === 0) {

              this.data = resdata.data.list;
              this.data_attach = []
              console.log('getList',this.data)
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
        this.pagination.current = curr.current
        if (this.pagination.pageSize != curr.pageSize) {
          this.pagination.current = 1
          this.pagination.pageSize = curr.pageSize
        }
        this.getList("")
      },
      rehandleSelectChange(selectedRowKeys: number[]) {
        this.selectedRowKeys = selectedRowKeys;
      },
      rehandleChange(changeParams, triggerAndData) {
      },
      handleClickDetail(e) {
        console.log(e)
        const {
          id
        } = e.row
        console.log('hostlist',id)
        this.$router.push({
          path: '/waf-host/anticc/detail',
          query: {
            id: id,
          },
        }, );
      },
      handleClickEdit(e) {
        console.log(e)
        const {
          id
        } = e.row
        console.log(id)
        this.editFormVisible = true
        this.getDetail(id)
      },
      onClickCloseBtn(): void {
        this.formVisible = false;
      },
      onClickCloseEditBtn(): void {
        this.editFormVisible = false;
        this.formEditData = {};
      },
      onCancel() {
        this.resetIdx();
      },
      resetIdx() {
        this.deleteIdx = -1;
      },
      getDetail(id) {
        let that = this
        this.$request
          .get('/sys_log/detail', {
            params: {
              id: id,
            }
          })
          .then((res) => {
            let resdata = res
            console.log(resdata)
            if (resdata.code === 0) {
              that.detail_data = resdata.data;
              that.formEditData = {
                ...that.detail_data
              }
            }
          })
          .catch((e: Error) => {
            console.log(e);
          })
          .finally(() => {});
      },
    },
  });
</script>

<style lang="less" scoped>
  @import '@/style/variables';
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

  .t-button+.t-button {
    margin-left: @spacer;
  }
</style>
