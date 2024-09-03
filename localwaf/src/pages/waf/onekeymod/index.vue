<template>
  <div>
    <t-card class="list-card-container">
      <t-row justify="space-between">
        <div class="left-operation-container">

          {{ $t('page.one_key_mod.one_key_placeholder')}}

          <span>{{ $t('page.one_key_mod.baota_placeholder') }}:</span>
          <t-input v-model="defaultFilePath" class="search-input" :placeholder="$t('page.one_key_mod.baota_placeholder')" clearable>
          </t-input>
          <t-button @click="handleOneKeyModify"> {{ $t('page.one_key_mod.button_one_key_modify') }} </t-button>
        </div>
        <div class="right-operation-container">
          <t-form ref="form" :data="searchformData" :label-width="80" colon :style="{ marginBottom: '8px' }">

            <t-row>

              <t-button theme="primary" :style="{ marginLeft: '8px' }" @click="getList('all')"> {{ $t('common.search') }} </t-button>
            </t-row>
          </t-form>
        </div>
      </t-row>

      <t-alert theme="info" :message="$t('page.one_key_mod.modify_logs')" close>
        <template #operation>

          <span @click="handleJumpOnlineUrl">{{ $t('common.online_document') }}</span>
        </template>
      </t-alert>
      <div class="table-container">
        <t-table :columns="columns" :data="data" :rowKey="rowKey" :verticalAlign="verticalAlign" :hover="hover"
          :pagination="pagination" :selected-row-keys="selectedRowKeys" :loading="dataLoading"
          @page-change="rehandlePageChange" @change="rehandleChange" @select-change="rehandleSelectChange"
          :headerAffixedTop="true" :headerAffixProps="{ offsetTop: offsetTop, container: getContainer }">

          <template #op="slotProps">
             <a class="t-button-link" @click="handleClickEdit(slotProps)">{{$t('common.details')}}</a>
            <a class="t-button-link" @click="handleClickDelete(slotProps)">{{$t('common.delete')}}</a>
          </template>
        </t-table>
      </div>
      <div>
      <router-view></router-view>
      </div>
    </t-card>


    <t-dialog :header="$t('common.details')" :visible.sync="editFormVisible" :width="680" :footer="false">
      <div slot="body">
        <t-form :data="formEditData" ref="form" :labelWidth="100">
          <t-form-item :label="$t('page.one_key_mod.label_op_system')" name="op_system">
           <t-input :style="{ width: '480px' }" v-model="formEditData.op_system" placeholder=""></t-input>
          </t-form-item>
          <t-form-item :label="$t('page.one_key_mod.label_file_path')" name="file_path">
            <t-input :style="{ width: '480px' }" v-model="formEditData.file_path" placeholder=""></t-input>
          </t-form-item>
          <t-form-item :label="$t('page.one_key_mod.label_before_content')" name="before_content">
            <t-textarea :style="{ width: '480px' }"  :autosize="{ minRows: 5, maxRows: 10 }"  v-model="formEditData.before_content" name="before_content">
            </t-textarea>
          </t-form-item>
          <t-form-item :label="$t('page.one_key_mod.label_after_content')" name="after_content">
            <t-textarea :style="{ width: '480px' }" :autosize="{ minRows: 5, maxRows: 10 }"  v-model="formEditData.after_content"  name="after_content">
            </t-textarea>
          </t-form-item>
          <t-form-item style="float: right">
            <t-button variant="outline" @click="onClickCloseEditBtn">{{ $t('common.close') }}</t-button>
          </t-form-item>
        </t-form>
      </div>
    </t-dialog>

    <t-dialog :header="$t('common.confirm_delete')" :body="confirmBody" :visible.sync="confirmVisible" @confirm="onConfirmDelete"
      :onCancel="onCancel">
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
    allhost
  } from '@/apis/host';

import {
    wafOneKeyModDelApi,wafOneKeyModDetailApi,wafOneKeyModListApi,wafDoOneKeyModApi
  } from '@/apis/onekeymod';
  import {
    SSL_STATUS,
    GUARD_STATUS,
    CONTRACT_STATUS,
    CONTRACT_STATUS_OPTIONS,
    CONTRACT_TYPES,
    CONTRACT_PAYMENT_TYPES
  } from '@/constants';

  const INITIAL_DATA = {
    host_code: '',
    url: '',
    rate: 1,
    limit: 30,
    remarks: '',
  };
  export default Vue.extend({
    name: 'ListBase',
    components: {
      SearchIcon,
      Trend,
    },
    data() {
      return {
        defaultFilePath:"/www/server/panel/vhost/nginx",
        addFormVisible: false,
        editFormVisible: false,
        guardVisible: false,
        confirmVisible: false,
        formData: {
          ...INITIAL_DATA
        },
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
            title: this.$t('page.one_key_mod.label_op_system'),
            align: 'left',
            width: 60,
            ellipsis: true,
            colKey: 'op_system',
          },
          {
            title: this.$t('page.one_key_mod.label_file_path'),
            width: 450,
            ellipsis: true,
            colKey: 'file_path',
          },
          {
            title: this.$t('common.create_time'),
            width: 130,
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
        // 与pagination对齐
        pagination: {
          total: 0,
          current: 1,
          pageSize: 10
        },
        //顶部搜索
        searchformData: {
          url:"",
          host_code:""
        },
        //索引区域
        deleteIdx: -1,
        guardStatusIdx :-1,
        //主机字典
        host_dic:{}
      };
    },
    computed: {
      confirmBody() {
        if (this.deleteIdx > -1) {
          const {
            url
          } = this.data?. [this.deleteIdx];
          return this.$t('common.confirm_delete');
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
      getList(keyword) {
        let that = this
        wafOneKeyModListApi( {
              pageSize: that.pagination.pageSize,
              pageIndex: that.pagination.current,
              ... that.searchformData
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
        this.formData = {};
      },
      onClickCloseEditBtn(): void {
        this.editFormVisible = false;
        this.formEditData = {};
      },
      handleClickDelete(row) {
        console.log(row)
        this.deleteIdx = row.rowIndex;
        this.confirmVisible = true;
      },
      onConfirmDelete() {
        this.confirmVisible = false;
        console.log('delete', this.data)
        console.log('delete', this.data[this.deleteIdx])
        let {
          id
        } = this.data[this.deleteIdx]
        let that = this
        wafOneKeyModDelApi( {
              id: id
          })
          .then((res) => {
            let resdata = res
            console.log(resdata)
            if (resdata.code === 0) {

              that.pagination.current = 1
              that.getList("")
              that.$message.success(resdata.msg);
            } else {
              that.$message.warning(resdata.msg);
            }
          })
          .catch((e: Error) => {
            console.log(e);
          })
          .finally(() => {});


        this.resetIdx();
      },
      onCancel() {
        this.resetIdx();
      },
      resetIdx() {
        this.deleteIdx = -1;
      },
      getDetail(id) {
        let that = this
        wafOneKeyModDetailApi( {
              id: id
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
      //跳转界面
      handleJumpOnlineUrl(){
        window.open(this.samwafglobalconfig.getOnlineUrl()+"/guide/OneKeyMod.html");
      },
      //一键修改
      handleOneKeyModify(){
        let that = this
        wafDoOneKeyModApi( {
          file_path:that.defaultFilePath
        })
          .then((res) => {
            let resdata = res
            console.log(resdata)
            if (resdata.code === 0) {
              that.$message.success(resdata.msg);
            }else{
              that.$message.warning(resdata.msg);
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
