<template>
  <div>
    <t-card class="list-card-container">
      <t-row justify="space-between">
        <div class="left-operation-container">
          <t-button @click="handleChangeLocalClear"> {{$t('page.center.switch_local')}}  </t-button>
        </div>
        <div class="right-operation-container">
          <t-form ref="form" :data="searchformData" :label-width="80" colon :style="{ marginBottom: '8px' }">

            <t-row>
              <t-button theme="primary" :style="{ marginLeft: '8px' }" @click="getList('all')"> {{ $t('common.search') }}</t-button>
            </t-row>
          </t-form>
        </div>
      </t-row>
      <div class="table-container">
        <t-table :columns="columns" :data="data" :rowKey="rowKey" :verticalAlign="verticalAlign" :hover="hover"
                 :pagination="pagination" :selected-row-keys="selectedRowKeys" :loading="dataLoading"
                 @page-change="rehandlePageChange" @change="rehandleChange" @select-change="rehandleSelectChange"
                 :headerAffixedTop="true" :headerAffixProps="{ offsetTop: offsetTop, container: getContainer }">

          <template #op="slotProps">
            <a class="t-button-link" v-if="pagination.total<=freeClientCount || isVip" @click="handleClickChangeServer(slotProps)">{{ $t('page.center.server_switch_button') }}</a>
            <a class="t-button-link" @click="handleClickDelete(slotProps)">{{ $t('common.delete') }}</a>
          </template>
        </t-table>
      </div>
      <div>
        <router-view></router-view>
      </div>
    </t-card>
  </div>
</template>
<script lang="ts">
import Vue from 'vue';
import {SearchIcon} from 'tdesign-icons-vue';
import Trend from '@/components/trend/index.vue';
import {prefix, TOKEN_NAME} from '@/config/global';
import {getLicenseDetailApi} from '@/apis/license';
import {centerListApi} from "../../../apis/center";
const INITIAL_REG_DATA = {
  version: '',
  username: '',
  member_type: '',
  machine_id: '',
  expiry_date: '',
  is_expiry:false,
};
const INITIAL_DATA = {
  client_server_name: '',
  client_ip: '',
  client_port: '',
  client_new_version: '',
  client_new_version_desc: '',
  client_system_type: '',
  last_visit_time: '',
};
export default Vue.extend({
  name: 'ListBase',
  components: {
    SearchIcon,
    Trend,
  },
  data() {
    return {
      regData: {
        ...INITIAL_REG_DATA
      },
      isVip:false,
      freeClientCount:1,
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
          title: this.$t('page.center.client_server_name'),
          align: 'left',
          width: 250,
          ellipsis: true,
          colKey: 'client_server_name',
        },
        {
          title:this.$t('page.center.client_system_type'),
          width: 100,
          ellipsis: true,
          colKey: 'client_system_type',
        }, {
          title: this.$t('page.center.client_ip'),
          width: 150,
          ellipsis: true,
          colKey: 'client_ip',
        }, {
          title: this.$t('page.center.client_port'),
          width: 100,
          ellipsis: true,
          colKey: 'client_port',
        },{
          title: this.$t('page.center.client_new_version'),
          width: 100,
          ellipsis: true,
          colKey: 'client_new_version',
        }, {
          title: this.$t('page.center.client_new_version_desc'),
          width: 200,
          ellipsis: true,
          colKey: 'client_new_version_desc',
        },
        {
          align: 'left',
          width: 200,
          colKey: 'op',
          title: this.$t('common.op'),
        },
        {
          title:this.$t('page.center.last_visit_time'),
          width: 200,
          ellipsis: true,
          colKey: 'last_visit_time',
        },
        {
          title: this.$t('common.create_time'),
          width: 200,
          ellipsis: true,
          colKey: 'create_time',
        },

      ],
      rowKey: 'id',
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
      },
      //索引区域
      deleteIdx: -1,
      guardStatusIdx: -1,
    };
  },
  computed: {
    offsetTop() {
      return this.$store.state.setting.isUseTabsRouter ? 48 : 0;
    },
  },
  mounted() {
    this.getList("")
    this.loadCurrentLicense()
  },

  methods: {
    loadCurrentLicense() {
      let that = this
      getLicenseDetailApi({})
        .then((res) => {
          let resdata = res
          console.log(resdata)
          if (resdata.code === 0) {
            that.regData = resdata.data.license;
            if(that.regData.username!="" && that.regData.is_expiry == false){
              that.isVip = true
            }
          }
        })
        .catch((e: Error) => {
          console.log(e);
        })
        .finally(() => {
        });
    },
    /**
     * 切换本机不进行数据处理
     */
    handleChangeLocalClear(){
      localStorage.removeItem("current_server");
      location.reload()
    },
    getList(keyword) {
      let that = this
      centerListApi({
        pageSize: that.pagination.pageSize,
        pageIndex: that.pagination.current
      })
        .then((res) => {
          let resdata = res
          console.log(resdata)
          if (resdata.code === 0) {

            this.data = resdata.data.list;
            this.data_attach = []
            console.log('getList', this.data)
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
      console.log('统一Change', changeParams, triggerAndData);
    },
    handleClickChangeServer(e){
      console.log(e)
      const {
        id
      } = e.row
      console.log(id)
      localStorage.setItem("current_server",JSON.stringify(e.row))
      location.reload()
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
    handleAddAntiCC() {
      //添加CC防护
      this.addFormVisible = true
      this.formData = {
        host_code: '',
        url: '',
        remarks: '',
        rate: 1,
        limit: 30
      };
    },
    onSubmit({
               result,
               firstError
             }): void {
      let that = this
      if (!firstError) {

        let postdata = {
          ...that.formData
        }
        wafAntiCCAddApi({
          ...postdata
        })
          .then((res) => {
            let resdata = res
            console.log(resdata)
            if (resdata.code === 0) {
              that.$message.success(resdata.msg);
              that.addFormVisible = false;
              that.pagination.current = 1
              that.getList("")
            } else {
              that.$message.warning(resdata.msg);
            }
          })
          .catch((e: Error) => {
            console.log(e);
          })
          .finally(() => {
          });
      } else {
        console.log('Errors: ', result);
        that.$message.warning(firstError);
      }
    },
    onSubmitEdit({
                   result,
                   firstError
                 }): void {
      let that = this
      if (!firstError) {

        let postdata = {
          ...that.formEditData
        }
        wafAntiCCEditApi({
          ...postdata
        })
          .then((res) => {
            let resdata = res
            console.log(resdata)
            if (resdata.code === 0) {
              that.$message.success(resdata.msg);
              that.editFormVisible = false;
              that.pagination.current = 1
              that.getList("")
            } else {
              that.$message.warning(resdata.msg);
            }
          })
          .catch((e: Error) => {
            console.log(e);
          })
          .finally(() => {
          });
      } else {
        console.log('Errors: ', result);
        that.$message.warning(firstError);
      }
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
      wafAntiCCDelApi({
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
        .finally(() => {
        });


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
      wafAntiCCDetailApi({
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
        .finally(() => {
        });
    },
    //跳转界面
    handleJumpOnlineUrl() {
      window.open(this.samwafglobalconfig.getOnlineUrl() + "/guide/CC.html");
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
