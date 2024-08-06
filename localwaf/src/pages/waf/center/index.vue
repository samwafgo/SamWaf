<template>
  <div>
    <t-card class="list-card-container">
      <t-row justify="space-between">
        <div class="left-operation-container">
          <t-button @click="handleChangeLocalClear"> 切换本机（不进行远程访问） </t-button>
          <p v-if="!!selectedRowKeys.length" class="selected-count">已选{{ selectedRowKeys.length }}项</p>
        </div>
        <div class="right-operation-container">
          <t-form ref="form" :data="searchformData" :label-width="80" colon :style="{ marginBottom: '8px' }">

            <t-row>
             <!-- <span>网站：</span>
              <t-select v-model="searchformData.host_code" clearable :style="{ width: '150px' }">
                <t-option v-for="(item, index) in host_dic" :value="index" :label="item" :key="index">
                  {{ item }}
                </t-option>
              </t-select>
              <span>URL：</span>
              <t-input v-model="searchformData.url" class="search-input" placeholder="请输入" clearable>
              </t-input>-->
              <t-button theme="primary" :style="{ marginLeft: '8px' }" @click="getList('all')"> 查询</t-button>
            </t-row>
          </t-form>
        </div>
      </t-row>
      <t-alert v-if="pagination.total>freeClientCount && isVip==false" theme="warning" message="超出免费台数限额" close>
        <template #operation>
          <span @click="handleJumpLicense">跳转授权信息画面</span>
        </template>
      </t-alert>
      <div class="table-container">
        <t-table :columns="columns" :data="data" :rowKey="rowKey" :verticalAlign="verticalAlign" :hover="hover"
                 :pagination="pagination" :selected-row-keys="selectedRowKeys" :loading="dataLoading"
                 @page-change="rehandlePageChange" @change="rehandleChange" @select-change="rehandleSelectChange"
                 :headerAffixedTop="true" :headerAffixProps="{ offsetTop: offsetTop, container: getContainer }">

          <template #host_code="{ row }">
            <span> {{ host_dic[row.host_code] }}</span>
          </template>

          <template #op="slotProps">
            <a class="t-button-link" v-if="pagination.total<=freeClientCount || isVip" @click="handleClickChangeServer(slotProps)">切换服务器</a>
            <a class="t-button-link" @click="handleClickDelete(slotProps)">删除</a>
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
        host_code: [{
          required: true,
          message: '请输入网站名称',
          type: 'error'
        }],
        rate: [{
          required: true,
          message: '请输入速率',
          type: 'error'
        }],
        limit: [{
          required: true,
          message: '请输入访问次数限制',
          type: 'error'
        }],
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
          title: '客户端名称',
          align: 'left',
          width: 250,
          ellipsis: true,
          colKey: 'client_server_name',
        },
        {
          title: '操作系统类型',
          width: 100,
          ellipsis: true,
          colKey: 'client_system_type',
        }, {
          title: 'IP',
          width: 150,
          ellipsis: true,
          colKey: 'client_ip',
        }, {
          title: '端口',
          width: 100,
          ellipsis: true,
          colKey: 'client_port',
        },{
          title: '版本号',
          width: 100,
          ellipsis: true,
          colKey: 'client_new_version',
        }, {
          title: '版本',
          width: 200,
          ellipsis: true,
          colKey: 'client_new_version_desc',
        },
        {
          align: 'left',
          width: 200,
          colKey: 'op',
          title: '操作',
        },
        {
          title: '最近访问时间',
          width: 200,
          ellipsis: true,
          colKey: 'last_visit_time',
        },
        {
          title: '添加时间',
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
      //主机字典
      host_dic: {}
    };
  },
  computed: {
    confirmBody() {
      if (this.deleteIdx > -1) {
        const {
          url
        } = this.data?. [this.deleteIdx];
        return `确认要删除吗？`;
      }
      return '';
    },
    offsetTop() {
      return this.$store.state.setting.isUseTabsRouter ? 48 : 0;
    },
  },
  mounted() {
    this.getList("")
    this.loadCurrentLicense()
  },

  methods: {
    /**
     * 跳转授权信息*/
    handleJumpLicense(){
      this.$router.push('/center/License');
    },
    /**加载当前授权信息**/
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
