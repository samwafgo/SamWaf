<template>
  <div>
    <t-card class="list-card-container">
      <t-row justify="space-between">
        <div class="left-operation-container">
          <t-button @click="handleAddHost"> 新建防护 </t-button>
          <t-button variant="base" theme="default" :disabled="!selectedRowKeys.length"> 导出日志 </t-button>
          <p v-if="!!selectedRowKeys.length" class="selected-count">已选{{ selectedRowKeys.length }}项</p>
        </div>
        <t-input v-model="searchValue" class="search-input" placeholder="请输入你需要搜索的攻击日志" clearable>
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
          <template #guard_status="{ row }">

            <t-popconfirm theme="default" :visible="row.guard_status_visiable" @visible-change="onVisibleChange">
              <template slot="content">
                <p class="title">防护规则</p>
                <p class="describe">带描述的气泡确认框在主要说明之外增加了操作相关的详细描述</p>
              </template>
              <t-switch size="large" v-model="row.guard_status ===1" :label="['已防护', '未防护']" @change="changeGuardStatus($event,row)">
              </t-switch>
            </t-popconfirm>
            <!--       <t-tag v-if="row.guard_status === GUARD_STATUS.UN_GUARDDING" theme="warning" variant="light">未防护</t-tag>
            <t-tag v-if="row.guard_status === GUARD_STATUS.GUARDDING" theme="success" variant="light">已防护</t-tag> -->



          </template>
          <template #ssl="{ row }">
            <p v-if="row.ssl === SSL_STATUS.NOT_SSL">否</p>
            <p v-if="row.ssl === SSL_STATUS.SSL">是</p>
          </template>
          <template #paymentType="{ row }">
            <p v-if="row.paymentType === CONTRACT_PAYMENT_TYPES.PAYMENT" class="payment-col">
              付款
              <trend class="dashboard-item-trend" type="up" />
            </p>
            <p v-if="row.paymentType === CONTRACT_PAYMENT_TYPES.RECIPT" class="payment-col">
              收款
              <trend class="dashboard-item-trend" type="down" />
            </p>
          </template>

          <template #op="slotProps">
            <a class="t-button-link" @click="handleClickDetail(slotProps)">详情</a>
            <a class="t-button-link" @click="handleClickEdit(slotProps)">编辑</a>
            <a class="t-button-link" @click="handleClickDelete(slotProps)">删除</a>
          </template>
        </t-table>
      </div>
    </t-card>

    <!-- 新建网站防御弹窗 -->
    <t-dialog header="新建网站防御" :visible.sync="addFormVisible" :width="680" :footer="false">
      <div slot="body">
        <!-- 表单内容 -->
        <t-form :data="formData" ref="form" :rules="rules" @submit="onSubmit" :labelWidth="100">
          <t-form-item label="网站" name="host">
            <t-input :style="{ width: '480px' }" v-model="formData.host" placeholder="请输入网站的网址"></t-input>
          </t-form-item>
          <t-form-item label="端口" name="port">
            <t-input-number :style="{ width: '150px' }" v-model="formData.port" placeholder="请输入网站的端口一般是80/443">
            </t-input-number>
          </t-form-item>
          <t-form-item label="加密证书" name="ssl">
            <t-radio-group v-model="formData.ssl">
              <t-radio value="0">非加密</t-radio>
              <t-radio value="1">加密证书（需上传证书）</t-radio>
            </t-radio-group>
          </t-form-item>
          <t-form-item label="证书串" name="certfile" v-if="formData.ssl=='1'">
            <t-textarea :style="{ width: '480px' }" v-model="formData.certfile" placeholder="请输入内容" name="certfile">
            </t-textarea>
          </t-form-item>
          <t-form-item label="密钥串" name="keyfile" v-if="formData.ssl=='1'">
            <t-textarea :style="{ width: '480px' }" v-model="formData.keyfile" placeholder="请输入内容" name="keyfile">
            </t-textarea>
          </t-form-item>
          <t-form-item label="后端系统类型" name="remote_system">
            <t-select v-model="formData.remote_system" clearable :style="{ width: '480px' }">
              <t-option v-for="(item, index) in remote_system_options" :value="item.value" :label="item.label"
                :key="index">
                {{ item.label }}
              </t-option>
            </t-select>
          </t-form-item>
          <t-form-item label="后端应用类型" name="remote_app">
            <t-select v-model="formData.remote_app" clearable :style="{ width: '480px' }">
              <t-option v-for="(item, index) in remote_app_options" :value="item.value" :label="item.label"
                :key="index">
                {{ item.label }}
              </t-option>
            </t-select>
          </t-form-item>
          <t-form-item label="后端域名" name="remote_host">
            <t-input :style="{ width: '480px' }" v-model="formData.remote_host" placeholder="请输入后端域名"></t-input>
          </t-form-item>
          <t-form-item label="后端端口" name="remote_port">
            <t-input-number :style="{ width: '150px' }" v-model="formData.remote_port" placeholder="请输入网站的端口一般是80/443">
            </t-input-number>
          </t-form-item>

          <t-form-item label="备注" name="remarks">
            <t-textarea :style="{ width: '480px' }" v-model="textareaValue" placeholder="请输入内容" name="remarks">
            </t-textarea>
          </t-form-item>
          <t-form-item style="float: right">
            <t-button variant="outline" @click="onClickCloseBtn">取消</t-button>
            <t-button theme="primary" type="submit">确定</t-button>
          </t-form-item>
        </t-form>
      </div>
    </t-dialog>

    <!-- 编辑网站防御弹窗 -->
    <t-dialog header="编辑网站防御" :visible.sync="editFormVisible" :width="680" :footer="false">
      <div slot="body">
        <!-- 表单内容 -->
        <t-form :data="formEditData" ref="form" :rules="rules" @submit="onSubmitEdit" :labelWidth="100">
          <t-form-item label="网站" name="host">
            <t-input :style="{ width: '480px' }" v-model="formEditData.host" placeholder="请输入网站的网址"></t-input>
          </t-form-item>
          <t-form-item label="端口" name="port">
            <t-input-number :style="{ width: '150px' }" v-model="formEditData.port" placeholder="请输入网站的端口一般是80/443">
            </t-input-number>
          </t-form-item>
          <t-form-item label="加密证书" name="ssl">
            <t-radio-group v-model="formEditData.ssl">
              <t-radio value="0">非加密</t-radio>
              <t-radio value="1">加密证书（需填写证书）</t-radio>
            </t-radio-group>
          </t-form-item>
          <t-form-item label="证书串" name="certfile" v-if="formEditData.ssl=='1'">
            <t-textarea :style="{ width: '480px' }" v-model="formEditData.certfile" placeholder="请输入内容" name="certfile">
            </t-textarea>
          </t-form-item>
          <t-form-item label="密钥串" name="keyfile" v-if="formEditData.ssl=='1'">
            <t-textarea :style="{ width: '480px' }" v-model="formEditData.keyfile" placeholder="请输入内容" name="keyfile">
            </t-textarea>
          </t-form-item>
          <t-form-item label="后端系统类型" name="remote_system">
            <t-select v-model="formEditData.remote_system" clearable :style="{ width: '480px' }">
              <t-option v-for="(item, index) in remote_system_options" :value="item.value" :label="item.label"
                :key="index">
                {{ item.label }}
              </t-option>
            </t-select>
          </t-form-item>
          <t-form-item label="后端应用类型" name="remote_app">
            <t-select v-model="formEditData.remote_app" clearable :style="{ width: '480px' }">
              <t-option v-for="(item, index) in remote_app_options" :value="item.value" :label="item.label"
                :key="index">
                {{ item.label }}
              </t-option>
            </t-select>
          </t-form-item>
          <t-form-item label="后端域名" name="remote_host">
            <t-input :style="{ width: '480px' }" v-model="formEditData.remote_host" placeholder="请输入后端域名"></t-input>
          </t-form-item>
          <t-form-item label="后端端口" name="remote_port">
            <t-input-number :style="{ width: '150px' }" v-model="formEditData.remote_port"
              placeholder="请输入网站的端口一般是80/443"></t-input-number>
          </t-form-item>

          <t-form-item label="备注" name="remarks">
            <t-textarea :style="{ width: '480px' }" v-model="textareaValue" placeholder="请输入内容" name="remarks">
            </t-textarea>
          </t-form-item>
          <t-form-item style="float: right">
            <t-button variant="outline" @click="onClickCloseEditBtn">取消</t-button>
            <t-button theme="primary" type="submit">确定</t-button>
          </t-form-item>
        </t-form>
      </div>
    </t-dialog>

    <t-dialog header="确认删除当前所选网站?" :body="confirmBody" :visible.sync="confirmVisible" @confirm="onConfirmDelete"
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
    attacklogList
  } from '@/apis/waflog/attacklog';

  import {
    SSL_STATUS,
    GUARD_STATUS,
    CONTRACT_STATUS,
    CONTRACT_STATUS_OPTIONS,
    CONTRACT_TYPES,
    CONTRACT_PAYMENT_TYPES
  } from '@/constants';

  const INITIAL_DATA = {
    host: 'baidu.com',
    port: 80,
    remote_host: 'baidu2.com',
    remote_port: 80,
    ssl: '0',
    remote_system: "宝塔",
    remote_app: "API业务系统",
    guard_status: '',
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
          host: [{
            required: true,
            message: '请输入网站名称',
            type: 'error'
          }],
        },
        textareaValue: '',
        remote_system_options: [{
            label: '宝塔',
            value: '1'
          },
          {
            label: '小皮面板(phpstudy)',
            value: '2'
          },
          {
            label: 'PHPnow',
            value: '3'
          },
        ],
        remote_app_options: [{
            label: '纯网站',
            value: '1'
          },
          {
            label: 'API业务系统',
            value: '2'
          },
          {
            label: '业务加管理',
            value: '3'
          },
        ],
        GUARD_STATUS,
        SSL_STATUS,
        CONTRACT_STATUS,
        CONTRACT_STATUS_OPTIONS,
        CONTRACT_TYPES,
        CONTRACT_PAYMENT_TYPES,
        prefix,
        dataLoading: false,
        data: [], //列表数据信息
        detail_data: [], //加载详情信息用于编辑
        selectedRowKeys: [],
        value: 'first',
        columns: [{
            colKey: 'row-select',
            type: 'multiple',
            width: 64,
            fixed: 'left'
          },
          {
            title: '网站',
            align: 'left',
            width: 250,
            ellipsis: true,
            colKey: 'host',
            fixed: 'left',
          },
          {
            title: '网站端口',
            width: 200,
            ellipsis: true,
            colKey: 'port',
          },
          {
            title: '防护状态',
            colKey: 'guard_status',
            width: 200,
            cell: {
              col: 'guard_status'
            }
          },
          {
            title: '加密证书',
            width: 200,
            ellipsis: true,
            colKey: 'ssl',
            cell: {
              col: 'ssl'
            }
          },
          {
            title: '备注',
            width: 200,
            ellipsis: true,
            colKey: 'remarks',
          },
          {
            title: '添加时间',
            width: 200,
            ellipsis: true,
            colKey: 'create_time',
          },

          {
            align: 'left',
            fixed: 'right',
            width: 200,
            colKey: 'op',
            title: '操作',
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
        searchValue: '',
        //索引区域
        deleteIdx: -1,
        guardStatusIdx :-1,
      };
    },
    computed: {
      confirmBody() {
        if (this.deleteIdx > -1) {
          const {
            host
          } = this.data?. [this.deleteIdx];
          return `删除后，${host}的所有网站信息和规则将被清空，且无法恢复`;
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
        this.$request
          .get('/wafhost/host/list', {
            params: {
              pageSize: that.pagination.pageSize,
              pageIndex: that.pagination.current,
            }
          })
          .then((res) => {
            let resdata = res
            console.log(resdata)
            if (resdata.code === 0) {

              //const { list = [] } = resdata.data.list;

              this.data = resdata.data.list;
              this.data_attach = []
              for (var i = 0; i < this.data.length; i++) {
                this.data[i].guard_status_visiable = false //可扩充
              }
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
      handleClickDetail(e) {
        console.log(e)
        const {
          code
        } = e.row
        console.log(code)
        this.$router.push({
          path: '/waf-host/wafhostdetail',
          query: {
            code: code,
          },
        }, );
      },
      handleClickEdit(e) {
        console.log(e)
        const {
          code
        } = e.row
        console.log(code)
        this.editFormVisible = true
        this.getDetail(code)
      },
      handleAddHost() {
        //添加host
        this.addFormVisible = true
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
          postdata['ssl'] = Number(postdata['ssl'])
          this.$request
            .post('/wafhost/host/add', {
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
            .finally(() => {});
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
          postdata['ssl'] = Number(postdata['ssl'])
          this.$request
            .post('/wafhost/host/edit', {
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
            .finally(() => {});
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
          code
        } = this.data[this.deleteIdx]
        let that = this
        this.$request
          .get('/wafhost/host/del', {
            params: {
              CODE: code,
            }
          })
          .then((res) => {
            let resdata = res.data
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
        this.$request
          .get('/wafhost/host/detail', {
            params: {
              CODE: id,
            }
          })
          .then((res) => {
            let resdata = res
            console.log(resdata)
            if (resdata.code === 0) {
              that.detail_data = resdata.data;
              that.detail_data.ssl = that.detail_data.ssl.toString()
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
      changeGuardStatus(e,row) {

        console.log(e,row)
        let {code } = row
        let rowIndex = this.data.findIndex(function(value,index,arr){
          console.log("findIndex",value,index,arr)
         return value['code'] == code
        })
        console.log("rowIndex",rowIndex)
        this.data[rowIndex].guard_status_visiable = !this.data [rowIndex].guard_status_visiable
        this.guardStatusIdx = rowIndex
        console.log(e)
      },
      onVisibleChange(val, context = {}) {
        let that = this
        console.log("this.guardStatusIdx",this.guardStatusIdx)
        if(this.guardStatusIdx==-1){
          return
        }

        console.log("this.data",this.data[that.guardStatusIdx])
        let {
          code,guard_status
        } = this.data[this.guardStatusIdx]
        console.log(context, context.trigger)
        // trigger 表示触发来源，可以根据触发来源自由控制 visible
        if (context && context.trigger === 'confirm') {
          console.log('guardStatusIdx',that.guardStatusIdx)
          const msg = that.$message.info('提交中');


          that.$request
            .get('/wafhost/host/guardstatus', {
              params: {
                CODE: code,
                GUARD_STATUS: guard_status==1?0:1,
              }
            })
            .then((res) => {
              let resdata = res
              console.log(resdata)
              if (resdata.code === 0) {
                that.getList("")
                that.$message.close(msg);
                that.$message.success(resdata.msg)
                that.data[that.guardStatusIdx].guard_status_visiable = false
                that.guardStatusIdx = -1;
              } else {
                that.$message.warning(resdata.msg);

              }
            })
            .catch((e: Error) => {
              console.log(e);
            })
            .finally(() => {});
        } else if(context && context.trigger === 'cancel'){
          //TODO 不知此处为何点击无效
          console.log("this.data",that.data)
          console.log("that.data[that.guardStatusIdx]",that.data[that.guardStatusIdx])
          that.data[that.guardStatusIdx].guard_status_visiable = false
          that.guardStatusIdx = -1;
        }
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

  .t-button+.t-button {
    margin-left: @spacer;
  }
</style>
