<template>
  <div>
    <t-card class="list-card-container">
      <t-row justify="space-between">
        <div class="left-operation-container">
          <t-button @click="handleAddAccount"> {{$t('page.account.create_account')}} </t-button>
        </div>
        <div class="right-operation-container">
          <t-form ref="form" :data="searchformData" :label-width="80" colon :style="{ marginBottom: '8px' }">

            <t-row>
              <span>{{$t('page.account.login_account_label')}}</span>
              <t-input v-model="searchformData.login_account" class="search-input" :placeholder="$t('common.placeholder_content')" clearable>
              </t-input>
              <t-button theme="primary" :style="{ marginLeft: '8px' }" @click="getList('all')"> {{$t('common.search')}} </t-button>
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
            <a class="t-button-link" @click="handleClickResetPwd(slotProps)">{{$t('common.reset_password')}}</a>
            <a class="t-button-link" @click="handleClickEdit(slotProps)">{{$t('common.edit')}}</a>
            <a class="t-button-link" @click="handleClickDelete(slotProps)">{{$t('common.delete')}}</a>
          </template>
        </t-table>
      </div>
      <div>
      <router-view></router-view>
      </div>
    </t-card>

    <!-- 新建账号弹窗 -->
    <t-dialog :header="$t('page.account.create_account')" :visible.sync="addFormVisible" :width="680" :footer="false">
      <div slot="body">
        <!-- 表单内容 -->
        <t-form :data="formData" ref="form" :rules="rules" @submit="onSubmit" :labelWidth="100">
          <t-form-item :label="$t('page.account.login_account_label')" name="login_account">
              <t-input :style="{ width: '480px' }" v-model="formData.login_account" :placeholder="$t('common.placeholder')+$t('page.account.login_account_label')"></t-input>
          </t-form-item>
          <t-form-item :label="$t('page.account.role')" name="role">
            <t-select v-model="formData.role" clearable :style="{ width: '480px' }">
              <t-option v-for="(item, index) in roleType" :value="item.value" :label="item.label"
                        :key="index">
                {{ item.label }}
              </t-option>
            </t-select>
          </t-form-item>
          <t-form-item :label="$t('page.account.login_password')" name="login_password">
            <t-input :style="{ width: '480px' }" type="password"  v-model="formData.login_password" :placeholder="$t('common.placeholder')+$t('page.account.login_password')"></t-input>
          </t-form-item>
          <t-form-item :label="$t('common.status')" name="rate">
            <t-input-number :style="{ width: '480px' }" v-model="formData.status" :placeholder="$t('common.placeholder')+$t('common.status')"></t-input-number>
          </t-form-item>
          <t-form-item :label="$t('common.remarks')" name="remarks">
            <t-textarea :style="{ width: '480px' }" v-model="formData.remarks" :placeholder="$t('common.placeholder')+$t('common.remarks')" name="remarks">
            </t-textarea>
          </t-form-item>
          <t-form-item style="float: right">
            <t-button variant="outline" @click="onClickCloseBtn">{{ $t('common.cancel') }}</t-button>
            <t-button theme="primary" type="submit">{{ $t('common.confirm') }}</t-button>
          </t-form-item>
        </t-form>
      </div>
    </t-dialog>

    <!-- 编辑账号弹窗 -->
    <t-dialog :header="$t('common.edit')" :visible.sync="editFormVisible" :width="680" :footer="false">
      <div slot="body">
        <!-- 表单内容 -->
        <t-form :data="formEditData" ref="form" :rules="rules" @submit="onSubmitEdit" :labelWidth="100">
          <t-form-item :label="$t('page.account.login_account_label')" name="login_account">
           <t-input :style="{ width: '480px' }" v-model="formEditData.login_account" :placeholder="$t('common.placeholder')+$t('page.account.login_account_label')"></t-input>
          </t-form-item>
          <t-form-item :label="$t('common.status')" name="status">
            <t-input-number :style="{ width: '480px' }" v-model="formEditData.status" :placeholder="$t('common.placeholder')+$t('common.status')"></t-input-number>
          </t-form-item>
          <t-form-item :label="$t('common.remarks')" name="remarks">
            <t-textarea :style="{ width: '480px' }" v-model="formEditData.remarks" :placeholder="$t('common.placeholder')+$t('common.remarks')" name="remarks">
            </t-textarea>
          </t-form-item>
          <t-form-item style="float: right">
            <t-button variant="outline" @click="onClickCloseEditBtn">{{ $t('common.cancel') }}</t-button>
            <t-button theme="primary" type="submit">{{ $t('common.confirm') }}</t-button>
          </t-form-item>
        </t-form>
      </div>
    </t-dialog>
    <!-- 重置密码弹窗 -->
    <t-dialog :header="$t('page.account.reset_password')" :visible.sync="resetPwdFormVisible" :width="680" :footer="false">
      <div slot="body">
        <!-- 表单内容 -->
        <t-form :data="formResetPwdData" ref="form" :rules="resetPwdRules" @submit="onSubmitResetPwd" :labelWidth="100">
          <t-form-item :label="$t('page.account.login_account_label')" name="login_account">
            <t-input :style="{ width: '480px' }" v-model="formResetPwdData.login_account" :placeholder="$t('common.placeholder')+$t('page.account.login_account_label')"></t-input>
          </t-form-item>
          <t-form-item :label="$t('page.account.super_admin_password')" name="login_super_password">
            <t-input :style="{ width: '480px' }" type="password" v-model="formResetPwdData.login_super_password" :placeholder="$t('common.placeholder')+$t('page.account.super_admin_password')"></t-input>
          </t-form-item>
          <t-form-item :label="$t('page.account.new_password')" name="login_new_password">
            <t-input :style="{ width: '480px' }" type="password"  v-model="formResetPwdData.login_new_password" :placeholder="$t('common.placeholder')+$t('page.account.new_password')"></t-input>
          </t-form-item>
          <t-form-item :label="$t('page.account.confirm_password')" name="login_new_password2">
            <t-input :style="{ width: '480px' }" type="password"  v-model="formResetPwdData.login_new_password2" :placeholder="$t('common.placeholder')+$t('page.account.confirm_password')"></t-input>
          </t-form-item>
          <t-form-item style="float: right">
            <t-button variant="outline" @click="onClickCloseEditBtn">{{ $t('common.cancel') }}</t-button>
            <t-button theme="primary" type="submit">{{ $t('common.confirm') }}</t-button>
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
    account_list_api
  } from '@/apis/account';

  const INITIAL_DATA = {
    login_account: '',
    login_password: '',
    status: 1,
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
        resetPwdFormVisible:false,
        formData: {
          ...INITIAL_DATA
        },
        formEditData: {
          ...INITIAL_DATA
        },
        formResetPwdData: {
          login_account: '',
          login_super_password: '',
          login_new_password: '',
          login_new_password2: '',
          id:"",
        },
        rules: {
          login_account: [{
            required: true,
            message: this.$t('common.placeholder')+this.$t('page.account.login_account_label'),
            type: 'error'
          }],
          login_password: [{
            required: true,
            message: this.$t('common.placeholder')+this.$t('page.account.login_password'),
            type: 'error'
          }],
        },
        resetPwdRules: {
          login_account: [{
            required: true,
            message: this.$t('common.placeholder')+this.$t('page.account.login_account_label'),
            type: 'error'
          }],
          login_super_password: [{
            required: true,
            message: this.$t('common.placeholder')+this.$t('page.account.super_admin_password'),
            type: 'error'
          }],
          login_new_password: [{
            required: true,
            message: this.$t('common.placeholder')+this.$t('page.account.new_password'),
            type: 'error'
          }],
          login_new_password2: [{
            required: true,
            message: this.$t('common.placeholder')+this.$t('page.account.confirm_password'),
            type: 'error'
          }],
        },
        roleType: [
          {
          label: this.$t('page.account.role_super_admin'),
          value: 'superAdmin'
         },
          {
            label: this.$t('page.account.role_admin'),
            value: 'admin'
          }
        ],
        textareaValue: '',
        prefix,
        dataLoading: false,
        data: [], //列表数据信息
        detail_data: [], //加载详情信息用于编辑
        selectedRowKeys: [],
        value: 'first',
        columns: [
          {
            title: this.$t('page.account.login_account_label'),
            align: 'left',
            width: 250,
            ellipsis: true,
            colKey: 'login_account',
          },
          {
            title: this.$t('page.account.role'),
            align: 'left',
            width: 250,
            ellipsis: true,
            colKey: 'role',
          },
          {
            title: this.$t('common.remarks'),
            width: 200,
            ellipsis: true,
            colKey: 'remarks',
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
        // 与pagination对齐
        pagination: {
          total: 0,
          current: 1,
          pageSize: 10
        },
        //顶部搜索
        searchformData: {
          login_account:"",
        },
        //索引区域
        deleteIdx: -1,
        guardStatusIdx :-1,
      };
    },
    computed: {
      confirmBody() {
        if (this.deleteIdx > -1) {
          const {
            url
          } = this.data?. [this.deleteIdx];
          return this.$t('common.data_delete_warning');
        }
        return '';
      },
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
        /* let that = this;
        allhost().then((res) => {
              let resdata = res
              console.log(resdata)
              if (resdata.code === 0) {
                  that.host_options = resdata.data;
              }
            })
            .catch((e: Error) => {
              console.log(e);
        }) */
      },
      getList(keyword) {
        let that = this
        account_list_api({
              pageSize: that.pagination.pageSize,
              pageIndex: that.pagination.current,
              ...that.searchformData
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
        console.log('list',id)
        this.$router.push({
          path: '/account/detail',
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
      handleAddAccount() {
        //添加
        this.addFormVisible = true
        this.formData =  {
          login_account: '',
          login_password: '',
          remarks: '',
          status:1,
        };
      },
      handleClickResetPwd(e) {
        console.log(e)
        const {
          id
        } = e.row
        console.log(id)
        this.resetPwdFormVisible = true
        this.getDetailModifyPwd(id)
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
          this.$request
            .post('/account/add', {
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
          this.$request
            .post('/account/edit', {
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
      /**
       * 重置密码
       * @param result
       * @param firstError
       */
      onSubmitResetPwd({
                     result,
                     firstError
                   }): void {
        let that = this
        if (!firstError) {

          if(that.formResetPwdData.login_new_password != that.formResetPwdData.login_new_password2){
            that.$message.warning(this.$t('page.account.password_mismatch_warning'))
            return;
          }
          let postdata = {
            ...that.formResetPwdData
          }
          this.$request
            .post('/account/resetpwd', {
              ...postdata
            })
            .then((res) => {
              let resdata = res
              console.log(resdata)
              if (resdata.code === 0) {
                that.$message.success(resdata.msg);
                that.resetPwdFormVisible = false;
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
        if(row.row.login_account=="admin"){
            alert(this.$t('page.account.admin_delete_warning'))
            return;
        }
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
        this.$request
          .get('/account/del', {
            params: {
              id: id,
            }
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
        this.$request
          .get('/account/detail', {
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
      getDetailModifyPwd(id) {
        let that = this
        this.$request
          .get('/account/detail', {
            params: {
              id: id,
            }
          })
          .then((res) => {
            let resdata = res
            console.log(resdata)
            if (resdata.code === 0) {
              that.formResetPwdData.login_account =  resdata.data.login_account
              that.formResetPwdData.id = id
            }
          })
          .catch((e: Error) => {
            console.log(e);
          })
          .finally(() => {});
      },
      //end methods
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
