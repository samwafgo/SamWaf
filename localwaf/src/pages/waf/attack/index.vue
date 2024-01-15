<template>
  <div>
    <t-alert theme="info" message="防御日志" close>
      <template #operation>
        <span @click="handleJumpOnlineUrl">在线文档</span>
      </template>
    </t-alert>
    <t-card class="list-card-container">
      <t-row justify="space-between">
        <t-form ref="form" :data="searchformData" :label-width="80" colon :style="{ marginBottom: '8px' }">
          <t-row>
            <t-col :span="10">
              <t-row :gutter="[16, 24]">
                <t-col :flex="1">
                  <t-form-item label="网站" name="rule">
                    <t-select v-model="searchformData.host_code" clearable :style="{ width: '150px' }">
                      <t-option v-for="(item, index) in host_dic" :value="index" :label="item" :key="index">
                        {{ item }}
                      </t-option>
                    </t-select>
                  </t-form-item>
                </t-col>
                <t-col :flex="1">

                  <t-form-item label="规则名称" name="rule">
                    <t-input v-model="searchformData.rule" class="form-item-content" type="search" placeholder="请输入规则名称"
                      :style="{ minWidth: '134px' }" />
                  </t-form-item>
                </t-col>
                <t-col :flex="1">
                  <t-form-item label="访问状态" name="action">
                    <t-select v-model="searchformData.action" class="form-item-content`" :options="action_options"
                      placeholder="请选择防御状态" :style="{ width: '100px' }" />
                  </t-form-item>
                </t-col>
                <t-col :flex="1">
                  <t-form-item label="响应码" name="status_code">
                    <t-input v-model="searchformData.status_code" class="form-item-content" placeholder="请输入响应码"
                      :style="{ minWidth: '100px' }" />
                  </t-form-item>
                </t-col>
                <t-col :flex="1">
                  <t-form-item label="访问IP" name="src_ip">
                    <t-input v-model="searchformData.src_ip" class="form-item-content" placeholder="请输入访问IP"
                      :style="{ minWidth: '100px' }" />
                  </t-form-item>
                </t-col>
                <t-col :flex="2">
                  <t-form-item label="访问日期" name="unix_add_time">
                    <t-date-range-picker v-model="dateControl.range1" :presets="dateControl.presets" enable-time-picker valueType="YYYY-MM-DD HH:mm:ss" /></t-form-item>
                </t-col>
                <t-col :flex="1">
                  <t-form-item label="访问方法" name="method">
                    <t-select v-model="searchformData.method" class="form-item-content`" :options="method_options"
                      placeholder="请输入访问方法" :style="{ width: '100px' }" />
                  </t-form-item>
                </t-col>
                <t-col :flex="1">
                  <t-form-item label="日志归档库" name="sharedb">
                    <t-select v-model="searchformData.current_db_name" clearable :style="{ width: '150px' }">
                      <t-option v-for="(item, index) in share_db_dic" :value="index" :label="item" :key="index">
                        {{ item }}
                      </t-option>
                    </t-select>
                  </t-form-item>
                </t-col>
              </t-row>
            </t-col>

            <t-col :span="2" class="operation-container">
              <t-button theme="primary" :style="{ marginLeft: '8px' }" @click="getList('all')"> 查询 </t-button>
              <t-button type="reset" variant="base" theme="default"> 重置 </t-button>
            </t-col>
          </t-row>
        </t-form>
      </t-row>

      <div class="table-container">
        <!-- 按钮操作区域 -->
        <!-- <t-space direction="vertical">
          <t-space>
            <t-checkbox v-model="customText" style="margin-left: 16px">自定义列配置按钮</t-checkbox>
          </t-space>
        </t-space> -->
        <t-table :columns="columns" :data="data"  size="small" :rowKey="rowKey" :verticalAlign="verticalAlign"
          :column-controller="columnControllerConfig" :displayColumns.sync="displayColumns" :pagination="pagination"
          :selected-row-keys="selectedRowKeys" :loading="dataLoading"
          @page-change="rehandlePageChange"
          :sort="sorts"
          @change="rehandleChange"
          @select-change="rehandleSelectChange"
          @sort-change="onSortChange"
          @filter-change="onFilterChange"
                 :headerAffixProps="{ offsetTop: offsetTop, container: getContainer }">

          <template #action="{ row }">
            <t-tag v-if="row.action === '放行'" shape="round" theme="success">{{row.action}}</t-tag>
            <t-tag v-if="row.action === '阻止'" shape="round" theme="danger">{{row.action}}</t-tag>
            <t-tag v-if="row.action === '禁止'" shape="round" theme="warning">{{row.action}}</t-tag>

          </template>
          <template #rule="{ row }">
            <t-tag v-if="row.rule !== ''" shape="round" theme="primary" variant="outline">{{row.rule}}</t-tag>
          </template>
          <template #op="slotProps">
            <a class="t-button-link" @click="handleClickIPDetail(slotProps)">查询IP</a>
            <a class="t-button-link" @click="handleClickDetail(slotProps)">详情</a>
            <!-- <a class="t-button-link" @click="handleClickDelete(slotProps)">删除</a> -->
          </template>
        </t-table>
      </div>
    </t-card>
    <t-dialog header="确认删除当前所选日志？" :body="confirmBody" :visible.sync="confirmVisible" @confirm="onConfirmDelete"
      :onCancel="onCancel">
    </t-dialog>
  </div>
</template>
<script lang="ts">
  import Vue from 'vue';
  import { SearchIcon } from 'tdesign-icons-vue';
  import Trend from '@/components/trend/index.vue';
  import { prefix } from '@/config/global';
  import { allsharedblist } from '@/apis/waflog/attacklog';

  import { NowDate, ConvertStringToUnix, ConvertDateToString, ConvertUnixToDate } from '@/utils/date';
  import {
    allhost
  } from '@/apis/host';

  import { CONTRACT_STATUS, CONTRACT_STATUS_OPTIONS, CONTRACT_TYPES, CONTRACT_PAYMENT_TYPES } from '@/constants';
  import { ErrorCircleFilledIcon, CheckCircleFilledIcon, CloseCircleFilledIcon } from 'tdesign-icons-vue';

  const staticColumn = ['action', 'op'];

  const GROUP_COLUMNS = [
    {
      label: '正常维度',
      value: 'index',
      columns: ['action', 'rule', 'create_time'],
    },
    {
      label: '次要维度',
      value: 'secondary',
      columns: ['action', 'rule', 'create_time'],
    },
    {
      label: '数据维度',
      value: 'data',
      columns: ['action', 'rule', 'create_time'],
    },
  ];

  export default Vue.extend({
    name: 'ListBase',
    components: {
      SearchIcon,
      Trend,
    },
    data() {
      return {
        dateControl:{
          presets: {
            最近300天: [ConvertDateToString(new Date(+new Date() - 86400000 * 299)) + " 00:00:00", ConvertDateToString(new Date()) + " 23:59:59"],
            最近7天: [ConvertDateToString(new Date(+new Date() - 86400000 * 6)) + " 00:00:00", ConvertDateToString(new Date()) + " 23:59:59"],
            最近3天: [ConvertDateToString(new Date(+new Date() - 86400000 * 2)) + " 00:00:00", ConvertDateToString(new Date()) + " 23:59:59"],
            今天: [ConvertDateToString(new Date()) + " 00:00:00", ConvertDateToString(new Date()) + " 23:59:59"],
          },
          range1: ['2023-11-01 00:00:00', '2023-11-16 23:59:59'],
        },
        action_options: [
          {
            label: '全部',
            value: ''
          },
          {
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
        method_options: [
          {
            label: '全部',
            value: ''
          },
          {
            label: 'POST',
            value: 'POST'
          },
          {
            label: 'GET',
            value: 'GET'
          },
          {
            label: 'CONNECT',
            value: 'CONNECT'
          }
          ,
          {
            label: 'HEAD',
            value: 'HEAD'
          },
          {
            label: 'OPTIONS',
            value: 'OPTIONS'
          },
          {
            label: 'PRI',
            value: 'PRI'
          }
        ],
        CONTRACT_STATUS,
        CONTRACT_STATUS_OPTIONS,
        CONTRACT_TYPES,
        CONTRACT_PAYMENT_TYPES,
        prefix,
        dataLoading: false,
        data: [],
        selectedRowKeys: [],
        value: 'first',
        customText: false,
        displayColumns: staticColumn.concat(['guest_identification','time_spent','create_time', 'host', 'method', 'url', 'src_ip', 'country']),
        columns: [
          {
            title: '访客身份',
            width: 100,
            ellipsis: true,
            colKey: 'guest_identification',
            filter: {
              type: 'input',
              resetValue: '',
              // 按下 Enter 键时也触发确认搜索
              confirmEvents: ['onEnter'],
              props: {
                placeholder: '输入关键词过滤',
              },
              // 是否显示重置取消按钮，一般情况不需要显示
              showConfirmAndReset: true,
            },
          },
          {
            title: '耗时(ms)',
            width: 100,
            ellipsis: true,
            colKey: 'time_spent',
            sorter: true
          },
          {
            title: '危害程度',
            width: 60,
            ellipsis: true,
            colKey: 'risk_level',
          },
          {
            title: '状态',
            width: 60,
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
            title: '时间',
            width: 170,
            ellipsis: true,
            colKey: 'create_time',
            sorter: true
          },
          {
            title: '域名',
            align: 'left',
            width: 150,
            ellipsis: true,
            colKey: 'host',
          },

          {
            title: '请求',
            width: 70,
            ellipsis: true,
            colKey: 'method',
          },
          {
            title: '来源IP',
            width: 150,
            ellipsis: true,
            colKey: 'src_ip',
          },
          {
            title: '国家',
            width: 100,
            ellipsis: true,
            colKey: 'country',
          },
          {
            title: '省份',
            width: 100,
            ellipsis: true,
            colKey: 'province',
          }, {
            title: '城市',
            width: 100,
            ellipsis: true,
            colKey: 'city',
          },
          {
            title: '访问url',
            width: 300,
            ellipsis: true,
            colKey: 'url',
          },
          {
            title: 'Header',
            width: 300,
            ellipsis: true,
            colKey: 'header',
            filter: {
              type: 'input',
              resetValue: '',
              // 按下 Enter 键时也触发确认搜索
              confirmEvents: ['onEnter'],
              props: {
                placeholder: '输入关键词过滤',
              },
              // 是否显示重置取消按钮，一般情况不需要显示
              showConfirmAndReset: true,
            },
          },
          {
            title: 'status',
            width: 100,
            ellipsis: true,
            colKey: 'status',
          },
          {
            align: 'left',
            width: 200,
            colKey: 'op',
            title: '操作',
          },
        ],
        rowKey: 'REQ_UUID',
        tableLayout: 'auto',
        verticalAlign: 'top',
        hover: true,
        rowClassName: (rowKey : string) => `${rowKey}-class`,
        // 与pagination对齐
        pagination: {
          total: 0,
          current: 1,
          pageSize: 10
        },
        searchValue: '',
        confirmVisible: false,
        deleteIdx: -1,
        //顶部搜索
        searchformData: {
          rule: "",
          action: "",
          src_ip: "",
          host_code: "",
          status_code: "",
          method: "",
          unix_add_time_begin: "",
          unix_add_time_end: "",
          current_db_name:"local_log.db",
        },
        //table 字段
        table:{
          multipleSort:true
        },
        //排序字段
        sorts: {
          sortBy:"create_time",
          descending:true,
        },
        //筛选字段
        filters:{
          filter_by:"",
          filter_value:"",
        },
        //主机字典
        host_dic: {},
        //日志存档字典
        share_db_dic: {}
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
      columnControllerConfig() {
        return {
          placement: this.placement,
          fields: ['action', 'rule', 'create_time', 'host', 'method', 'url', 'header', 'country', 'province', 'city', 'status','risk_level','guest_identification','time_spent'],
          // 弹框组件属性透传
          dialogProps: { preventScrollThrough: true },
          // 列配置按钮属性头像
          buttonProps: this.customText ? { content: '显示列控制', theme: 'primary', variant: 'base' } : undefined,
          // 数据字段分组显示
          groupColumns: this.groupColumn ? GROUP_COLUMNS : undefined,
        };
      },
    },
    created() {
      console.log(NowDate)
      this.dateControl.range1[0] = NowDate + " 00:00:00"
      this.dateControl.range1[1] = NowDate + " 23:59:59"
      this.searchformData.unix_add_time_begin = ConvertStringToUnix(this.dateControl.range1[0]).toString(),
        this.searchformData.unix_add_time_end = ConvertStringToUnix(this.dateControl.range1[1]).toString(),
        // unix_add_time_begin: ConvertStringToUnix(this.range1[0]).toString(),
        //unix_add_time_end: ConvertStringToUnix(this.range1[1]).toString(),
        console.log(this.range1)
    },
    mounted() {
      console.log("attack list mounted ");
      if (this.$route.query.action != null) {
        console.log(this.$route.query.action)
        this.searchformData.action = this.$route.query.action
      }
      // 判断 vuex 中是否有保存的搜索参数

      if (this.$store.state.attacklog.msgData) {
        const attack = this.$store.state.attacklog;
        this.pagination.current = attack.msgData.currentpage;
        this.searchformData = attack.msgData.searchData;   // 可以直接取出整个对象
        console.log('daysrc', attack.msgData.searchData)
        let newrange =  Array()
        newrange[0] = ConvertUnixToDate(parseInt(attack.msgData.searchData.unix_add_time_begin))
        newrange[1] = ConvertUnixToDate(parseInt(attack.msgData.searchData.unix_add_time_end))
        //console.log(this.dateControl.range1)
        this.$set(this.dateControl, "range1", newrange)
      }

      this.loadHostList()
      this.loadShareDbList()
      this.getList("")
    },
    watch: {
      '$route.query.action'(newVal, oldVal) {
        console.log('action changed', newVal, oldVal)
        this.searchformData.action = newVal
        this.getList("")
      },
    },
    beforeRouteLeave(to, from, next) {
      console.log("attack list beforeRouteLeave ");
      // vuex 存储操作
      this.$store.dispatch("attacklog/setAttackMsgData", {
        //query: this.queryParam,
        currentpage: this.pagination.current,
        searchData: this.searchformData,
      })
      next(); // 继续后续的导航解析过程
    },
    methods: {
      loadShareDbList() {
        let that = this;
        allsharedblist("").then((res) => {
          let resdata = res
          console.log("loadShareDbList",resdata)
          if (resdata.code === 0) {
            let share_options = resdata.data;
            for (let i = 0; i < share_options.length; i++) {
              that.share_db_dic[share_options[i].file_name] = share_options[i].file_name+"("+share_options[i].cnt+")"
            }
          }
        })
          .catch((e : Error) => {
            console.log(e);
          })
      },
      loadHostList() {
        let that = this;
        allhost().then((res) => {
          let resdata = res
          console.log(resdata)
          if (resdata.code === 0) {
            let host_options = resdata.data;
            for (let i = 0; i < host_options.length; i++) {
              that.host_dic[host_options[i].value] = host_options[i].label
            }
          }
        })
          .catch((e : Error) => {
            console.log(e);
          })
      },
      getList(keyword) {

        let that = this
        if (keyword != undefined && keyword == "all") {
          that.pagination.current = 1
        }
        that.searchformData.unix_add_time_begin = ConvertStringToUnix(this.dateControl.range1[0]).toString()
        that.searchformData.unix_add_time_end = ConvertStringToUnix(this.dateControl.range1[1]).toString()

        let sort_descending =that.sorts.descending?"desc":"asc"

        this.$request
          .post('/waflog/attack/list', {
            pageSize: that.pagination.pageSize,
            pageIndex: that.pagination.current,
            sort_by: that.sorts.sortBy,
            sort_descending: sort_descending,
            filter_by:that.filters.filter_by,
            filter_value:that.filters.filter_value,
            unix_add_time_begin: ConvertStringToUnix(this.dateControl.range1[0]).toString(),
            unix_add_time_end: ConvertStringToUnix(this.dateControl.range1[1]).toString(),
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
            }else {
              that.$message.warning(resdata.msg);
            }
          })
          .catch((e : Error) => {
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
      rehandleSelectChange(selectedRowKeys : number[]) {
        this.selectedRowKeys = selectedRowKeys;
      },
      rehandleChange(changeParams, triggerAndData) {
        console.log('统一Change', changeParams, triggerAndData);
      },
      handleClickDetail(e) {
        console.log(e)
        const { req_uuid } = e.row
        console.log(req_uuid)
        this.$router.push(
          {
            path: '/waf/wafattacklogdetail',
            query: {
              req_uuid: req_uuid+"#"+this.searchformData.current_db_name,
            },
          },
        );
      },
      handleClickIPDetail(e) {
        console.log(e)
        const { src_ip } = e.row
        this.searchformData.src_ip = src_ip
        this.getList("")

      },
      handleClickDelete(row : { rowIndex : any }) {
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
      //跳转界面
      handleJumpOnlineUrl(){
        window.open(this.samwafglobalconfig.getOnlineUrl()+"/guide/attacklog.html");
      },
      /**
       * table 排序
       */
      onSortChange(sorter){
        console.log('排序',sorter)
        let that = this

        if (sorter != undefined){
          this.sorts.sortBy= sorter.sortBy
          that.sorts.descending= sorter.descending

        }else{
          that.sorts.sortBy="create_time"
          that.sorts.descending= true
        }
        this.getList("")
      },
      /**
       * 访客身份筛选
       */
      filterGuestChange(e){
        console.log("访客身份",e)
      },
      /**
       * 筛选结果
       */
      onFilterChange(e){
        console.log("筛选结果",e)
        this.filters.filter_by = "";
        this.filters.filter_value = "";
        //访客身份
        if(e.guest_identification != undefined){
           this.filters.filter_by = "guest_identification";
           this.filters.filter_value = e.guest_identification ;
        }
        //header
        if(e.header != undefined){
          if(this.filters.filter_by==""){
            this.filters.filter_by = "header";
            this.filters.filter_value = e.header ;
          }else{
            this.filters.filter_by = this.filters.filter_by +"|header";
            this.filters.filter_value = this.filters.filter_value +"|"+ e.header ;
          }
        }
        this.getList("")
      }
      //end meathod
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
