<template>
  <div>
    <t-alert theme="info" :message="$t('page.visit_log.visit_log')" close>
      <template #operation>
        <span @click="handleJumpOnlineUrl">{{ $t('common.online_document') }}</span>
      </template>
    </t-alert>
    <t-card class="list-card-container">
      <t-row justify="space-between">
        <t-form ref="form" :data="searchformData" :label-width="150" colon :style="{ marginBottom: '8px' }">
          <t-row>
            <t-col :span="10">
              <t-row :gutter="[16, 24]">
                <t-col :flex="1">
                  <t-form-item :label="$t('page.visit_log.website')" name="website">
                    <t-select v-model="searchformData.host_code" clearable :style="{ width: '150px' }">
                      <t-option v-for="(item, index) in host_dic" :value="index" :label="item" :key="index">
                        {{ item }}
                      </t-option>
                    </t-select>
                  </t-form-item>
                </t-col>
                <t-col :flex="1">

                  <t-form-item :label="$t('page.visit_log.rule_name')" name="rule">
                    <t-input v-model="searchformData.rule" class="form-item-content" type="search" :placeholder="$t('common.placeholder') + $t('page.visit_log.rule_name')"
                      :style="{ minWidth: '134px' }" />
                  </t-form-item>
                </t-col>
                <t-col :flex="1">
                  <t-form-item :label="$t('page.visit_log.access_status')" name="action">
                    <t-select v-model="searchformData.action" class="form-item-content`" :options="action_options"
                      :placeholder="$t('common.select_placeholder')+$t('page.visit_log.access_status')" :style="{ width: '100px' }" />
                  </t-form-item>
                </t-col>
                <t-col :flex="1">
                  <t-form-item :label="$t('page.visit_log.status_code')" name="status_code">
                    <t-input v-model="searchformData.status_code" class="form-item-content" :placeholder="$t('common.placeholder')+$t('page.visit_log.status_code')"
                      :style="{ minWidth: '100px' }" />
                  </t-form-item>
                </t-col>
                <t-col :flex="1">
                  <t-form-item :label="$t('page.visit_log.source_ip')" name="src_ip">
                    <t-input v-model="searchformData.src_ip" class="form-item-content" :placeholder="$t('common.placeholder')+$t('page.visit_log.source_ip')"
                      :style="{ minWidth: '100px' }" />
                  </t-form-item>
                </t-col>
                <t-col :flex="2">
                  <t-form-item :label="$t('page.visit_log.access_date')" name="unix_add_time">
                    <t-date-range-picker v-model="dateControl.range1" :presets="dateControl.presets" enable-time-picker valueType="YYYY-MM-DD HH:mm:ss" /></t-form-item>
                </t-col>
                <t-col :flex="1">
                  <t-form-item :label="$t('page.visit_log.access_method')" name="method">
                    <t-select v-model="searchformData.method" class="form-item-content`" :options="method_options"
                      :placeholder="$t('common.placeholder') + $t('page.visit_log.access_method')" :style="{ width: '100px' }" />
                  </t-form-item>
                </t-col>
                <t-col :flex="1">
                  <t-form-item :label="$t('page.visit_log.log_archive_db')" name="sharedb">
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
              <t-button theme="primary" :style="{ marginLeft: '8px' }" @click="getList('all')"> {{ $t('common.search') }} </t-button>
              <t-button type="reset" variant="base" theme="default"> {{ $t('common.reset') }}  </t-button>
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
            <a class="t-button-link" @click="handleClickIPDetail(slotProps)">{{$t('common.search') + $t('page.visit_log.source_ip') }}</a>
            <a class="t-button-link" @click="handleClickDetail(slotProps)">{{$t('common.details')}}</a>
          </template>
        </t-table>
      </div>
    </t-card>
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
            label: this.$t('common.defense_status.all'),
            value: ''
          },
          {
            label: this.$t('common.defense_status.stop'),
            value: '阻止'
          },
          {
            label: this.$t('common.defense_status.pass'),
            value: '放行'
          },
          {
            label: this.$t('common.defense_status.forbid'),
            value: '禁止'
          },
        ],
        method_options: [
          {
            label: this.$t('common.all'),
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
            title: this.$t('page.visit_log.guest_identity'),
            width: 100,
            ellipsis: true,
            colKey: 'guest_identification',
            filter: {
              type: 'input',
              resetValue: '',
              // 按下 Enter 键时也触发确认搜索
              confirmEvents: ['onEnter'],
              props: {
                placeholder: this.$t('common.placeholder'),
              },
              // 是否显示重置取消按钮，一般情况不需要显示
              showConfirmAndReset: true,
            },
          },
          {
            title: this.$t('page.visit_log.time_spent'),
            width: 100,
            ellipsis: true,
            colKey: 'time_spent',
            sorter: true
          },
          {
            title: this.$t('page.visit_log.risk_level'),
            width: 60,
            ellipsis: true,
            colKey: 'risk_level',
          },
          {
            title: this.$t('common.status'),
            width: 60,
            ellipsis: true,
            colKey: 'action',
          },
          {
            title: this.$t('page.visit_log.trigger_rule'),
            align: 'left',
            width: 150,
            ellipsis: true,
            colKey: 'rule',
          },
          {
            title: this.$t('page.visit_log.time'),
            width: 170,
            ellipsis: true,
            colKey: 'create_time',
            sorter: true
          },
          {
            title: this.$t('page.visit_log.domain'),
            align: 'left',
            width: 150,
            ellipsis: true,
            colKey: 'host',
          },

          {
            title: this.$t('page.visit_log.request'),
            width: 70,
            ellipsis: true,
            colKey: 'method',
          },
          {
            title: this.$t('page.visit_log.source_ip'),
            width: 150,
            ellipsis: true,
            colKey: 'src_ip',
          },
          {
            title:  this.$t('page.visit_log.country'),
            width: 100,
            ellipsis: true,
            colKey: 'country',
          },
          {
            title:this.$t('page.visit_log.province'),
            width: 100,
            ellipsis: true,
            colKey: 'province',
          }, {
            title: this.$t('page.visit_log.city'),
            width: 100,
            ellipsis: true,
            colKey: 'city',
          },
          {
            title: this.$t('page.visit_log.access_url'),
            width: 160,
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
                placeholder: this.$t('common.placeholder'),
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
            width: 120,
            colKey: 'op',
            title: this.$t('common.op'),
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
      offsetTop() {
        return this.$store.state.setting.isUseTabsRouter ? 48 : 0;
      },
      columnControllerConfig() {
        return {
          placement: this.placement,
          fields: ['action', 'rule', 'create_time', 'host', 'method', 'url', 'header', 'country', 'province', 'city', 'status','risk_level','guest_identification','time_spent'],
          // 弹框组件属性透传
          dialogProps: { preventScrollThrough: true },
          // 列配置按钮属性
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
      //Jump Url
      handleJumpOnlineUrl(){
        window.open(this.samwafglobalconfig.getOnlineUrl()+"/guide/attacklog.html");
      },
      /**
       * table 排序
       */
      onSortChange(sorter){
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
      },
      /**
       * 筛选结果
       */
      onFilterChange(e){
        this.filters.filter_by = "";
        this.filters.filter_value = "";
        //访客身份
        if(e.guest_identification != undefined && e.guest_identification!=""){
           this.filters.filter_by = "guest_identification";
           this.filters.filter_value = e.guest_identification ;
        }
        //header
        if(e.header != undefined && e.header!=""){
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
  .t-button+.t-button {
    margin-left: @spacer;
  }
</style>
