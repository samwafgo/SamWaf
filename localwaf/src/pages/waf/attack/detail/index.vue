<template>
  <div class="detail-base">
    <t-card :title="$t('page.visit_log.detail.defense_status')" class="container-base-margin-top">
      <t-steps class="detail-base-info-steps" layout="horizontal" theme="dot" :current="3">
        <t-step-item :title="$t('page.visit_log.detail.visit_time')" :content="detail_data.create_time" />
        <t-step-item :title="$t('page.visit_log.detail.detection_time')" />
        <t-step-item :title="$t('page.visit_log.detail.defense_status_step')" :content="detail_data.action" />
        <t-step-item :title="$t('page.visit_log.detail.response_status')" :content="detail_data.status" />
      </t-steps>
    </t-card>
    <t-card :title="$t('common.details')" >
      <div class="info-block">
        <div class="info-item">
          <h1> {{ $t('page.visit_log.detail.request_identifier') }}</h1>
          <span>
            {{ detail_data.req_uuid }}
          </span>
        </div>
        <div class="info-item">
          <h1> {{ $t('page.visit_log.detail.request_time') }}</h1>
          <span>
            {{ detail_data.create_time }}
          </span>
        </div>
        <div class="info-item">
          <h1> {{ $t('page.visit_log.detail.request_domain') }}</h1>
          <span>
            {{ detail_data.host }}
          </span>
        </div>
        <div class="info-item">
          <h1> {{ $t('page.visit_log.detail.request_method') }}</h1>
          <span>
            {{ detail_data.method }}
          </span>
        </div>
        <div class="info-item">
          <h1> {{ $t('page.visit_log.detail.request_content_size') }}</h1>
          <span>
            {{ detail_data.content_length }}
          </span>
        </div>
        <div class="info-item">
          <h1> {{ $t('page.visit_log.detail.visitor_ip') }}</h1>
          <span>
            {{ detail_data.src_ip }}
            <t-button theme="primary" shape="round" size="small" @click="handleAddipblock">{{ $t('page.visit_log.detail.add_to_deny_list') }}</t-button>
          </span>
        </div>
        <div class="info-item">
          <h1> {{ $t('page.visit_log.detail.visitor_port') }}</h1>
          <span>
            {{ detail_data.src_port }}
          </span>
        </div>
        <div class="info-item">
          <h1> {{ $t('page.visit_log.detail.request_region') }}</h1>
          <span>
            {{ detail_data.country }} {{ detail_data.province }} {{ detail_data.city }}
          </span>
        </div>
        <div class="info-item">
          <h1> {{ $t('page.visit_log.detail.response_code') }}</h1>
          <span>
            {{ detail_data.status_code }} ({{detail_data.status}} )
          </span>
        </div>
      </div>
    </t-card>
    <t-card :title="$t('page.visit_log.detail.more_info')" class="container-base-margin-top">
         <template #actions>
           <t-tooltip :content="$t('page.visit_log.detail.mouse_select_tooltip')">
               {{$t('page.visit_log.detail.quick_add_rule')}}:  <t-switch size="large" v-model="quickAddRuleChecked" :label="[$t('page.visit_log.detail.open'), $t('page.visit_log.detail.close')]"></t-switch>
               </t-tooltip>
        </template>
      <t-list :split="true">
        <t-list-item>
          <t-list-item-meta :title="$t('page.visit_log.detail.request_path')"></t-list-item-meta>
        </t-list-item>
         <t-textarea v-model="detail_data.url" :autosize="{ minRows: 3, maxRows: 5 }" readonly @blur="handleMouseSelect('url')"/>
        <t-list-item>
          <t-list-item-meta :title="$t('page.visit_log.detail.request_header')"></t-list-item-meta>
        </t-list-item>
         <t-textarea v-model="detail_data.header" :autosize="{ minRows: 3, maxRows: 5 }"  readonly @blur="handleMouseSelect('header')"/>
        <t-list-item>
         <t-list-item-meta :title="$t('page.visit_log.detail.request_user_browser')" ></t-list-item-meta>
        </t-list-item>
         <t-textarea v-model="detail_data.user_agent" :autosize="{ minRows: 3, maxRows: 5 }" readonly @blur="handleMouseSelect('user_agent')"/>
        <t-list-item>
          <t-list-item-meta :title="$t('page.visit_log.detail.request_cookies')" ></t-list-item-meta>
        </t-list-item>
         <t-textarea v-model="detail_data.cookies" :autosize="{ minRows: 3, maxRows: 5 }" readonly @blur="handleMouseSelect('cookies')"/>
        <t-list-item >
          <t-list-item-meta :title="$t('page.visit_log.detail.request_body')" ></t-list-item-meta>
        </t-list-item>
        <t-textarea v-model="detail_data.body" :autosize="{ minRows: 3, maxRows: 5 }" readonly @blur="handleMouseSelect('body')"/>
        <t-list-item >
          <t-list-item-meta :title="$t('page.visit_log.detail.request_form')" ></t-list-item-meta>
        </t-list-item>
        <t-textarea v-model="detail_data.post_form" :autosize="{ minRows: 3, maxRows: 5 }" readonly />
      </t-list>
    </t-card>
    <t-card :title="$t('page.visit_log.detail.response_data')">
      <t-textarea v-model="detail_data.res_body" :autosize="{ minRows: 5, maxRows: 10 }" readonly />

      </t-card>
     <t-button theme="primary" type="button" @click="backPage">{{ $t('page.visit_log.detail.back') }}</t-button>


  </div>
</template>
<script lang="ts">
  import {
    prefix
  } from '@/config/global';
  import model from '@/service/service-detail-base';
  import {
    wafIPBlockAddApi
  } from '@/apis/ipblock';

  export default {
    name: 'WafAttackLogDetail',
    data() {
      return {
        prefix,
        baseInfoData: model.getBaseInfoData(),
        detail_data: {},
        quickAddRuleChecked:false,
      };
    },
    beforeRouteUpdate(to, from) {
      console.log('beforeRouteUpdate')
    },
    mounted() {
      console.log('----mounted----')

      //console.log(this.$route.params.req_uuid);
      //this.getDetail(this.$route.params.req_uuid);
      this.getDetail(this.$route.query.req_uuid);
    },
    beforeCreate() {
      console.log('----beforeCreate----')
    },
    created() {
      console.log('----created----')
    },
    beforeMount() {
      console.log('----beforeMount----')
    },
    beforeUpdate() {
      console.log('----beforeUpdate----')
    },
    updated() {
      console.log('----updated----')
    },
    watch: {
      '$route.query.req_uuid'(newVal, oldVal) {
        console.log('route.query.req_uuid changed', newVal, oldVal)
        if(newVal!=undefined){
          this.getDetail(newVal)
        }

      },
    },
    methods: {
      backPage(){
        　history.go(-1)
      },
      getDetail(uuid_and_name) {
        if(uuid_and_name == undefined){
          return
        }
       let arr =  uuid_and_name.split("#");
        let id = arr[0]
       let current_db_name = arr[1]
        let that = this
        this.$request
          .get('/waflog/attack/detail', {
            params: {
              REQ_UUID: id,
              current_db_name:current_db_name
            }
          })
          .then((res) => {
            let resdata = res
            console.log(resdata)
            if (resdata.code === 0) {

              //const { list = [] } = resdata.data.list;

              that.detail_data = resdata.data;

            }
          })
          .catch((e: Error) => {
            console.log(e);
          })
          .finally(() => {});
      },
      handleAddipblock() {

        if(this.detail_data.host_code==""){
          this.$message.warning("当前网站不存在");
          return
        }
        let that = this


        const confirmDia = this.$dialog.confirm({
                header: this.$t('page.visit_log.detail.add_to_deny_list_confirm_header')  ,
                body: this.$t('page.visit_log.detail.add_to_deny_list_confirm_body') ,
                confirmBtn: this.$t('common.confirm') ,
                cancelBtn: this.$t('common.cancel') ,
                onConfirm: ({ e }) => {
                   //add deny IP
                   let formData = {
                     host_code: this.detail_data.host_code,
                     ip: this.detail_data.src_ip,
                     remarks: '手工增加',
                   };
                   wafIPBlockAddApi({
                       ...formData
                     })
                     .then((res) => {
                       let resdata = res
                       console.log(resdata)
                       if (resdata.code === 0) {
                         that.$message.success(resdata.msg);
                       } else {
                         that.$message.warning(resdata.msg);
                       }
                     })
                     .catch((e: Error) => {
                       console.log(e);
                     })
                     .finally(() => {});

                  confirmDia.destroy();
                },
                onClose: ({ e, trigger }) => {
                  console.log('e: ', e);
                  console.log('trigger: ', trigger);
                  confirmDia.hide();
                },
              });



      },
      handleMouseSelect(sourcePoint) {
         if(this.quickAddRuleChecked==false){
           return
         }
      		let text = window.getSelection().toString()
      		console.log(text)
          if(text.length==0){
            return
          }
          let that = this
          this.$router.push(
                  {
                    path:'/waf-host/wafruleedit',
                    query: {
                      type: "add",
                      host_code: that.detail_data.host_code,
                      contentstr:text,
                      is_manual_rule :1,
                      sourcePoint :sourcePoint
                    },
                  },
           );
      	}
    },
  };
</script>
<style lang="less" scoped>
  @import './index';
</style>
