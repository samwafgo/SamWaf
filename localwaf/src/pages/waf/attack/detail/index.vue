<template>
  <div class="detail-base">
    <t-card title="防御情况" class="container-base-margin-top">
      <t-steps class="detail-base-info-steps" layout="horizontal" theme="dot" :current="3">
        <t-step-item title="访问" :content="detail_data.create_time" />
        <t-step-item title="检测" :content="detail_data.create_time" />
        <t-step-item title="防御状态" :content="detail_data.action" />
        <t-step-item title="响应状态" :content="detail_data.status" />
      </t-steps>
    </t-card>
    <t-card title="本次请求详情">
      <div class="info-block">
        <div class="info-item">
          <h1> 请求标识</h1>
          <span>
            {{ detail_data.req_uuid }}
          </span>
        </div>
        <div class="info-item">
          <h1> 请求时间</h1>
          <span>
            {{ detail_data.create_time }}
          </span>
        </div>
        <div class="info-item">
          <h1> 请求域名</h1>
          <span>
            {{ detail_data.host }}
          </span>
        </div>
        <div class="info-item">
          <h1> 请求方法</h1>
          <span>
            {{ detail_data.method }}
          </span>
        </div>
        <div class="info-item">
          <h1> 请求内容大小</h1>
          <span>
            {{ detail_data.content_length }}
          </span>
        </div>
        <div class="info-item">
          <h1> 访问者IP</h1>
          <span>
            {{ detail_data.src_ip }}
            <t-button theme="primary" shape="round" size="small" @click="handleAddipblock">加黑名单</t-button>
          </span>
        </div>
        <div class="info-item">
          <h1> 访问者端口</h1>
          <span>
            {{ detail_data.src_port }}
          </span>
        </div>
        <div class="info-item">
          <h1> 请求地区</h1>
          <span>
            {{ detail_data.country }} {{ detail_data.province }} {{ detail_data.city }}
          </span>
        </div>
        <div class="info-item">
          <h1> 响应编码</h1>
          <span>
            {{ detail_data.status_code }} ({{detail_data.status}} )
          </span>
        </div>
      </div>
    </t-card>
    <t-card title="访问其他记录" class="container-base-margin-top">

      <t-list :split="true">
        <t-list-item>
          <t-list-item-meta title="请求路径"></t-list-item-meta>
        </t-list-item>
         <t-textarea v-model="detail_data.url" :autosize="{ minRows: 3, maxRows: 5 }" readonly/>
        <t-list-item>
          <t-list-item-meta title="请求头"></t-list-item-meta>
        </t-list-item>
         <t-textarea v-model="detail_data.header" :autosize="{ minRows: 3, maxRows: 5 }" readonly/>
        <t-list-item>
         <t-list-item-meta title="请求用户浏览器" ></t-list-item-meta>
        </t-list-item>
         <t-textarea v-model="detail_data.user_agent" :autosize="{ minRows: 3, maxRows: 5 }" readonly/>
        <t-list-item>
          <t-list-item-meta title="请求cookies" ></t-list-item-meta>
        </t-list-item>
         <t-textarea v-model="detail_data.cookies" :autosize="{ minRows: 3, maxRows: 5 }" readonly/>
        <t-list-item >
          <t-list-item-meta title="请求BODY" ></t-list-item-meta>
        </t-list-item>
        <t-textarea v-model="detail_data.body" :autosize="{ minRows: 3, maxRows: 5 }" readonly/>
      </t-list>
    </t-card>
     <t-button theme="primary" type="button" @click="backPage">返回</t-button>


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
        detail_data: {}
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
        this.getDetail(newVal)
      },
    },
    methods: {
      backPage(){
        　history.go(-1)
      },
      getDetail(id) {
        let that = this
        this.$request
          .get('/waflog/attack/detail', {
            params: {
              REQ_UUID: id,
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
                header: '加入IP黑名单',
                body: '你确定要加入黑名单IP（'+ this.detail_data.src_ip +"）么？",
                confirmBtn: '确定',
                cancelBtn: '取消',
                onConfirm: ({ e }) => {
                   //添加黑名单IP
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

                  // 请求成功后，销毁弹框
                  confirmDia.destroy();
                },
                onClose: ({ e, trigger }) => {
                  console.log('e: ', e);
                  console.log('trigger: ', trigger);
                  confirmDia.hide();
                },
              });



      },
    },
  };
</script>
<style lang="less" scoped>
  @import './index';
</style>
