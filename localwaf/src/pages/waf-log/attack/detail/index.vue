<template>
  <div class="detail-base">
    <t-card title="防御情况" class="container-base-margin-top">
      <t-steps class="detail-base-info-steps" layout="horizontal" theme="dot" :current="2">
        <t-step-item title="访问" :content="detail_data.create_time" />
        <t-step-item title="检测" :content="detail_data.create_time" />
        <t-step-item title="防御状态" :content="detail_data.action" />
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
          <h1> 请求路径</h1>
          <span>
            {{ detail_data.url }}
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
            {{ detail_data.country }}
          </span>
        </div>
      </div>
    </t-card>
    <t-card title="访问其他记录" class="container-base-margin-top">

      <t-list :split="true">
        <t-list-item>
          <t-list-item-meta title="请求头" :description="detail_data.header"></t-list-item-meta>
        </t-list-item>
        <t-list-item>
          <t-list-item-meta title="请求用户浏览器" :description="detail_data.user_agent"></t-list-item-meta>
        </t-list-item>
        <t-list-item>
          <t-list-item-meta title="请求cookies" :description="detail_data.cookies"></t-list-item-meta>
        </t-list-item>
        <t-list-item>
          <t-list-item-meta title="请求BODY" :description="detail_data.body"></t-list-item-meta>
        </t-list-item>
      </t-list>
    </t-card>


  </div>
</template>
<script lang="ts">
  import {
    prefix
  } from '@/config/global';
  import model from '@/service/service-detail-base';

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
      getDetail(id) {
        let that = this
        this.$request
          .get('/waflog/attack/detail', {
            params: {
              REQ_UUID: id,
            }
          })
          .then((res) => {
            let resdata = res.data
            console.log(resdata)
            if (resdata.code === 200) {

              //const { list = [] } = resdata.data.list;

              that.detail_data = resdata.data;

            }
          })
          .catch((e: Error) => {
            console.log(e);
          })
          .finally(() => {});
      },
    },
  };
</script>
<style lang="less" scoped>
  @import './index';
</style>
