<template>

  <div class="detail-base"> 
    <t-card title="网站详情">
      <div class="info-block">

        <div class="info-item">
          <h1> 创建时间</h1>
          <span>
            {{ detail_data.create_time }}
          </span>
        </div>
        <div class="info-item">
          <h1> 网站</h1>
          <span>
            {{ detail_data.host }}
          </span>
        </div>
        <div class="info-item">
          <h1> 网站端口</h1>
          <span>
            {{ detail_data.port }}
          </span>
        </div>
        <div class="info-item">
          <h1> 加密证书</h1>
          <span>
            {{ detail_data.ssl }}
          </span>
        </div>
        <div class="info-item">
          <h1> 后端系统类型</h1>
          <span>
            {{ detail_data.remote_system }}
          </span>
        </div>
        <div class="info-item">
          <h1> 后端系统应用类型</h1>
          <span>
            {{ detail_data.remote_app }}
          </span>
        </div>
        <div class="info-item">
          <h1> 后端域名</h1>
          <span>
            {{ detail_data.remote_host }}
          </span>
        </div>
        <div class="info-item">
          <h1> 后端端口</h1>
          <span>
            {{ detail_data.remote_port }}
          </span>
        </div>
      </div>
    </t-card>
    <t-card title="最近配置记录" class="container-base-margin-top">

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
      '$route.query.code'(newVal, oldVal) {
        console.log('route.query.code changed', newVal, oldVal)
        this.getDetail(newVal)
      },
    },
    methods: {
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
