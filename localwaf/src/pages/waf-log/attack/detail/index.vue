<template>
  <div class="detail-base">
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
          <h1> 请求用户浏览器</h1>
          <span>
            {{ detail_data.user_agent }}
          </span>
        </div>
        <div class="info-item">
          <h1> 请求地区</h1>
          <span>
            {{ detail_data.country }}
          </span>
        </div>
        <div class="info-item">
          <h1> 请求头</h1>
          <span>
            {{ detail_data.header }}
          </span>
        </div>
      </div>
    </t-card>

    <t-card title="变更记录" class="container-base-margin-top">
      <t-steps class="detail-base-info-steps" layout="vertical" theme="dot" :current="1">
        <t-step-item title="上传合同附件" content="这里是提示文字" />
        <t-step-item title="修改合同金额" content="这里是提示文字" />
        <t-step-item title="新建合同" content="2020-12-01 15:00:00 管理员-李川操作" />
      </t-steps>
    </t-card>
  </div>
</template>
<script lang="ts">
import { prefix } from '@/config/global';
import model from '@/service/service-detail-base';

export default {
  name: 'WafAttackLogDetail',
  data() {
    return {
      prefix,
      baseInfoData: model.getBaseInfoData(),
      detail_data:{}
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
    getDetail(id){
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
        .finally(() => {
        });
    },
  },
};
</script>
<style lang="less" scoped>
@import './index';
</style>
