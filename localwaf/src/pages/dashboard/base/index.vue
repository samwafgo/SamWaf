<template>
  <div>
    <t-swiper :duration="300" :interval="5000" :navigation="navigation" v-if="tipsVisable" trigger="click">
      <t-swiper-item  v-for="(item, index)  in tips" :key="index" v-if="item.visable" >
        <t-alert :theme="item.tipsType" :message="$t(item.message)" >
          <template #operation="row">
            <span @click="handleCreateWebOperation" v-if="item.name==='emptyHost'" >{{$t('dashboard.tip_create_website_link')}}</span>
            <span @click="handleModifyDefaultPassWebOperation" v-if="item.name==='defaultAccount'" >{{$t('dashboard.tip_modify_pwd_link')}}</span>
          </template>
        </t-alert>
      </t-swiper-item>
    </t-swiper>
<br>
    <!-- 顶部 card  -->
    <top-panel class="row-container" />
    <!-- 中部图表  -->
    <middle-chart class="row-container" />
    <!-- 列表排名 -->
   <!-- <rank-list class="row-container" /> -->
  </div>
</template>
<script lang="ts">
import TopPanel from './components/TopPanel.vue';
import MiddleChart from './components/MiddleChart.vue';
import RankList from './components/RankList.vue';
import {
  wafStatSysinfoapi
} from '@/apis/stats';
export default {
  name: 'DashboardBase',
  components: {
    TopPanel,
    MiddleChart,
    RankList,
  },
  data() {
    return {
      center: {lng: 0, lat: 0},
      zoom: 3,
      navigation:{
        type: 'bars' ,
        size:'small',
        showSlideBtn:'never' ,
        placement:'inside'
      },
      tipsVisable:false,
      tips:[
        {
          name:"emptyHost",
          visable:false,
          message:'dashboard.tip_create_website_title',
          tipsType:"success"
        },
        {
          name:"defaultAccount",
          visable:false,
          message:'dashboard.tip_modify_pwd_title',
          tipsType:"error"
        },
      ]
    }
  },
  mounted() {
    this.loadSysInfo()
  },
  methods: {
     handler ({BMap, map}) {
          console.log(BMap, map)
          this.center.lng = 116.404
          this.center.lat = 39.915
          this.zoom = 15
    },
    //引导创建网站
    handleCreateWebOperation(){
      this.$router.push(
        {
          path: '/waf-host/wafhost',
          query: {
            sourcePage: "HomeFrist",
          },
        },
      );
    },//引导修改默认密码
    handleModifyDefaultPassWebOperation(){
      this.$router.push(
        {
          path: '/account/Account',
          query: {
            sourcePage: "HomeFrist",
          },
        },
      );
    },
    loadSysInfo(){
      wafStatSysinfoapi({}).then((res)=>{
        console.log("home res",res.data)
        this.tips[0].visable = res.data.is_empty_host
        this.tips[1].visable = res.data.is_default_account
        this.tipsVisable = this.tips[0].visable || this.tips[1].visable
      } ).catch((e: Error) => {
        console.log(e);
      }).finally(() => {})
    },
    //end method
  },
};
</script>
<style scoped>
.row-container {
  margin-bottom: 16px;
}
.map {
  width: 100%;
  height: 300px;
}
</style>
