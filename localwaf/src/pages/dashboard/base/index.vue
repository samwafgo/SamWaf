<template>
  <div>
    <t-alert theme="error" :message="defaultAccountMessage" v-if="defaultAccountVisable" >
      <template #operation>
        <span @click="handleModifyDefaultPassWebOperation">马上修改</span>
      </template>
    </t-alert>
    <t-alert theme="success" :message="emptyHostMessage"  v-if="emptyHostVisable">
      <template #operation>
        <span @click="handleCreateWebOperation">马上创建</span>
      </template>
    </t-alert>
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
import OutputOverview from './components/OutputOverview.vue';
import {
  wafStatSysinfoapi
} from '@/apis/stats';
export default {
  name: 'DashboardBase',
  components: {
    TopPanel,
    MiddleChart,
    RankList,
    OutputOverview,
  },
  data() {
    return {
      center: {lng: 0, lat: 0},
      zoom: 3,
      emptyHostMessage:"您当前未创建需要防护的网站，点击进行创建",
      emptyHostVisable: false,
      defaultAccountMessage:"您当前还是使用默认帐号和密码请尽快修改",
      defaultAccountVisable:false,
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
        this.defaultAccountVisable = res.data.is_default_account
        this.emptyHostVisable =  res.data.is_empty_host
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
