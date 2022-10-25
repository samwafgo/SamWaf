<template>
  <div>
    <!-- 顶部 card  -->
    <top-panel class="row-container" />
    <!-- 中部图表  -->
    <middle-chart class="row-container" />
    <!-- 列表排名 -->
    <rank-list class="row-container" />
    <!-- 出入库概览 -->
    <output-overview class="row-container" />

     <baidu-map class="map"  :center="center" :zoom="zoom" @ready="handler">
      </baidu-map>
  </div>
</template>
<script>
import TopPanel from './components/TopPanel.vue';
import MiddleChart from './components/MiddleChart.vue';
import RankList from './components/RankList.vue';
import OutputOverview from './components/OutputOverview.vue';

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
            zoom: 3
    }
  },
  methods: {
     handler ({BMap, map}) {
          console.log(BMap, map)
          this.center.lng = 116.404
          this.center.lat = 39.915
          this.zoom = 15
        }
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
