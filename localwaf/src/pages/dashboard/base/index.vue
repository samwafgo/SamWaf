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
};
</script>
<style scoped>
.row-container {
  margin-bottom: 16px;
}
</style>
