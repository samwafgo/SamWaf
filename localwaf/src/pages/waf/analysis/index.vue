<template>
  <div id="countryMap" style="width:73.125rem; height:40.5rem;"></div>
</template>

<script lang="ts">
  import {
    TooltipComponent,
    LegendComponent,
    GridComponent
  } from 'echarts/components';
  import {
    PieChart,
    LineChart,
    MapChart
  } from 'echarts/charts';
  import {
    CanvasRenderer
  } from 'echarts/renderers';
  import * as echarts from 'echarts/core';
  import {
    mapState
  } from 'vuex';

  import {
    LAST_7_DAYS
  } from '@/utils/date';

  import {
    changeChartsTheme
  } from '@/utils/color';
  import chinaMap from '@/assets/mapjson/china.json'
  import worldMap from '@/assets/mapjson/world.json'
  import worldchsname from '@/assets/mapjson/worldchsname.json'
  import {
    wafanalysisdaycountryrange
  } from '@/apis/stats';
  echarts.use([TooltipComponent, LegendComponent, PieChart, GridComponent, LineChart, CanvasRenderer, MapChart]);


  export default {
    name: 'Analysis',
    data() {
      return {
        map: null,
        xData: ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"], //横坐标
        yData: [23, 24, 18, 25, 27, 28, 25], //数据
        myChartStyle: {
          float: "left",
          width: "100%",
          height: "400px"
        },//图表样式
        mapOptions: {
          // 默认的颜色数组 （如果不明确设置每个数据项的颜色，则会采用默认的数组
          color: ["#ac6767", "#1d953f", "#6950a1", "#918597"],
          series: [{
            type: 'map',
            map: 'world', // 使用世界地图
            label: {
              "show": false,
              "position": "top",
              "margin": 8
            },
            data: [ //图表数据来源
              {
                // ItemStyle 中设置每一个数据项的颜色
                "name": "美国", "value": 43,
                'itemStyle': { 'color': "#c23531" }
              },

            ],
            nameMap: worldchsname
          }],
          // 鼠标悬浮，单击产生的效果（在网页上可以动态显示）
          tooltip: {
            "show": true,
            "trigger": "item", //触发器
            "triggerOn": "mousemove|click", //触发事件为鼠标单击或悬浮
            "axisPointer": {
              "type": "line"
            },
            "textStyle": {
              "fontSize": 14
            },
            "borderWidth": 0
          },
          "roam": true, //关闭鼠标缩放和平移漫游
          "zoom": 1, //设置地图缩放大小

        }
      };
    },
    computed: {},
    watch: {},
    mounted() {

      this.initEcharts();
      this.loadCountryData();
    },

    methods: {
      loadCountryData() {
        let that = this
        let rangeStartDay = 20231101
        let rangeEndDay = 20231116
        wafanalysisdaycountryrange({
          'start_day': rangeStartDay,
          'end_day': rangeEndDay,
          'attack_type': '阻止'
        })
          .then((res) => {
            let resdata = res
            console.log(resdata.data)
            that.mapOptions.series[0].data = resdata.data
            that.map.setOption(that.mapOptions);

          }

          ).catch((e : Error) => {
            console.log(e);
          })
          .finally(() => { })
      },
      initEcharts() {



        /*
         融合数据 世界和中国
         let data = this.map_decode(chinaMap) // 打印这个data，得到就是解密之后的中国地图数据了
        let worldAndChina = Object.assign({}, worldMap); // 原本的world还需要用 所以这里用了一个深拷贝赋值世界地图数据
        worldAndChina.features = worldAndChina.features.concat(data.features); // 对，就是这么简单用concat把两者的features合并起来就可以了

        echarts.registerMap("world", {
          geoJSON: worldAndChina
        }); */

        echarts.registerMap("world", {
          geoJSON: worldMap
        });
        const myChart = echarts.init(document.getElementById("countryMap"));
        this.map = myChart
        myChart.setOption(this.mapOptions);
        //随着屏幕大小调节图表
        window.addEventListener("resize", () => {
          myChart.resize();
        });
        /* myChart.on("georoam", function(params) {
          console.log("georoam")
            var options = myChart.getOption(); //获得option对象
            if (!params.originX) return; // 不是缩放就返回
            let zoom = options.geo[0].zoom;
            if (zoom > 4.5) {
                let data = this.map_decode(china);
                let worldAndChina = Object.assign({}, worldMap);
                worldAndChina.features = worldAndChina.features.concat(data.features);
                echarts.registerMap("world", worldAndChina);
                options.geo[0].label.show = true;
            } else {
                echarts.registerMap("world", worldMap);
                options.geo[0].label.show = false;
            }
            myChart.setOption(options);
        }); */
      },
      map_decodePolygon(coordinate, encodeOffsets, encodeScale) {
        var result = [];
        var prevX = encodeOffsets[0];
        var prevY = encodeOffsets[1];
        for (var i = 0; i < coordinate.length; i += 2) {
          var x = coordinate.charCodeAt(i) - 64;
          var y = coordinate.charCodeAt(i + 1) - 64;
          // ZigZag decoding
          x = (x >> 1) ^ -(x & 1);
          y = (y >> 1) ^ -(y & 1);
          // Delta deocding
          x += prevX;
          y += prevY;
          prevX = x;
          prevY = y;
          // Dequantize
          result.push([x / encodeScale, y / encodeScale]);
        }
        return result;
      },
      map_decode(json) {
        if (!json.UTF8Encoding) {
          return json;
        }
        var encodeScale = json.UTF8Scale;
        if (encodeScale == null) {
          encodeScale = 1024;
        }
        var features = json.features;
        for (var f = 0; f < features.length; f++) {
          var feature = features[f];
          var geometry = feature.geometry;
          var coordinates = geometry.coordinates;
          var encodeOffsets = geometry.encodeOffsets;
          for (var c = 0; c < coordinates.length; c++) {
            var coordinate = coordinates[c];
            if (geometry.type === "Polygon") {
              coordinates[c] = this.map_decodePolygon(
                coordinate,
                encodeOffsets[c],
                encodeScale
              );
            } else if (geometry.type === "MultiPolygon") {
              for (var c2 = 0; c2 < coordinate.length; c2++) {
                var polygon = coordinate[c2];
                coordinate[c2] = this.map_decodePolygon(
                  polygon,
                  encodeOffsets[c][c2],
                  encodeScale
                );
              }
            }
          }
        }
        // Has been decoded
        json.UTF8Encoding = false;
        return json;
      },
    },
    beforeDestroy() {
      // 在组件销毁前，销毁echarts实例，防止内存泄漏
      if (this.map) {
        this.map.dispose()
      }
    }
  };
</script>

<style>
</style>
