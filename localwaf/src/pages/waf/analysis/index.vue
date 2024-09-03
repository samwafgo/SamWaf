<template>
  <div class="contentarea">
    <div class="left-column">
      <!-- 左边列内容 -->
      {{$t('common.date')}} :<t-space direction="horizontal">
        <t-date-range-picker v-model="range1" :presets="presets" />
        <t-select v-model="currentAction" class="form-item-content`" :options="action_options"
          :style="{ width: '100px' }" />
      </t-space>

      <t-button variant="outline" @click="loadCountryData"> {{ $t('common.search') }} </t-button>
      <div id="countryMap" style="width:100%; height:40.5rem;"></div>
    </div>
    <div class="right-column">
      <div class="top-right">
        <!-- 右边上半部分内容 -->
        <div id="wordCloudCountry" style="width:100%;height:20.5rem;"></div>
      </div>
      <div class="bottom-right">
        <!-- 右边下半部分内容 -->

      </div>
    </div>
  </div>
</template>

<script lang="ts">
  import {
    AddIcon, CloudUploadIcon, SearchIcon, DiscountIcon, CloudDownloadIcon,
  } from 'tdesign-icons-vue';
  import {
    TooltipComponent,
    LegendComponent,
    GridComponent,
    VisualMapComponent
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
  echarts.use([TooltipComponent, LegendComponent, PieChart, GridComponent, LineChart, CanvasRenderer, MapChart, VisualMapComponent]);
  import 'echarts-wordcloud';

  export default {
    name: 'Analysis',
    data() {
      return {
        //词云的相关配置
        wordCloudChartsInfo: {
          wordCloudEchart: null,
          wordCloudOptions: {
            series: [{
              type: 'wordCloud',
              shape: 'circle',
              keepAspect: false,
              // maskImage: maskImage,
              left: 'center',
              top: 'center',
              width: '100%',
              height: '90%',
              right: null,
              bottom: null,
              sizeRange: [12, 60],
              rotationRange: [-90, 90],
              rotationStep: 45,
              gridSize: 8,
              drawOutOfBound: false,
              layoutAnimation: true,
              textStyle: {
                fontFamily: 'sans-serif',
                fontWeight: 'bold',
                color: function () {
                  return 'rgb(' + [
                    Math.round(Math.random() * 160),
                    Math.round(Math.random() * 160),
                    Math.round(Math.random() * 160)
                  ].join(',') + ')';
                }
              },
              emphasis: {
                // focus: 'self',
                textStyle: {
                  textShadowBlur: 3,
                  textShadowColor: '#333'
                }
              },
              //data属性中的value值却大，权重就却大，展示字体就却大
              data: [
                //{name: 'Farrah',value: 366},
                //{name: "汽车",value: 900},
                //{name: "视频",value: 606},
              ]
            }]

          }
        },
        currentAction: "",
        action_options: [
          {
            label: this.$t('common.defense_status.all'),
            value: ''
          },
          {
            label: this.$t('common.defense_status.stop'),
            value: '阻止'
          },
          {
            label: this.$t('common.defense_status.pass'),
            value: '放行'
          },
          {
            label: this.$t('common.defense_status.forbid'),
            value: '禁止'
          },
        ],
        presets: {
          最近7天: [new Date(+new Date() - 86400000 * 6), new Date()],
          最近3天: [new Date(+new Date() - 86400000 * 2), new Date()],
          今天: [new Date(), new Date()],
        },
        range1: ['2023-11-01', '2023-11-16'],
        map: null,
        xData: ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"], //横坐标
        yData: [23, 24, 18, 25, 27, 28, 25], //数据
        myChartStyle: {
          float: "left",
          width: "100%",
          height: "400px"
        },//图表样式
        mapOptions: {
          visualMap: {
            min: 0,
            max: 1000,
            calculable: true,
            inRange: {
              color: ['#50a3ba', '#eac736', '#d94e5d'] // 指定颜色范围
            },
            textStyle: {
              color: '#fff' // 可选，设置文本颜色
            }
          },
          // 默认的颜色数组 （如果不明确设置每个数据项的颜色，则会采用默认的数组
          color: ["#ac6767", "#1d953f", "#6950a1", "#918597"],
          /* label: {
            show: true, // 设置标签显示
            formatter: '{b}', // 显示地区名称
            color: '#000', // 标签颜色
            fontSize: 12, // 标签字体大小
            // 其他标签样式配置
          }, */
          series: [{
            type: 'map',
            map: 'world', // 使用世界地图
            label: {
              "show": true,
              "position": "top",
              "margin": 8,
              formatter: function (params) {
                if (params.data && params.data.value > 0) {
                  return params.data.name; // 显示地区名称
                } else {
                  return ''; // 如果不满足条件，返回空字符串，不显示标签
                }
              },
            },
            data: [ //图表数据来源
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
            "borderWidth": 0,
            formatter: function (params) {
              if (params.data && params.data.value > 0) {
                return params.name + ': ' + params.data.value; // 当数据大于0时显示地区名称和数值
              } else {
                return ''; // 当数据小于等于0时不显示提示框
              }
            },
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
    created() {
      this.range1[0] = LAST_7_DAYS[0]
      this.range1[1] = LAST_7_DAYS[1]
      console.log(this.range1)
    },

    methods: {
      renderIcon() {
        return "<SearchIcon />";
      },
      loadCountryData() {
        let that = this
        let rangeStartDay = that.range1[0].replace(/-/g, '')
        let rangeEndDay = that.range1[1].replace(/-/g, '')
        console.log(rangeStartDay, rangeEndDay)
        wafanalysisdaycountryrange({
          'start_day': rangeStartDay,
          'end_day': rangeEndDay,
          'attack_type': that.currentAction
        })
          .then((res) => {
            let resdata = res.data
            console.log(resdata)
            if (resdata == null) {
              that.mapOptions.series[0].data = []
              that.mapOptions.visualMap.max = 0
              that.map.setOption(that.mapOptions);
            } else {
              let maxValue = 0;

              resdata.forEach(item => {
                if (item.value > maxValue) {
                  maxValue = item.value;
                }
              });
              that.mapOptions.series[0].data = resdata
              that.mapOptions.visualMap.max = maxValue
              that.map.setOption(that.mapOptions);

              //赋值词云部分
              that.wordCloudChartsInfo.wordCloudOptions.series[0].data = resdata
              that.wordCloudChartsInfo.wordCloudEchart.setOption(that.wordCloudChartsInfo.wordCloudOptions);

            }



          }

          ).catch((e : Error) => {
            console.log(e);
          })
          .finally(() => { })
      },
      initEcharts() {
        this.initWorldMap();
        this.initWordCloud();
      },
      //初始化世界地图
      initWorldMap() {
        //
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
      //初始化词云
      initWordCloud() {
        let that = this
        let echartDom = document.getElementById('wordCloudCountry')
        that.wordCloudChartsInfo.wordCloudEchart = echarts.init(echartDom)
        that.wordCloudChartsInfo.wordCloudEchart.setOption(that.wordCloudChartsInfo.wordCloudOptions)

        //随着屏幕大小调节图表
        window.addEventListener("resize", () => {
          that.wordCloudChartsInfo.wordCloudEchart.resize();
        });
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
  .contentarea {
    display: flex;
    width: 80%;
    height: 100vh;
    /* 让布局占据整个视口高度 */
    height: 50rem;
  }

  .left-column {
    flex: 2;
    /* 左边列宽度占比，这里为 1，可以根据需要调整 */
    background-color: #f0f0f0;
    /* 左边列背景色 */
    padding: 20px;
  }

  .right-column {
    flex: 1;
    /* 右边列宽度占比，这里为 2，可以根据需要调整 */
    display: flex;
    flex-direction: column;
    /* 纵向排列子元素 */
  }

  .top-right {
    flex: 1;
    /* 上半部分高度占比，这里为 1，可以根据需要调整 */
    //background-color: #dcdcdc;
    /* 上半部分背景色 */
    padding: 20px;
    margin-bottom: 10px;
    /* 上下边距 */
  }

  .bottom-right {
    flex: 1;
    /* 下半部分高度占比，这里为 1，可以根据需要调整 */
    background-color: #f0f0f0;
    /* 下半部分背景色 */
    padding: 20px;
  }
</style>
