<template>
  <div class="detail-base">
    <t-form :data="formData"  @submit="onSubmit"> <!--:rules="rules"-->
      <!--基本信息 开始-->
      <t-card title="基本信息">
        <t-form-item label="规则名称" name="rule_name">
          <t-input placeholder="请输入内容" v-model="formData.rule_base.rule_name" />
        </t-form-item>
        <t-form-item label="防护网站" name="rule_domain_code">
          <t-input placeholder="请输入内容" v-model="formData.rule_base.rule_domain_code" />
        </t-form-item>
        <t-form-item label="防护级别" name="salience">
          <t-input placeholder="请输入内容" v-model="formData.rule_base.salience" />
        </t-form-item>
      </t-card>
      <!--基本信息 结束-->

      <!--规则编排 开始-->
      <t-card title="规则编排">
        <t-form-item label="关系" name="relation_symbol">
          <t-select clearable :style="{ width: '480px' }"
            v-model="formData.rule_condition_detail.relation_detail.relation_symbol">
            <t-option v-for="(item, index) in relation_symbol_option" :value="item.value" :label="item.label"
              :key="index">
              {{ item.label }}
            </t-option>
          </t-select>
        </t-form-item>
        <t-card title="条件" v-for="condition_item in formData.rule_condition_detail.relation_detail">
          <t-row :gutter="{ xs: 8, sm: 16, md: 24, lg: 32, xl: 32, xxl: 40 }">
            <t-col :span="4">
              <div>
                <t-form-item label="内置实体名称">
                  <t-select clearable :style="{ width: '480px' }" v-model="condition_item.fact_name">
                    <t-option v-for="(item, index) in fact_option" :value="item.value" :label="item.label" :key="index">
                      {{ item.label }}
                    </t-option>
                  </t-select>
                </t-form-item>
              </div>
            </t-col>
            <t-col :span="4">
              <div>
                <t-form-item label="作用域" name="attr">
                  <t-select clearable :style="{ width: '480px' }" v-model="condition_item.attr">
                    <t-option v-for="(item, index) in attr_option" :value="item.value" :label="item.label" :key="index">
                      {{ item.label }}
                    </t-option>
                  </t-select>
                </t-form-item>
              </div>
            </t-col>
            <t-col :span="4">
              <div>
                <t-form-item label="值类型" name="attr_type">
                  <t-select clearable :style="{ width: '480px' }" v-model="condition_item.attr_type">
                    <t-option v-for="(item, index) in attr_type_option" :value="item.value" :label="item.label"
                      :key="index">
                      {{ item.label }}
                    </t-option>
                  </t-select>
                </t-form-item>
              </div>
            </t-col>
          </t-row>
          <t-form-item label="值" name="att_val">
            <t-input placeholder="请输入内容" v-model="condition_item.attr_val" />
          </t-form-item>
        </t-card>
      </t-card>
      <!--规则编排 结束-->

      <!--符合则执行部分 开始-->
      <t-card title="符合则执行如下">

        <!--赋值总区块 开始-->
        <t-card title="赋值">

          <t-card title="赋值明细" v-for="do_assignment_item in formData.rule_do_assignment">
            <t-row :gutter="{ xs: 8, sm: 16, md: 24, lg: 32, xl: 32, xxl: 40 }">
              <t-col :span="4">
                <div>
                  <t-form-item label="内置实体名称">
                    <t-select clearable :style="{ width: '480px' }" v-model="do_assignment_item.fact_name">
                      <t-option v-for="(item, index) in fact_option" :value="item.value" :label="item.label"
                        :key="index">
                        {{ item.label }}
                      </t-option>
                    </t-select>
                  </t-form-item>
                </div>
              </t-col>
              <t-col :span="4">
                <div>
                  <t-form-item label="作用域" name="attr">
                    <t-select clearable :style="{ width: '480px' }" v-model="do_assignment_item.attr">
                      <t-option v-for="(item, index) in attr_option" :value="item.value" :label="item.label"
                        :key="index">
                        {{ item.label }}
                      </t-option>
                    </t-select>
                  </t-form-item>
                </div>
              </t-col>
              <t-col :span="4">
                <div>
                  <t-form-item label="值类型" name="attr_type">
                    <t-select clearable :style="{ width: '480px' }" v-model="do_assignment_item.attr_type">
                      <t-option v-for="(item, index) in attr_type_option" :value="item.value" :label="item.label"
                        :key="index">
                        {{ item.label }}
                      </t-option>
                    </t-select>
                  </t-form-item>
                </div>
              </t-col>
            </t-row>
            <t-form-item label="值" name="att_val">
              <t-input placeholder="请输入内容" v-model="do_assignment_item.attr_val" />
            </t-form-item>
          </t-card>

        </t-card>
        <!--赋值总区块 结束-->

        <!--方法执行总区块 开始-->
        <t-card title="方法执行">
          <!--方法执行明细 开始-->
          <t-card title="方法明细" v-for="do_method_item in formData.rule_do_method">
            <t-row :gutter="{ xs: 8, sm: 16, md: 24, lg: 32, xl: 32, xxl: 40 }">
              <t-col :span="6">
                <div>
                  <t-form-item label="内置实体名称">
                    <t-select clearable :style="{ width: '480px' }" v-model="do_method_item.fact_name">
                      <t-option v-for="(item, index) in fact_option" :value="item.value" :label="item.label"
                        :key="index">
                        {{ item.label }}
                      </t-option>
                    </t-select>
                  </t-form-item>
                </div>
              </t-col>
              <t-col :span="6">
                <div>
                  <t-form-item label="内置方法名称">
                    <t-select clearable :style="{ width: '480px' }" v-model="do_method_item.method_name">
                      <t-option v-for="(item, index) in method_option" :value="item.value" :label="item.label"
                        :key="index">
                        {{ item.label }}
                      </t-option>
                    </t-select>
                  </t-form-item>
                </div>
              </t-col>
            </t-row>
            <!--传参列表明细 开始-->
            <t-card title="传参">
              <t-row :gutter="{ xs: 8, sm: 16, md: 24, lg: 32, xl: 32, xxl: 40 }"
                v-for="do_method_parms_item in do_method_item.parms">
                <t-col :span="6">
                  <div>
                    <t-form-item label="值类型" name="attr_type">
                      <t-select clearable :style="{ width: '480px' }" v-model="do_method_parms_item.attr_type">
                        <t-option v-for="(item, index) in attr_type_option" :value="item.value" :label="item.label"
                          :key="index">
                          {{ item.label }}
                        </t-option>
                      </t-select>
                    </t-form-item>

                  </div>
                </t-col>
                <t-col :span="6">
                  <div>
                    <t-form-item label="值" name="att_val">
                      <t-input placeholder="请输入内容" v-model="do_method_parms_item.attr_val" />
                    </t-form-item>
                  </div>
                </t-col>
              </t-row>
            </t-card>
            <!--传参列表明细 结束-->
          </t-card>
          <!--方法执行明细 结束-->
        </t-card>
        <!--方法执行总区块 结束-->
      </t-card>
      <!--符合则执行部分 结束-->



      <t-form-item style="margin-left: 100px">
        <t-space size="10px">
          <!-- type = submit，表单中的提交按钮，原生行为 -->
          <t-button theme="primary" type="submit">提交</t-button>
          <!-- type = reset，表单中的重置按钮，原生行为 -->
          <t-button theme="default" variant="base" type="reset">重置</t-button>
        </t-space>
      </t-form-item>
    </t-form>


  </div>
</template>
<script lang="ts">
  import {
    prefix
  } from '@/config/global';
  import {
    RULE
  } from '@/service/service-rule';

  export default {
    name: 'WafRuleAdd',
    data() {
      return {
        prefix,
        detail_data: {},
        rules: {
          rule_name: [{ required: true, message: '请输入规则名称', type: 'error' }],
        },
        fact_option: [{
          label: '默认',
          value: 'MF'
        }, ],
        method_option: [{
          label: '做动作',
          value: 'DoSomeThing'
        }, ],
        attr_option: [{
            label: '网址',
            value: 'URL'
          },
          {
            label: '请求端口',
            value: 'PORT'
          },
          {
            label: '访客IP',
            value: 'SRC_IP'
          },
        ],
        attr_type_option: [{
            label: '文本',
            value: 'string'
          },
          {
            label: '数字',
            value: 'int'
          },
        ],
        relation_symbol_option: [{
            label: '并且',
            value: '&&'
          },
          {
            label: '或者',
            value: 'or'
          },
        ],
        formData: {
          ...RULE
        },

      };
    },
    beforeRouteUpdate(to, from) {
      console.log('beforeRouteUpdate')
    },
    mounted() {
      console.log('----mounted----')
      console.log(RULE)

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
      onSubmit({ result, firstError }): void {
         let that = this
        if (!firstError) {

          let postdata = {...that.formData}
          this.$request
            .post('/wafhost/rule/add', {
              RuleJson: JSON.stringify(postdata)
            })
            .then((res) => {
              let resdata = res.data
              console.log(resdata)
              if (resdata.code === 200) {
                that.$message.success(resdata.msg);
                this.$router.push(
                  {
                    path:'/waf-host/wafrule',
                  },
                );

              }else{
                 that.$message.warning(resdata.msg);
              }
            })
            .catch((e: Error) => {
              console.log(e);
            })
            .finally(() => {
            });
        } else {
          console.log('Errors: ', result);
          that.$message.warning(firstError);
        }
      },
    },
  };
</script>
<style lang="less" scoped>
  @import './index';
</style>
