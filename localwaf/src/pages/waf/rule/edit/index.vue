<template>
  <div class="detail-base">

    <t-form :data="formData"  @submit="onSubmit"> <!--:rules="rules"-->
      <!--基本信息 开始-->
      <t-card title="基本信息">
        <t-form-item label="规则名称" name="rule_name">
          <t-input placeholder="请输入内容" v-model="formData.rule_base.rule_name" />
        </t-form-item>
        <t-form-item label="防护网站" name="rule_domain_code">
          <t-select v-model="formData.rule_base.rule_domain_code" clearable :style="{ width: '480px' }">
              <t-option v-for="(item, index) in host_options" :value="item.value" :label="item.label"
                :key="index">
                {{ item.label }}
              </t-option>
            </t-select>
        </t-form-item>
        <t-form-item label="防护级别" name="salience">
          <t-input placeholder="请输入内容" v-model="formData.rule_base.salience" />
        </t-form-item>
        <t-form-item label="防护编排方式" name="is_manual_rule">
            <t-select  :style="{ width: '480px' }"
              v-model="formData.is_manual_rule">
              <t-option v-for="(item, index) in rule_manual_option" :value="item.value" :label="item.label"
                :key="index">
                {{ item.label }}
              </t-option>
            </t-select>
        </t-form-item>
      </t-card>
      <!--基本信息 结束-->

       <!--手工编排-->
      <div v-if="formData.is_manual_rule=='0'">
        <!--规则编排 开始-->
      <t-card title="规则编排">
        <t-button theme="primary" @click="ruleDynAdd('cond')">
              新建
        </t-button>
        <t-form-item label="关系" name="relation_symbol" v-if="formData.rule_condition.relation_detail.length>1">
          <t-select clearable :style="{ width: '480px' }"
            v-model="formData.rule_condition.relation_symbol">
            <t-option v-for="(item, index) in relation_symbol_option" :value="item.value" :label="item.label"
              :key="index">
              {{ item.label }}
            </t-option>
          </t-select>
        </t-form-item>
        <t-card title="条件"  v-for="(condition_item,condition_index) in formData.rule_condition.relation_detail">

          <t-button theme="primary" @click="ruleDynDel('cond',condition_index)">
                删除
          </t-button>
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

          <t-row :gutter="{ xs: 8, sm: 16, md: 24, lg: 32, xl: 32, xxl: 40 }">
            <t-col :span="4">
              <div>
               <t-form-item label="判断" name="attr_judge">
                 <t-select clearable :style="{ width: '480px' }" v-model="condition_item.attr_judge">
                   <t-option v-for="(item, index) in attr_judge_option" :value="item.value" :label="item.label"
                     :key="index">
                     {{ item.label }}
                   </t-option>
                 </t-select>
               </t-form-item>
              </div>
            </t-col>
            <t-col :span="4">
              <div>
                <t-form-item label="值" name="att_val">
                  <t-input placeholder="请输入内容" v-model="condition_item.attr_val" />
                </t-form-item>
              </div>
            </t-col>
            <t-col :span="4">
              <div>
                <t-form-item label="函数判断结果" name="att_val2">
                  <t-input placeholder="请输入函数返回值" v-model="condition_item.attr_val2" />
                </t-form-item>
              </div>
            </t-col>
          </t-row>

        </t-card>
      </t-card>
      <!--规则编排 结束-->

      <!--符合则执行部分 开始-->
      <t-card title="符合则执行如下">

        <!--赋值总区块 开始-->
        <t-card title="赋值">
        <t-button theme="primary" @click="ruleDynAdd('assignment')">
              新建
        </t-button>
          <t-card title="赋值明细" v-for="(do_assignment_item,assignment_index) in formData.rule_do_assignment">
            <t-button theme="primary"  @click="ruleDynDel('assignment',assignment_index)">
                  删除
            </t-button>
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
          <t-button theme="primary" @click="ruleDynAdd('method')">
                新建
          </t-button>
          <!--方法执行明细 开始-->
          <t-card title="方法明细" v-for="(do_method_item,method_index) in formData.rule_do_method">
            <t-button theme="primary"  @click="ruleDynDel('method',method_index)">
                  删除
            </t-button>
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
              <t-button theme="primary" @click="ruleDynAdd('parms',method_index)">
                    新建
              </t-button>
              <t-row :gutter="{ xs: 8, sm: 16, md: 24, lg: 32, xl: 32, xxl: 40 }"
                v-for="(do_method_parms_item,parms_index) in do_method_item.parms">
                <t-col :span="4">
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
                <t-col :span="4">
                  <div>
                    <t-form-item label="值" name="att_val">
                      <t-input placeholder="请输入内容" v-model="do_method_parms_item.attr_val" />
                    </t-form-item>
                  </div>
                </t-col>
                <t-col :span="4">
                  <div>
                    <t-button theme="primary"  @click="ruleDynDel('parms',parms_index,method_index)">
                                    删除
                    </t-button>
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

    </div>
    <!--界面编排 结束-->

    <!--手工编排-->
    <div v-if="formData.is_manual_rule=='1'">
    <t-card title="规则编排">
      <writeRule>
        valuecontent="formData.rule_content"
      	@edtinput="edtinput"

      ></writeRule>
    </t-card>
    </div>


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
    RULE,RULE_RELATION_DETAIL,RULE_DO_ASSIGNMENT,RULE_DO_METHOD,RULE_DO_METHOD_PARM
  } from '@/service/service-rule';
  import { copyObj } from '@/utils/usuallytool';
  import writeRule from "@/components/write-rule/index.vue";
  import {
    allhost
  } from '@/apis/host';

  export default {
    name: 'WafRuleEdit',
    components: {
      writeRule
    },
    data() {
      return {
        op_type :"add",
        op_rule_no :"",//规则识别号
        prefix,
        detail_data: {},
        rule_manual_option: [{
          label: '界面编排',
          value: '0'
        }, {
          label: '手工代码编排',
          value: '1'
        }, ],
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
            label: '主机',
            value: 'HOST'
          },
          {
            label: '网址',
            value: 'URL'
          },
          {
            label: '网站来路(referrer)',
            value: 'REFERER'
          },
          {
            label: '用户代理(User-Agent)',
            value: 'USER_AGENT'
          },
          {
            label: '访问方法',
            value: 'METHOD'
          },
          {
            label: '访问COOKIES',
            value: 'COOKIES'
          },
          {
            label: '访问BODY',
            value: 'BODY'
          },
          {
            label: '请求端口',
            value: 'PORT'
          },
          {
            label: '访客IP',
            value: 'SRC_IP'
          },
          {
            label: '访客归属国家',
            value: 'COUNTRY'
          },
          {
            label: '访客归属省份',
            value: 'PROVINCE'
          },{
            label: '访客归属城市',
            value: 'CITY'
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
        attr_judge_option: [
          {
            label: '判断是否等于',
            value: '=='
          },
          {
            label: '判断是否不等于',
            value: '!='
          },
          {
            label: '判断是否大于',
            value: '>'
          },
          {
            label: '判断是否小于',
            value: '<'
          },
          {
            label: '判断是否大于等于',
            value: '>='
          },
          {
            label: '判断是否小于等于',
            value: '<='
          },
          {
            label: '判断包含(函数)',
            value: 'system.Contains'
          },
          {
            label: '判断开头(函数)',
            value: 'system.HasPrefix'
          },
          {
            label: '判断结尾(函数)',
            value: 'system.HasSuffix'
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

        //主机列表
        host_options:[]
      };
    },
    beforeRouteUpdate(to, from) {
      console.log('beforeRouteUpdate')
    },
    mounted() {
      let that = this

      this.loadHostList()
      console.log('----mounted----')
      console.log(RULE)
      this.$bus.$on('codeedit', (e) => {
         console.log('消息总线 来自子组件e', e)
         this.formData.rule_content = e
      })
      //console.log(this.$route.params.req_uuid);
      if(this.$route.query.code != undefined){

        this.op_rule_no = this.$route.query.code
        this.getDetail(this.op_rule_no);
      }
      if(this.$route.query.type != undefined){

        this.op_type = this.$route.query.type
      }
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
      '$route.query.type'(newVal, oldVal) {
        console.log('route.query.type changed', newVal, oldVal)
        //this.getDetail(newVal)
        this.op_type = newVal
      },
      '$route.query.code'(newVal, oldVal) {
        console.log('route.query.code changed', newVal, oldVal)
        this.op_rule_no = newVal
        this.getDetail(newVal)
      },
    },
    methods: {
      loadHostList(){
        let that = this;
        allhost().then((res) => {
              let resdata = res
              console.log(resdata)
              if (resdata.code === 0) {
                  that.host_options = resdata.data;
              }
            })
            .catch((e: Error) => {
              console.log(e);
        })
      },
      getDetail(id) {
        let that = this
        this.$request
          .get('/wafhost/rule/detail', {
            params: {
              CODE: id,
            }
          })
          .then((res) => {
            let resdata = res
            console.log(resdata)
            if (resdata.code === 0) {

              //const { list = [] } = resdata.data;

              that.formData = JSON.parse(resdata.data.rule_content_json);

              that.$bus.$emit("showcodeedit",resdata.data.rule_content)
              console.log('返回的', that.formData )
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
          let postdata = {}
          let url = ''
          if(that.op_type == "add"){
             url = '/wafhost/rule/add'
             postdata = {
                          RuleJson : JSON.stringify(that.formData),
                          is_manual_rule:parseInt( that.formData.is_manual_rule),
                          rule_content:that.formData.rule_content,
                        }
          }else{
             url = '/wafhost/rule/edit'
             postdata = {
               Code:that.op_rule_no,
               RuleJson : JSON.stringify(that.formData),
               is_manual_rule:parseInt( that.formData.is_manual_rule),
               rule_content:that.formData.rule_content,
             }
          }

          this.$request
            .post(url, {
              ...postdata
            })
            .then((res) => {
              let resdata = res
              console.log(resdata)
              if (resdata.code === 0) {
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
      ruleDynAdd(add_type,parent_index){
          console.log(add_type)
          console.log(parent_index)
          console.log(this.formData)
          switch (add_type){
            case "cond":
              this.formData.rule_condition.relation_detail.push(copyObj(RULE_RELATION_DETAIL))
              break;
            case "assignment":
                this.formData.rule_do_assignment.push(copyObj(RULE_DO_ASSIGNMENT))
                break;
            case "method":
                console.log(RULE_DO_METHOD)
                this.formData.rule_do_method.push(copyObj(RULE_DO_METHOD))
                break;
            case "parms":
                console.log(RULE_DO_METHOD_PARM)
                console.log(this.formData.rule_do_method[parent_index])
                this.formData.rule_do_method[parent_index].parms.push(copyObj(RULE_DO_METHOD_PARM))
                break;
            default:
              break;
          }
      },
      ruleDynDel(del_type,index,parent_index){
          console.log(del_type)
          console.log(index)
          console.log(this.formData)
          switch (del_type){
            case "cond":
              this.formData.rule_condition.relation_detail.splice(index,1)
              break;
            case "assignment":
                this.formData.rule_do_assignment.splice(index,1)
                break;
            case "method":
                this.formData.rule_do_method.splice(index,1)
                break;
            case "parms":
               this.formData.rule_do_method[parent_index].parms.splice(index,1)
                break;
            default:
              break;
          }
      },
      edtinput(e){
        console.log('来子组件',e)
      },
      getinfoClick(e){
          console.log(e)

          console.log(this.$refs.changeSql)
      },
    },
  };
</script>
<style lang="less" scoped>
  @import './index';
</style>
