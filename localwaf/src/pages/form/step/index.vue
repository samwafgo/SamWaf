<template>
  <t-card>
    <div class="form-step-container">
      <!-- 简单步骤条 -->
      <t-card :bordered="false">
        <t-steps :defaultCurrent="1" :current="activeForm" status="process">
          <t-step-item title="申请提交" content="已于12月21日提交"></t-step-item>
          <t-step-item title="电子发票" content="预计1～3个工作日"></t-step-item>
          <t-step-item title="发票已邮寄" content="电子发票开出后7个工作日内联系"></t-step-item>
          <t-step-item title="完成" content=""></t-step-item>
        </t-steps>
      </t-card>

      <!-- 分步表单1 -->
      <div v-show="activeForm === 0" class="rule-tips">
        <t-alert theme="info" title="发票开具规则：" :close="true">
          <div slot="message">
            <p class="span-txt">
              1、申请开票后，电子发票在1～3个工作日内开具；增值税专用发票（纸质）如资质审核通过，将在电子发票开具后10个工作日内为您寄出；
            </p>
            <p class="span-txt">2、开票金额为您实际支付金额；</p>
            <p class="span-txt">3、如有疑问请直接联系：13300001111。</p>
          </div>
        </t-alert>
      </div>
      <t-form
        v-show="activeForm === 0"
        class="step-form"
        :data="formData1"
        :rules="rules"
        labelAlign="right"
        @submit="onSubmit1"
      >
        <t-form-item label="合同名称" name="name">
          <t-select :style="{ width: '390px' }" v-model="formData1.name" class="demo-select-base" clearable>
            <t-option v-for="(item, index) in nameOptions" :value="item.value" :label="item.label" :key="index">
              {{ item.label }}
            </t-option>
          </t-select>
        </t-form-item>
        <t-form-item label="发票类型" name="type">
          <t-select :style="{ width: '390px' }" v-model="formData1.type" class="demo-select-base" clearable>
            <t-option v-for="(item, index) in typeOptions" :value="item.value" :label="item.label" :key="index">
              {{ item.label }}
            </t-option>
          </t-select>
        </t-form-item>
        <t-form-item class="amount-label" label="开票金额"> {{ amount }} 元 </t-form-item>
        <t-form-item>
          <t-button theme="primary" type="submit">提交申请</t-button>
        </t-form-item>
      </t-form>

      <!-- 分步表单2 -->
      <t-form
        v-show="activeForm === 1"
        class="step-form"
        :data="formData2"
        :rules="rules"
        labelAlign="right"
        @reset="onReset2"
        @submit="onSubmit2"
      >
        <t-form-item label="发票抬头" name="title">
          <t-input :style="{ width: '480px' }" v-model="formData2.title" placeholder="请输入发票抬头"></t-input>
        </t-form-item>
        <t-form-item label="纳税人识别号" name="taxNum">
          <t-input :style="{ width: '480px' }" v-model="formData2.taxNum" placeholder="请输入纳税人识别号"></t-input>
        </t-form-item>
        <t-form-item label="单位地址" name="address">
          <t-input :style="{ width: '480px' }" v-model="formData2.address" placeholder="请输入单位地址"></t-input>
        </t-form-item>
        <t-form-item label="开户行" name="bank">
          <t-input :style="{ width: '480px' }" v-model="formData2.bank" placeholder="请输入开户行"></t-input>
        </t-form-item>
        <t-form-item label="银行账号" name="bankAccount">
          <t-input :style="{ width: '480px' }" v-model="formData2.bankAccount" placeholder="请输入银行账号"></t-input>
        </t-form-item>
        <t-form-item label="通知邮箱" name="email">
          <t-input :style="{ width: '480px' }" v-model="formData2.email" placeholder="请输入通知邮箱"></t-input>
        </t-form-item>
        <t-form-item label="通知手机" name="tel">
          <t-input :style="{ width: '480px' }" v-model="formData2.tel" placeholder="请输入通知手机"></t-input>
        </t-form-item>
        <t-form-item>
          <t-button type="reset" theme="default" variant="base">上一步</t-button>
          <t-button theme="primary" type="submit">下一步</t-button>
        </t-form-item>
      </t-form>

      <!-- 分步表单3 -->
      <t-form
        v-show="activeForm === 2"
        class="step-form"
        :data="formData3"
        :rules="rules"
        labelAlign="left"
        @reset="onReset3"
        @submit="onSubmit3"
      >
        <t-form-item label="收货人" name="consignee">
          <t-input :style="{ width: '480px' }" v-model="formData3.consignee" placeholder="请输入收货人"></t-input>
        </t-form-item>
        <t-form-item label="手机号码" name="mobileNum">
          <t-input :style="{ width: '480px' }" v-model="formData3.mobileNum" placeholder="请输入手机号码"></t-input>
        </t-form-item>
        <t-form-item label="收货地址" name="deliveryAddress">
          <t-select
            :style="{ width: '480px' }"
            placeholder="请选择收货地址"
            v-model="formData3.deliveryAddress"
            class="demo-select-base"
            clearable
          >
            <t-option v-for="(item, index) in addressOptions" :value="item.value" :label="item.label" :key="index">
              {{ item.label }}
            </t-option>
          </t-select>
        </t-form-item>
        <t-form-item label="详细地址" name="fullAddress">
          <t-textarea
            :style="{ width: '480px' }"
            v-model="formData3.fullAddress"
            placeholder="请输入详细地址"
          ></t-textarea>
        </t-form-item>
        <t-form-item>
          <t-button type="reset" theme="default" variant="base">上一步</t-button>
          <t-button theme="primary" type="submit">下一步</t-button>
        </t-form-item>
      </t-form>

      <!-- 分步表单4 -->
      <div class="step-form-4" v-show="activeForm === 6">
        <check-circle-filled-icon style="color: green" size="52px" />
        <p class="text">完成开票申请</p>
        <p class="tips">预计1～3个工作日会将电子发票发至邮箱，发票邮寄请耐心等待</p>
        <div class="button-group">
          <t-button @click="onReset4" theme="primary">再次申请</t-button>
          <t-button @click="onSubmit4" variant="base" theme="default">查看进度</t-button>
        </div>
      </div>
    </div>
  </t-card>
</template>
<script>
import { CheckCircleFilledIcon } from 'tdesign-icons-vue';
import { prefix } from '@/config/global';

const INITIAL_DATA1 = {
  name: '',
  type: '',
};
const INITIAL_DATA2 = {
  title: '',
  taxNum: '',
  address: '',
  bank: '',
  bankAccount: '',
  email: '',
  tel: '',
};
const INITIAL_DATA3 = {
  consignee: '',
  mobileNum: '',
  deliveryAddress: '',
  fullAddress: '',
};

export default {
  name: 'FormStep',
  components: {
    CheckCircleFilledIcon,
  },
  data() {
    return {
      prefix,
      formData1: { ...INITIAL_DATA1 },
      formData2: { ...INITIAL_DATA2 },
      formData3: { ...INITIAL_DATA3 },
      nameOptions: [
        { label: '合同A', value: '1' },
        { label: '合同B', value: '2' },
        { label: '合同C', value: '3' },
      ],
      typeOptions: [
        { label: '类型A', value: '1' },
        { label: '类型B', value: '2' },
        { label: '类型C', value: '3' },
      ],
      addressOptions: [
        { label: '广东省深圳市南山区', value: '1' },
        { label: '北京市海淀区', value: '2' },
        { label: '上海市徐汇区', value: '3' },
        { label: '四川省成都市高新区', value: '4' },
        { label: '广东省广州市天河区', value: '5' },
        { label: '陕西省西安市高新区', value: '6' },
      ],
      rules: {
        name: [{ required: true, message: '请选择合同名称', type: 'error' }],
        type: [{ required: true, message: '请选择发票类型', type: 'error' }],
        title: [{ required: true, message: '请输入发票抬头', type: 'error' }],
        taxNum: [{ required: true, message: '请输入纳税人识别号', type: 'error' }],
        consignee: [{ required: true, message: '请输入收货人', type: 'error' }],
        mobileNum: [{ required: true, message: '请输入手机号码', type: 'error' }],
        deliveryAddress: [{ required: true, message: '请选择收货地址', type: 'error' }],
        fullAddress: [{ required: true, message: '请输入详细地址', type: 'error' }],
      },
      activeForm: 0,
    };
  },
  computed: {
    amount() {
      if (this.formData1.name === '1') {
        return '565421';
      }
      if (this.formData1.name === '2') {
        return '278821';
      }
      if (this.formData1.name === '3') {
        return '109824';
      }
      return '--';
    },
  },
  methods: {
    onSubmit1({ validateResult }) {
      if (validateResult === true) {
        this.activeForm = 1;
      }
    },
    onSubmit2({ validateResult }) {
      if (validateResult === true) {
        this.activeForm = 2;
      }
    },
    onReset2() {
      this.activeForm = 0;
    },
    onSubmit3({ validateResult }) {
      if (validateResult === true) {
        this.activeForm = 6;
      }
    },
    onReset3() {
      this.activeForm = 1;
    },
    onSubmit4() {
      this.$router.replace({ path: '/detail/advanced' });
    },
    onReset4() {
      this.activeForm = 0;
    },
  },
};
</script>
<style lang="less" scoped>
@import './index';
</style>
