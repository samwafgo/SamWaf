<template>
  <t-form
    ref="form"
    :class="['item-container', `register-${type}`]"
    :data="formData"
    :rules="FORM_RULES"
    label-width="0"
    @submit="onSubmit"
  >
    <template v-if="type == 'phone'">
      <t-form-item name="phone">
        <t-input v-model="formData.phone" :maxlength="11" size="large" placeholder="请输入您的手机号">
          <template #prefix-icon>
            <user-icon />
          </template>
        </t-input>
      </t-form-item>
    </template>

    <template v-if="type == 'email'">
      <t-form-item name="email">
        <t-input v-model="formData.email" type="text" size="large" placeholder="请输入您的邮箱">
          <template #prefix-icon>
            <mail-icon />
          </template>
        </t-input>
      </t-form-item>
    </template>

    <t-form-item name="password">
      <t-input
        v-model="formData.password"
        size="large"
        :type="showPsw ? 'text' : 'password'"
        clearable
        placeholder="请输入登录密码"
      >
        <template #prefix-icon>
          <lock-on-icon />
        </template>
        <template #suffix-icon>
          <browse-icon v-if="showPsw" key="browse" @click="showPsw = !showPsw" />
          <browse-off-icon v-else key="browse-off" @click="showPsw = !showPsw" />
        </template>
      </t-input>
    </t-form-item>

    <template v-if="type == 'phone'">
      <t-form-item class="verification-code" name="verifyCode">
        <t-input v-model="formData.verifyCode" size="large" placeholder="请输入验证码" />
        <t-button variant="outline" :disabled="countDown > 0" @click="handleCounter">
          {{ countDown == 0 ? '发送验证码' : `${countDown}秒后可重发` }}
        </t-button>
      </t-form-item>
    </template>

    <t-form-item class="check-container" name="checked">
      <t-checkbox v-model="formData.checked">我已阅读并同意 </t-checkbox> <span>TDesign服务协议</span> 和
      <span>TDesign 隐私声明</span>
    </t-form-item>

    <t-form-item>
      <t-button block size="large" type="submit"> 注册 </t-button>
    </t-form-item>

    <div class="switch-container">
      <span class="tip" @click="switchType(type == 'phone' ? 'email' : 'phone')">{{
        type == 'phone' ? '使用邮箱注册' : '使用手机号注册'
      }}</span>
    </div>
  </t-form>
</template>
<script lang="ts">
import Vue from 'vue';
import { UserIcon, MailIcon, BrowseIcon, BrowseOffIcon, LockOnIcon } from 'tdesign-icons-vue';

const INITIAL_DATA = {
  phone: '',
  email: '',
  password: '',
  verifyCode: '',
  checked: false,
};

const FORM_RULES = {
  phone: [{ required: true, message: '手机号必填', type: 'error' }],
  email: [{ required: true, email: true, message: '邮箱必填', type: 'error' }],
  password: [{ required: true, message: '密码必填', type: 'error' }],
  verifyCode: [{ required: true, message: '验证码必填', type: 'error' }],
};

/** 高级详情 */
export default Vue.extend({
  name: 'Register',
  components: {
    UserIcon,
    MailIcon,
    BrowseIcon,
    BrowseOffIcon,
    LockOnIcon,
  },
  data() {
    return {
      FORM_RULES,
      type: 'phone',
      emailOptions: [],
      formData: { ...INITIAL_DATA },
      showPsw: false,
      countDown: 0,
      intervalTimer: null,
    };
  },
  beforeDestroy() {
    clearInterval(this.intervalTimer);
  },
  methods: {
    onSubmit({ validateResult }: { validateResult: boolean }) {
      if (validateResult === true) {
        if (!this.formData.checked) {
          this.$message.error('请同意TDesign服务协议和TDesign 隐私声明');
          return;
        }
        this.$message.success('注册成功');
        this.$emit('registerSuccess');
      }
    },
    switchType(val: 'email' | 'phone') {
      this.$refs.form.reset();
      this.type = val;
    },
    handleCounter() {
      this.countDown = 60;
      this.intervalTimer = setInterval(() => {
        if (this.countDown > 0) {
          this.countDown -= 1;
        } else {
          clearInterval(this.intervalTimer);
          this.countDown = 0;
        }
      }, 1000);
    },
  },
});
</script>
