<template>
  <t-form
    ref="form"
    :class="['item-container', `login-${type}`]"
    :data="formData"
    :rules="FORM_RULES"
    label-width="0"
    @submit="onSubmit"
  >
    <template v-if="type == 'password'">
      <t-form-item name="account">
        <t-input v-model="formData.account" size="large" :placeholder="$t('login.input_account_placeholder')">
          <template #prefix-icon>
            <user-icon />
          </template>
        </t-input>
      </t-form-item>

      <t-form-item name="password">
        <t-input
          v-model="formData.password"
          size="large"
          :type="showPsw ? 'text' : 'password'"
          clearable
          key="password"
          :placeholder="$t('login.input_password_placeholder')"
        >
          <template #prefix-icon>
            <lock-on-icon />
          </template>
          <template #suffix-icon>
            <browse-icon v-if="showPsw" @click="showPsw = !showPsw" key="browse" />
            <browse-off-icon v-else @click="showPsw = !showPsw" key="browse-off" />
          </template>
        </t-input>
      </t-form-item>
    </template>

    <t-form-item v-if="type !== 'qrcode'" class="btn-container">
      <t-button block size="large" type="submit"> {{ $t('login.login_btn_title') }} </t-button>
    </t-form-item>
  </t-form>
</template>
<script lang="ts">
import i18n from '@/i18n'; // 确保导入全局 i18n 实例
import Vue from 'vue';
import QrcodeVue from 'qrcode.vue';
import { UserIcon, LockOnIcon, BrowseOffIcon, BrowseIcon, RefreshIcon } from 'tdesign-icons-vue';
import { loginapi } from '@/apis/login';
const INITIAL_DATA = {
  phone: '',
  account: '',
  password: '',
  verifyCode: '',
  checked: false,
};

const FORM_RULES = {
  phone: [{ required: true, message: i18n.t('login.rule.phone') , type: 'error' }],
  account: [{ required: true, message: i18n.t('login.rule.account') , type: 'error' }],
  password: [{ required: true, message: i18n.t('login.rule.password') , type: 'error' }],
  verifyCode: [{ required: true, message: i18n.t('login.rule.verifyCode') , type: 'error' }],
};
/** 高级详情 */
export default Vue.extend({
  name: 'Login',
  components: {
    QrcodeVue,
    UserIcon,
    LockOnIcon,
    BrowseOffIcon,
    BrowseIcon,
    RefreshIcon,
  },
  data() {
    return {
      FORM_RULES,
      type: 'password',
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
    switchType(val) {
      this.type = val;
      this.$refs.form.reset();
    },
     onSubmit({ validateResult }) {
      if (validateResult === true) {
        loginapi({login_account:this.formData.account,login_password:this.formData.password})
        .then((res)=>{
            console.log(res)
            if(res.code==0){
                localStorage.setItem("access_token",res.data.access_token)
                localStorage.setItem("current_account",this.formData.account)
                this.$store.dispatch('user/login', this.formData);

                this.$message.success( this.$t('login.login_success'));
                setTimeout(()=>{
                   this.$router.replace('/').catch(() => '');
                },1000)

            }else{
              this.$message.error(res.msg);
            }

        }).catch((err)=>{
            console.log(err)
        })

      }
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
