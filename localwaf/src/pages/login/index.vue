<template>
  <div class="login-wrapper">
   <!-- <login-header /> -->

    <div class="login-container">
      <div class="title-container">
        <h1 class="title margin-no">登录</h1>
        <h1 class="title">SamWaf网站防火墙后台</h1>
        <div class="sub-title">
         <!-- <p class="tip">{{ type == 'register' ? '已有账号?' : '没有账号吗?' }}</p>
          <p class="tip" @click="switchType(type == 'register' ? 'login' : 'register')">
            {{ type == 'register' ? '登录' : '注册新账号' }}
          </p>-->
        </div>
      </div>

      <login v-if="type === 'login'" />
      <register v-else @register-success="switchType('login')" />
      <tdesign-setting />
    </div>

    <footer class="copyright">Copyright @ 2022-{{ new Date().getFullYear() }} SamWaf. All Rights Reserved  <t-link theme="primary" @click="handleJumpOnlineUrl"> 遇到问题？ </t-link>  <a href="https://doc.samwaf.com">SamWaf在线文档</a></footer>
  </div>
</template>
<script>
import Login from './components/components-login.vue';
import Register from './components/components-register.vue';
import LoginHeader from './components/components-header.vue';
import TdesignSetting from '@/layouts/setting.vue';

export default {
  name: 'LoginIndex',
  components: {
    LoginHeader,
    Login,
    Register,
    TdesignSetting,
  },
  data() {
    return {
      type: 'login',
      copyright:'',
    };
  },
  methods: {
    switchType(val) {
      this.type = val;
    },
    //跳转界面
    handleJumpOnlineUrl(){
      window.open(this.samwafglobalconfig.getOnlineUrl()+"");
    },
  },
};
</script>
<style lang="less">
@import url('./index.less');
</style>
