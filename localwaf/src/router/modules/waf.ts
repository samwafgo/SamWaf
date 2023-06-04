import { ViewModuleIcon } from 'tdesign-icons-vue';
import Layout from '@/layouts/index.vue';

export default [
 {
    path: '/waf',
    name: 'waf',
    component: Layout,
    redirect: '/waf-log/visit',
    meta: { title: '防护日志', icon: ViewModuleIcon },
    children: [
      {
        path: 'wafattacklog',
        name: 'WafAttackLog',
        component: () => import('@/pages/waf/attack/index.vue'),
        meta: { title: '防护日志' },
      },
      {
        path: 'wafattacklogdetail',
        name: 'WafAttackLogDetail',
        component: () => import('@/pages/waf/attack/detail/index.vue'),
        meta: { title: '防护详情' ,hidden: true,keepAlive:false}
        ,

      },
    ],
  },
  {
     path: '/account',
     name: 'account',
     component: Layout,
     redirect: '/account',
     meta: { title: '账号', icon: ViewModuleIcon },
     children: [
       {
         path: 'Account',
         name: 'Account',
         component: () => import('@/pages/waf/account/index.vue'),
         meta: { title: '账号管理' },
       },
       {
          path: 'AccountLog',
          name: 'AccountLog',
          component: () => import('@/pages/waf/accountlog/index.vue'),
          meta: { title: '账号操作日志' },
       },


     ],
   }, 
  {
    path: '/sys',
    name: 'sys',
    component: Layout,
    redirect: '/sys',
    meta: { title: '系统设置', icon: ViewModuleIcon },
    children: [
      {
         path: 'SysLog',
         name: 'SysLog',
         component: () => import('@/pages/waf/syslog/index.vue'),
         meta: { title: '系统操作日志' },
      },
      {
         path: 'SystemConfig',
         name: 'SystemConfig',
         component: () => import('@/pages/waf/systemconfig/index.vue'),
         meta: { title: '参数设置' },
       },

    ],
  },

  {
    path: '/waf-host',
    name: 'wafhost',
    component: Layout,
    meta: { title: '网站防护', icon: ViewModuleIcon },
    children: [
      {
        path: 'wafhost',
        name: 'WafHost',
        component: () => import('@/pages/waf/host/index.vue'),
        meta: { title: '网站防护' },

      },
      {
        path: 'wafhostdetail',
        name: 'WafHostDetail',
        component: () => import('@/pages/waf/host/detail/index.vue'),
        meta: { title: '主机防护详情', hidden: true},
      },
      {
        path: 'wafrule',
        name: 'WafRule',
        component: () => import('@/pages/waf/rule/index.vue'),
        meta: { title: '防御规则' },
      },
      {
        path: 'wafruleedit',
        name: 'Wafruleedit',
        component: () => import('@/pages/waf/rule/edit/index.vue'),
        meta: { title: '防御规则编辑', keepAlive: false, hidden: true },
      },
      {
        path: 'wafipwhitelist',
        name: 'WafIpWhiteList',
        component: () => import('@/pages/waf/ipwhite/index.vue'),
        meta: { title: 'IP白名单' },

      },
      {
        path: 'wafurlwhitelist',
        name: 'WafUrlWhiteList',
        component: () => import('@/pages/waf/urlwhite/index.vue'),
        meta: { title: 'Url白名单' },

      },

      {
        path: 'wafipBlocklist',
        name: 'WafIpBlockList',
        component: () => import('@/pages/waf/ipblock/index.vue'),
        meta: { title: 'IP黑名单' },

      },
      {
        path: 'wafurlblocklist',
        name: 'WafUrlBlockList',
        component: () => import('@/pages/waf/urlblock/index.vue'),
        meta: { title: '限制访问Url' },

      },
      {
        path: 'wafldpurllist',
        name: 'WafLdpUrlList',
        component: () => import('@/pages/waf/ldpurl/index.vue'),
        meta: { title: '隐私保护Url' },

      },{
        path: 'wafanticclist',
        name: 'WafAntiCCList',
        component: () => import('@/pages/waf/anticc/index.vue'),
        meta: { title: 'CC防护设置' },

      },
    ],
  },
];
