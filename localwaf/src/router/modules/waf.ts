import { UserSafetyIcon,SystemSettingIcon,UsergroupIcon,SystemLogIcon,ApplicationIcon,LightingCircleIcon ,ServerIcon} from 'tdesign-icons-vue';
import Layout from '@/layouts/index.vue';

export default [

  {
    path: '/waf-host',
    name: 'wafhost',
    component: Layout,
    meta: { title: '网站防护', icon: ApplicationIcon },
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

  {
     path: '/wafanalysis',
     name: 'wafanalysis',
     component: Layout,
     meta: { title: '数据分析', icon: SystemLogIcon },
     children: [
       {
         path: 'wafanalysislog',
         name: 'WafAnalysisLog',
         component: () => import('@/pages/waf/analysis/index.vue'),
         meta: { title: '数据分析' },
       },
     ],
   },
 {
    path: '/waf',
    name: 'waf',
    component: Layout,
    redirect: '/waf-log/visit',
    meta: { title: '防护日志', icon: LightingCircleIcon },
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
     meta: { title: '账号管理', icon: UsergroupIcon },
     children: [
       {
         path: 'Account',
         name: 'Account',
         component: () => import('@/pages/waf/account/index.vue'),
         meta: { title: '账号列表' },
       },
       {
          path: 'AccountLog',
          name: 'AccountLog',
          component: () => import('@/pages/waf/accountlog/index.vue'),
          meta: { title: '账号日志' },
       },


     ],
   },
  {
    path: '/sys',
    name: 'sys',
    component: Layout,
    redirect: '/sys',
    meta: { title: '系统设置', icon: SystemSettingIcon },
    children: [
      {
         path: 'SysLog',
         name: 'SysLog',
         component: () => import('@/pages/waf/syslog/index.vue'),
         meta: { title: '系统日志' },
      },
      {
         path: 'SystemConfig',
         name: 'SystemConfig',
         component: () => import('@/pages/waf/systemconfig/index.vue'),
         meta: { title: '参数设置' },
       },
      {
        path: 'RumtimeSysteminfo',
        name: 'RumtimeSysteminfo',
        component: () => import('@/pages/waf/sysruntime/index.vue'),
        meta: { title: '运行参数' },
      },{
        path: 'OneKeyMod',
        name: 'OneKeyMod',
        component: () => import('@/pages/waf/onekeymod/index.vue'),
        meta: { title: '一键修改' },
      }
    ],
  },

  {
    path: '/center',
    name: 'center',
    component: Layout,
    redirect: '/center',
    meta: { title: '集中管理', icon: ServerIcon },
    children: [
     {
        path: 'CenterManager',
        name: 'CenterManager',
        component: () => import('@/pages/waf/center/index.vue'),
        meta: { title: '设备列表' },
      },
      {
        path: 'License',
        name: 'License',
        component: () => import('@/pages/waf/license/index.vue'),
        meta: { title: '授权信息' },
      },
    ],
  },
];
