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
    ],
  },
];
