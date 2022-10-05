import { ViewModuleIcon } from 'tdesign-icons-vue';
import Layout from '@/layouts/index.vue';

export default [
 {
    path: '/waf',
    name: 'waf',
    component: Layout,
    redirect: '/waf-log/visit',
    meta: { title: '安全防护日志', icon: ViewModuleIcon },
    children: [
      {
        path: 'wafvisitlog',
        name: 'WafVisitLog',
        component: () => import('@/pages/waf-log/visit/index.vue'),
        meta: { title: '访问日志' },
      },
      {
        path: 'wafattacklog',
        name: 'WafAttackLog',
        component: () => import('@/pages/waf-log/attack/index.vue'),
        meta: { title: '攻击日志' },
      },
    ],
  },
];
