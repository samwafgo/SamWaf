import { ViewModuleIcon } from 'tdesign-icons-vue';
import Layout from '@/layouts/index.vue';

export default [
 {
    path: '/waf-host',
    name: 'wafhost',
    component: Layout,
    redirect: '/waf-host/wafhost',
    meta: { title: '网站防护', icon: ViewModuleIcon },
    children: [
      {
        path: 'wafhost',
        name: 'WafHost',
        component: () => import('@/pages/waf-host/host/index.vue'),
        meta: { title: '网站防护' },
      },
      {
        path: 'wafhostdetail',
        name: 'WafhostDetail',
        component: () => import('@/pages/waf-host/host/detail/index.vue'),
        meta: { title: '主机防护详情' ,hidden: true,keepAlive:false}
        ,

      },
      {
        path: 'wafrule',
        name: 'WafRule',
        component: () => import('@/pages/waf-host/rule/index.vue'),
        meta: { title: '防御规则' },
      }, 
      {
        path: 'wafruleedit',
        name: 'Wafruleedit',
        component: () => import('@/pages/waf-host/rule/edit/index.vue'),
        meta: { title: '防御规则编辑' ,keepAlive:false},
      }, 
    ],
  },
];
