import VueRouter from 'vue-router';

import baseRouters from './modules/base';
import componentsRouters from './modules/components';
import othersRouters from './modules/others';
import waflogRouters from './modules/waflog';

// 存放动态路由
export const asyncRouterList = [...baseRouters, ...componentsRouters, ...othersRouters,...waflogRouters];

// 存放固定的路由
const defaultRouterList = [
  {
    path: '/login',
    name: 'login',
    component: () => import('@/pages/login/index.vue'),
  },
  {
    path: '*',
    redirect: '/dashboard/base',
  },
  ...asyncRouterList,
];

const createRouter = () =>
  new VueRouter({
    routes: defaultRouterList,
    scrollBehavior() {
      return { x: 0, y: 0 };
    },
  });

const router = createRouter();

export function resetRouter() {
  const newRouter = createRouter();
  router.matcher = newRouter.matcher; // reset router
}

export default router;
