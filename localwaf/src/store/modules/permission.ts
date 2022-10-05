import { resetRouter, asyncRouterList } from '@/router';

function filterPermissionsRouters(routes, roles) {
  const res = [];
  routes.forEach((route) => {
    const children = [];
    route.children?.forEach((childRouter) => {
      const roleCode = childRouter.meta?.roleCode || childRouter.name;
      if (roles.indexOf(roleCode) !== -1) {
        children.push(childRouter);
      }
    });
    if (children.length > 0) {
      route.children = children;
      res.push(route);
    }
  });
  return res;
}

const state = {
  whiteListRouters: ['/login'],
  routers: [],
};

const mutations = {
  setRouters: (state, routers) => {
    state.routers = routers;
  },
};

const getters = {
  routers: (state) => state.routers,
  whiteListRouters: (state) => state.whiteListRouters,
};

const actions = {
  async initRoutes({ commit }, roles) {
    let accessedRouters;

    // special token
    if (roles.includes('ALL_ROUTERS')) {
      accessedRouters = asyncRouterList;
    } else {
      accessedRouters = filterPermissionsRouters(asyncRouterList, roles);
    }

    commit('setRouters', accessedRouters);

    // register routers
    // router.addRoutes(state.routers);
  },
  async restore({ commit }) {
    // remove routers
    resetRouter();
    commit('setRouters', []);
  },
};

export default {
  namespaced: true,
  state,
  mutations,
  actions,
  getters,
};
