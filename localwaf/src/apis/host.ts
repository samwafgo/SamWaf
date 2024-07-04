import request from '@/utils/request'
//查询所有主机列表
export function allhost(params) {
  return request({
    url: 'wafhost/host/allhost',
    method: 'get',
    params: params
  })
}

//查询主机列表
export function hostlist(data) {
  return request({
    url: 'wafhost/host/list',
    method: 'post',
    data: data
  })
}
//更改防护状态
export function changeGuardStatus(params) {
    return request({
      url: 'wafhost/host/guardstatus',
      method: 'get',
      params: params
    })
}
//更改启动状态
export function changeStartStatus(params) {
  return request({
    url: 'wafhost/host/startstatus',
    method: 'get',
    params: params
  })
}
//加载详情
export function getHostDetail(params) {
  return request({
    url: 'wafhost/host/detail',
    method: 'get',
    params: params
  })
}


//删除主机
export function delHost(params) {
  return request({
    url: 'wafhost/host/del',
    method: 'get',
    params: params
  })
}

//添加主机
export function addHost(data) {
  return request({
    url: 'wafhost/host/add',
    method: 'post',
    data: data
  })
}

//编辑主机
export function editHost(data) {
  return request({
    url: 'wafhost/host/edit',
    method: 'post',
    data: data
  })
}
