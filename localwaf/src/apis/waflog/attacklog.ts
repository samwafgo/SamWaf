import request from '@/utils/request'
//查询攻击日志列表
export function attacklogList(params) {
  return request({
    url: '/waflog/attacklog/list',
    method: 'get',
    params: params
  })
}

//查询存档日志库列表
export function allsharedblist(params) {
  return request({
    url: 'waflog/attack/allsharedb',
    method: 'get',
    params: params
  })
}
