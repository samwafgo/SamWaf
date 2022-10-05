import request from '@/utils/request'
//查询攻击日志列表
export function attacklogList(params) {
  return request({
    url: '/waflog/attacklog/list',
    method: 'get',
    params: params
  })
}
