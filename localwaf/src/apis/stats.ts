import request from '@/utils/request'
//查询顶部的汇总天信息
export function wafstatsumdayapi(params) {
  return request({
    url: 'wafstatsumday',
    method: 'get',
    params: params
  })
}
//查询周期区间的攻击和正常信息
export function wafstatsumdayrangeapi(params) {
  return request({
    url: 'wafstatsumdayrange',
    method: 'get',
    params: params
  })
}
//查询周期区间的IP攻击和正常信息
export function wafstatsumdaytopiprangeapi(params) {
  return request({
    url: 'wafstatsumdaytopiprange',
    method: 'get',
    params: params
  })
}
