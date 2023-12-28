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
//首页获取基本信息
export function wafStatSysinfoapi(params) {
  return request({
    url: 'statsysinfo',
    method: 'get',
    params: params
  })
}
//首页获取运行基本信息
export function wafStatRuntimeSysinfoapi(params) {
  return request({
    url: 'statrumtimesysinfo',
    method: 'get',
    params: params
  })
}


//【数据分析】查询周期区间国家级别攻击和正常信息
export function wafanalysisdaycountryrange(params) {
  return request({
    url: 'wafanalysisdaycountryrange',
    method: 'get',
    params: params
  })
}
