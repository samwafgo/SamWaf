import request from '@/utils/request'
//查询所有主机列表
export function allhost(params) {
  return request({
    url: 'wafhost/host/allhost',
    method: 'get',
    params: params
  })
}