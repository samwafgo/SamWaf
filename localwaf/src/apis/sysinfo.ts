import request from '@/utils/request'

//查询版本信息
export function SysVersionApi(params) {
  return request({
    url: 'sysinfo/version',
    method: 'get',
    params: params
  })
}

//查询是否需要升级版本信息
export function CheckVersionApi(params) {
  return request({
    url: 'sysinfo/checkversion',
    method: 'get',
    params: params
  })
}

//升级
export function DoUpdateApi(params) {
  return request({
    url: 'sysinfo/update',
    method: 'get',
    params: params
  })
}
