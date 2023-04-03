import request from '@/utils/request'

//查询版本信息
export function SysVersionApi(params) {
  return request({
    url: 'sysinfo/version',
    method: 'get',
    params: params
  })
}