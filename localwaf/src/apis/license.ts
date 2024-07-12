import request from '@/utils/request'

/**
 * 授权文件
 */

//获取授权详情
export function getLicenseDetailApi(params) {
  return request({
    url: '/license/detail',
    method: 'get',
    params: params
  })
}
//确认刚刚输入的文件
export function confirmLicenseApi(params) {
  return request({
    url: '/license/confirm',
    method: 'get',
    params: params
  })
}
