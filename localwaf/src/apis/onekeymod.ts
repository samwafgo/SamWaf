import request from '@/utils/request'
//查看一键修改记录列表
export function wafOneKeyModListApi(params) {
  return request({
    url: '/wafhost/onekeymod/list',
    method: 'post',
    data: params
  })
}
//删除一键修改记录
export function wafOneKeyModDelApi(params) {
  return request({
    url: '/wafhost/onekeymod/del',
    method: 'get',
    params: params
  })
}
//详细一键修改记录
export function wafOneKeyModDetailApi(params) {
  return request({
    url: '/wafhost/onekeymod/detail',
    method: 'get',
    params: params
  })
}
//触发一键修改
export function wafDoOneKeyModApi(params) {
  return request({
    url: '/wafhost/onekeymod/doModify',
    method: 'post',
    data: params
  })
}
