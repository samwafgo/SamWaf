import request from '@/utils/request'
//查看URL黑名单列表
export function wafURLBlockListApi(params) {
  return request({
    url: '/wafhost/urlblock/list',
    method: 'get',
    params: params
  })
}
//删除URL黑名单
export function wafURLBlockDelApi(params) {
  return request({
    url: '/wafhost/urlblock/del',
    method: 'get',
    params: params
  })
}
//编辑URL黑名单
export function wafURLBlockEditApi(params) {
  return request({
    url: '/wafhost/urlblock/edit',
    method: 'post',
    data: params
  })
}
//添加URL黑名单
export function wafURLBlockAddApi(params) {
  return request({
    url: '/wafhost/urlblock/add',
    method: 'post',
    data: params
  })
}
//详细URL黑名单
export function wafURLBlockDetailApi(params) {
  return request({
    url: '/wafhost/urlblock/detail',
    method: 'get',
    params: params
  })
}
