import request from '@/utils/request'
//查看URL白名单列表
export function wafURLWhiteListApi(params) {
  return request({
    url: '/wafhost/urlwhite/list',
    method: 'get',
    params: params
  })
}
//删除URL白名单
export function wafURLWhiteDelApi(params) {
  return request({
    url: '/wafhost/urlwhite/del',
    method: 'get',
    params: params
  })
}
//编辑URL白名单
export function wafURLWhiteEditApi(params) {
  return request({
    url: '/wafhost/urlwhite/edit',
    method: 'post',
    data: params
  })
}
//添加URL白名单
export function wafURLWhiteAddApi(params) {
  return request({
    url: '/wafhost/urlwhite/add',
    method: 'post',
    data: params
  })
}
//详细URL白名单
export function wafURLWhiteDetailApi(params) {
  return request({
    url: '/wafhost/urlwhite/detail',
    method: 'get',
    params: params
  })
}
