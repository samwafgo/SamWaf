import request from '@/utils/request'
//查看IP白名单列表
export function wafIPWhiteListApi(params) {
  return request({
    url: '/wafhost/ipwhite/list',
    method: 'get',
    params: params
  })
}
//删除IP白名单
export function wafIPWhiteDelApi(params) {
  return request({
    url: '/wafhost/ipwhite/del',
    method: 'get',
    params: params
  })
}
//编辑IP白名单
export function wafIPWhiteEditApi(params) {
  return request({
    url: '/wafhost/ipwhite/edit',
    method: 'post',
    data: params
  })
}
//添加IP白名单
export function wafIPWhiteAddApi(params) {
  return request({
    url: '/wafhost/ipwhite/add',
    method: 'post',
    data: params
  })
}
//详细IP白名单
export function wafIPWhiteDetailApi(params) {
  return request({
    url: '/wafhost/ipwhite/detail',
    method: 'get',
    params: params
  })
}
