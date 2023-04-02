import request from '@/utils/request'
//查看隐私保护URL列表
export function wafLdpURLListApi(params) {
  return request({
    url: '/wafhost/ldpurl/list',
    method: 'get',
    params: params
  })
}
//删除隐私保护URL
export function wafLdpURLDelApi(params) {
  return request({
    url: '/wafhost/ldpurl/del',
    method: 'get',
    params: params
  })
}
//编辑隐私保护URL
export function wafLdpURLEditApi(params) {
  return request({
    url: '/wafhost/ldpurl/edit',
    method: 'post',
    data: params
  })
}
//添加隐私保护URL
export function wafLdpURLAddApi(params) {
  return request({
    url: '/wafhost/ldpurl/add',
    method: 'post',
    data: params
  })
}
//详细隐私保护URL
export function wafLdpURLDetailApi(params) {
  return request({
    url: '/wafhost/ldpurl/detail',
    method: 'get',
    params: params
  })
}
