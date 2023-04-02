import request from '@/utils/request'
//查看抵御CC攻击列表
export function wafAntiCCListApi(params) {
  return request({
    url: '/wafhost/anticc/list',
    method: 'get',
    params: params
  })
}
//删除抵御CC攻击
export function wafAntiCCDelApi(params) {
  return request({
    url: '/wafhost/anticc/del',
    method: 'get',
    params: params
  })
}
//编辑抵御CC攻击
export function wafAntiCCEditApi(params) {
  return request({
    url: '/wafhost/anticc/edit',
    method: 'post',
    data: params
  })
}
//添加抵御CC攻击
export function wafAntiCCAddApi(params) {
  return request({
    url: '/wafhost/anticc/add',
    method: 'post',
    data: params
  })
}
//详细抵御CC攻击
export function wafAntiCCDetailApi(params) {
  return request({
    url: '/wafhost/anticc/detail',
    method: 'get',
    params: params
  })
}
