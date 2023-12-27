import request from '@/utils/request'
//查看规则列表
export function wafRuleListApi(params) {
  return request({
    url: '/wafhost/rule/list',
    method: 'post',
    data: params
  })
}
//删除规则
export function wafRuleDelApi(params) {
  return request({
    url: '/wafhost/rule/del',
    method: 'get',
    params: params
  })
}
//编辑规则
export function wafRuleEditApi(params) {
  return request({
    url: '/wafhost/rule/edit',
    method: 'post',
    data: params
  })
}
//添加规则
export function wafRuleAddApi(params) {
  return request({
    url: '/wafhost/rule/add',
    method: 'post',
    data: params
  })
}
//详细规则
export function wafRuleDetailApi(params) {
  return request({
    url: '/wafhost/rule/detail',
    method: 'get',
    params: params
  })
}
