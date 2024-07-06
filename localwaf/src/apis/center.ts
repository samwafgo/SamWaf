import request from '@/utils/request'
//查看控制中心列表
export function centerListApi(params) {
  return request({
    url: '/center/list',
    method: 'post',
    data: params
  })
}
//详细控制中心详情
export function centerDetailApi(params) {
  return request({
    url: '/center/detail',
    method: 'get',
    params: params
  })
}
