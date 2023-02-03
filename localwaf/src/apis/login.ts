import request from '@/utils/request'
//登录
export function loginapi(params) {
  return request({
    url: 'public/login',
    method: 'post',
    data: params
  })
}

//注销
export function logoutapi(params) {
  return request({
    url: 'logout',
    method: 'post',
    data: params
  })
}
