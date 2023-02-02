import request from '@/utils/request'
//登录
export function loginapi(params) {
  return request({
    url: 'login',
    method: 'post',
    data: params
  })
}

//登录
export function loginout(params) {
  return request({
    url: 'loginout',
    method: 'post',
    data: params
  })
}
