import request from '@/utils/request'
//查询所有账号列表
export function account_list_api(params) {
  return request({
    url: 'account/list',
    method: 'get',
    params: params
  })
}


//查询所有账号操作日志列表
export function account_log_list_api(params) {
  return request({
    url: 'account_log/list',
    method: 'get',
    params: params
  })
}
