import request from '@/utils/request'
  
//查询所有系统操作日志列表
export function sys_log_list_api(params) {
  return request({
    url: 'sys_log/list',
    method: 'get',
    params: params
  })
}
