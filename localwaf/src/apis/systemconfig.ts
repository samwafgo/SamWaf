import request from '@/utils/request'
//查询所有系统配置列表
export function system_config_list_api(params) {
  return request({
    url: 'system_config/list',
    method: 'get',
    params: params
  })
} 