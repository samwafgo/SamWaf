import request from '@/utils/request'
//查询所有系统配置列表
export function system_config_list_api(data) {
  return request({
    url: 'systemconfig/list',
    method: 'post',
    data: data
  })
}
