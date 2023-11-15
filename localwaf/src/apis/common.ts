import request from '@/utils/request'


//导出excel文件
export function export_api(params) {
  return request({
    url: 'export',
    method: 'get',
    responseType: 'blob',
    timeout: 20000,
    params: params
  })
} 