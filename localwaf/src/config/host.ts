export default {
  development: {
    // 开发环境接口请求
    API: 'http://127.0.0.1:26666/samwaf',
    // 开发环境 cdn 路径
    CDN: '',
  },
  test: {
    // 测试环境接口地址
    API: 'https://service-exndqyuk-1257786608.gz.apigw.tencentcs.com',
    // 测试环境 cdn 路径
    CDN: '',
  },
  release: {
    // 正式环境接口地址
    API: '/samwaf',
    // 正式环境 cdn 路径
    CDN: '',
  },
};
