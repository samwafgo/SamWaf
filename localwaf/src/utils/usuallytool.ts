import proxy from '../config/host';
const env = import.meta.env.MODE || 'development';
export function copyObj(obj){
     const newObj =Array.isArray(obj) ? [] : {}
      for (let key in obj) {
          if (typeof obj[key] !== 'object') {
              newObj[key] = obj[key];
          } else {
              newObj[key] = copyObj(obj[key]);
          }
      }
      return newObj;
}
export function getBaseUrl(){
  const API_HOST = env === 'mock' ? '/' : proxy[env].API; // 如果是mock模式 就不配置host 会走本地Mock拦截
  return API_HOST
}

/**
 * 获取在线文档前缀
 */
export function getOnlineUrl(){
  return "https://doc.samwaf.com"
}
