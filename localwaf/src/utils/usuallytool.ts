import proxy from '../config/host';
const env = import.meta.env.MODE || 'development';
import CryptoJS from "crypto-js"; //crypto-js加解密库
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
//解密数据
export function AesDecrypt( text ){
  let key = CryptoJS.enc.Utf8.parse("7E@u*has$d*@s5YX");

  let decryptedData = CryptoJS.AES.decrypt(text, key, {
    iv: key,
    mode: CryptoJS.mode.CBC,
    padding: CryptoJS.pad.Pkcs7
  });

  return decryptedData.toString(CryptoJS.enc.Utf8);
}
//加密数据
export function AesEncrypt( text ){
  let key = CryptoJS.enc.Utf8.parse("7E@u*has$d*@s5YX");

  let encryptedData = CryptoJS.AES.encrypt(text, key, {
    iv: key, // 使用相同的 IV 和密钥
    mode: CryptoJS.mode.CBC,
    padding: CryptoJS.pad.Pkcs7
  });

  return encryptedData.toString();
}
/**
 * 判断是否是对象
 */
export const isObject = (obj, isEffective = false) => {
  if (Object.prototype.toString.call(obj) === "[object Object]") {
    if (isEffective) {
      return !!Object.keys(obj).length;
    } else {
      return true;
    }
  } else {
    return false;
  }
};
