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

// 生成随机的IV
function generateRandomIV() {
  return CryptoJS.lib.WordArray.random(16);
}

// 解密数据
export function AesDecrypt(encryptedText: string) {
  const key = CryptoJS.enc.Utf8.parse("7E@u*has$d*@s5YX");

  // 分离加密数据和IV
  const encryptedDataWithIV = CryptoJS.enc.Base64.parse(encryptedText);
  const iv = CryptoJS.lib.WordArray.create(
    encryptedDataWithIV.words.slice(0, 4)
  ); // IV为前16字节
  const encryptedData = CryptoJS.lib.WordArray.create(
    encryptedDataWithIV.words.slice(4)
  ); // 剩余为加密数据

  const decrypted = CryptoJS.AES.decrypt(
    { ciphertext: encryptedData },
    key,
    {
      iv: iv,
      mode: CryptoJS.mode.CBC,
      padding: CryptoJS.pad.Pkcs7,
    }
  );

  return decrypted.toString(CryptoJS.enc.Utf8);
}

// 加密数据
export function AesEncrypt( plainText: string) {
  const key = CryptoJS.enc.Utf8.parse("7E@u*has$d*@s5YX");
  const iv = generateRandomIV();

  const encrypted = CryptoJS.AES.encrypt(plainText, key, {
    iv: iv,
    mode: CryptoJS.mode.CBC,
    padding: CryptoJS.pad.Pkcs7,
  });

  // 将IV和加密数据一起编码为Base64字符串
  const encryptedDataWithIV = iv.concat(encrypted.ciphertext);
  return CryptoJS.enc.Base64.stringify(encryptedDataWithIV);
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

/**
 * value 是否在list中
 * @param value
 * @param list
 */
export const isInList=(value=string, list=Array)=> {
  return list.includes(value);
}
