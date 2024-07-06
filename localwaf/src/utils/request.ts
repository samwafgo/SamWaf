import axios from 'axios';
import proxy from '../config/host';
import router from '../router/index';
import  {AesDecrypt,AesEncrypt,isObject,isInList} from './usuallytool'

const env = import.meta.env.MODE || 'development';

const API_HOST = env === 'mock' ? '/' : proxy[env].API; // 如果是mock模式 就不配置host 会走本地Mock拦截

const noVisitClientList = ["/center/list", "logout", "public/login"];
const CODE = {
  LOGIN_TIMEOUT: 1000,
  REQUEST_SUCCESS: 0,
  REQUEST_FOBID: 1001,
  AUTH_FAILURE :-999
};

const instance = axios.create({
  baseURL: API_HOST,
  timeout: 3000,
  withCredentials: true,
  transformRequest: [
    function (data, headers) {
      // 这里没有对 Form-Data 格式的报文处理
      if (isObject(data)) {
        // 一、请求参数加密
        //if (process.env.VUE_APP_RUNTIME === 'prod') {
          data = JSON.stringify(data)
          //headers["keyCipher"] = rsaEncrypt(aesKey) // 传输 aes key 密文
          data = AesEncrypt(data) // 加密请求参数
       // }
        return data
      }
      return data
    }
  ],
});

// eslint-disable-next-line
// @ts-ignore
// axios的retry ts类型有问题
instance.interceptors.retry = 3;


instance.interceptors.request.use(
  (config:any) => {

    let token:string =localStorage.getItem("access_token")? localStorage.getItem("access_token"):"" //此处换成自己获取回来的token，通常存在在cookie或者store里面
    if (token) {
      // 让每个请求携带token-- ['X-Token']为自定义key 请根据实际情况自行修改
      config.headers['X-Token'] = token
      //config.headers.Authorization =  + token
    }
    //如果有远控机器
    let remoteBean =localStorage.getItem("current_server")? localStorage.getItem("current_server"):"" //此处换成自己获取回来的token，通常存在在cookie或者store里面

    if (remoteBean && !isInList(config.url,noVisitClientList) ) {
      console.log(config)
      remoteBean = JSON.parse(localStorage.getItem("current_server"))
      // 让每个请求携带token-- ['X-Token']为自定义key 请根据实际情况自行修改
      config.headers['Remote-Waf-User-Id'] =  remoteBean.client_tenant_id+"@"+remoteBean.client_user_code
      //config.headers.Authorization =  + token
    }
    /*if(config.headers['Content-Type'] !=undefined && config.headers['Content-Type']=="application/json" ){
      data = JSON.stringify(config.data)

      config.data = AesEncrypt(data) // 加密请求参数
    }
    console.log("request",config)*/
    return config
  },
  error => {
    // Do something with request error
    console.log("出错啦", error) // for debug
    Promise.reject(error)
  }
)
instance.interceptors.response.use(
  (response) => {
    if (response.status === 200) {
      const { data } = response;
      if (data.code === CODE.REQUEST_SUCCESS) {
        //console.log("解密前",data)
        let tmpSrcContent = AesDecrypt(data.data)
        data.data = JSON.parse(tmpSrcContent)
        //console.log("解密后",data)

        //console.log("再加密后",AesEncrypt(tmpSrcContent))
        return data;
      }else {
        //如果有远控机器
        let remoteBean =localStorage.getItem("current_server")? localStorage.getItem("current_server"):"" //此处换成自己获取回来的token，通常存在在cookie或者store里面

        if(!remoteBean  && data.code === CODE.AUTH_FAILURE){
          localStorage.clear();     //删除用户信息
          console.log("鉴权失败")
          router.replace({path: '/login'})
        }else if(remoteBean  && data.code === CODE.AUTH_FAILURE){
          remoteBean = JSON.parse(localStorage.getItem("current_server"))
          data.code = -1
          data.msg = remoteBean.client_server_name + " 远端鉴权失败"
          console.log("远端鉴权失败")
        }
      }
      return data;
    }
  },
  (err) => {
    const { config } = err;

    if (!config || !config.retry) return Promise.reject(err);

    config.retryCount = config.retryCount || 0;

    if (config.retryCount >= config.retry) {
      return Promise.reject(err);
    }

    config.retryCount += 1;

    const backoff = new Promise((resolve) => {
      setTimeout(() => {
        resolve({});
      }, config.retryDelay || 1);
    });

    return backoff.then(() => instance(config));
  },
);

export default instance;
