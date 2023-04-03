/* WebSocket封装
 * @param url: WebSocket接口地址与携带参数必填
 * @param token: WebSocket接口凭证与携带参数必填
 * @param onOpenFunc: WebSocket的onopen回调函数，如果不需要可传null
 * @param onMessageFunc: WebSocket的onmessage回调函数，如果不需要可传null
 * @param onCloseFunc: WebSocket的onclose回调函数，如果不需要可传null
 * @param onErrorFunc: WebSocket的onerror回调函数，如果不需要可传null
 * @param heartMessage: 发送后台的心跳包参数,必填 (给服务端的心跳包就是定期给服务端发送消息)
 * @param timer: 给后台传送心跳包的间隔时间，不传时使用默认值3000毫秒
 * @param isReconnect: 是否断掉立即重连，不传true时不重连
 */
function useWebSocket(
  url,
  token,
  onOpenFunc,
  onMessageFunc,
  onCloseFunc,
  onErrorFunc,
  heartMessage,
  timer,
  isReconnect
) {
  let isConnected = false; // 设定已链接webSocket标记
  // websocket对象
  let ws = null;
  // 创建并链接webSocket
  let connect = () => {
    // 如果未链接webSocket，则创建一个新的webSocket
    if (!isConnected) {
      ws = new WebSocket(url,[token]);
      isConnected = true;
    }
  };
  // 向后台发送心跳消息
  let heartCheck = () => {
    // for (let i = 0; i < heartMessage.length; i++) {
    //   ws.send(JSON.stringify(heartMessage[i]))
    // }
  };
  // 初始化事件回调函数
  let initEventHandle = () => {
    ws.addEventListener('open', (e) => {
      console.log('onopen', e);
      // 给后台发心跳请求，在onmessage中取得消息则说明链接正常
      //heartCheck()
      // 如果传入了函数，执行onOpenFunc
      if (!onOpenFunc) {
        return false;
      } else {
        onOpenFunc(e, ws);
      }
    });
    ws.addEventListener('message', (e) => {
      // console.log('onmessage', e)
      // 接收到任何后台消息都说明当前连接是正常的
      if (!e) {
        console.log('get nothing from service');
        return false;
      } else {
        // 如果获取到后台消息，则timer毫秒后再次发起心跳请求给后台，检测是否断连
        setTimeout(
          () => {
            if (isConnected) {
              heartCheck();
            }
          },
          !timer ? 3000 : timer
        );
      }
      // 如果传入了函数，执行onMessageFunc
      if (!onMessageFunc) {
        return false;
      } else {
        onMessageFunc(e);
      }
    });
    ws.addEventListener('close', (e) => {
      console.log('onclose', e);
      // 如果传入了函数，执行onCloseFunc
      if (!onCloseFunc) {
        return false;
      } else {
        onCloseFunc(e);
      }
      // if (isReconnect) { // 如果断开立即重连标志为true
      //   // 重新链接webSocket
      //   connect()
      // }
    });
    ws.addEventListener('error', (e) => {
      console.log('onerror', e);
      // 如果传入了函数，执行onErrorFunc
      if (!onErrorFunc) {
        return false;
      } else {
        onErrorFunc(e);
      }
      if (isReconnect) {
        // 如果断开立即重连标志为true
        // 重新链接webSocket
        connect();
      }
    });
  };
  // 初始化webSocket
  // (() => {
  // 1.创建并链接webSocket
  connect();
  // 2.初始化事件回调函数
  initEventHandle();
  // 3.返回是否已连接
  return ws;
  // })()
}

export default {
  useWebSocket,
};