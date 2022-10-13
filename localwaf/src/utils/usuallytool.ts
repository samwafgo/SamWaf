
export function copyObj(obj){
     const newObj = {};
      for (let key in obj) {
          if (typeof obj[key] !== 'object') {
              newObj[key] = obj[key];
          } else {
              newObj[key] = copyObj(obj[key]);
          }
      }
      return newObj;
}
