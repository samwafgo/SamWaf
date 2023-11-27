// 获取常用时间
import dayjs from 'dayjs';

export const LAST_7_DAYS = [
  dayjs().subtract(7, 'day').format('YYYY-MM-DD'),
  dayjs().format('YYYY-MM-DD'),
];


export const LAST_30_DAYS = [
  dayjs().subtract(30, 'day').format('YYYY-MM-DD'),
  dayjs().subtract(1, 'day').format('YYYY-MM-DD'),
];
//当前日期
export const NowDate = dayjs().format('YYYY-MM-DD');

//转换数据成毫秒
export function ConvertStringToUnix(timestr: string) :Number{
   return dayjs(timestr).valueOf()
}
//转换字符串
export function ConvertDateToString(now: Date) :string{
   return dayjs(now).format('YYYY-MM-DD');
}
