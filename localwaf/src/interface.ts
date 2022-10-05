import STYLE_CONFIG from '@/config/style';

export interface ResDataType {
  code: number;
  data: any;
}

export interface MenuRoute {
  path: string;
  title?: string;
  icon?:
    | string
    | {
        render: () => void;
      };
  redirect?: string;
  children: MenuRoute[];
  meta: any;
}

export type ModeType = 'dark' | 'light';

export type SettingType = typeof STYLE_CONFIG;

export type ClassName = { [className: string]: any } | ClassName[] | string;

export type CommonObjType = {
  [key: string]: string | number;
};

export interface NotificationItem {
  id: string;
  content: string;
  type: string;
  status: boolean;
  collected: boolean;
  date: string;
  quality: 'high' | 'low' | 'middle';
}
