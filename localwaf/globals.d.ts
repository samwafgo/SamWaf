// 通用声明
declare type ClassName = { [className: string]: any } | ClassName[] | string;

declare interface ImportMeta {
  env: {
    MODE: 'mock' | 'development' | 'test' | 'release';
  };
}

declare module '*.svg' {
  const content: string;
  export default content;
}
