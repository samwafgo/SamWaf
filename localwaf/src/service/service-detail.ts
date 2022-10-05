interface DashboardPanel {
  title: string;
  number: string | number;
  leftType?: string;
  upTrend?: string;
  downTrend?: string;
}

export const PANE_LIST_DATA: Array<DashboardPanel> = [
  {
    title: '总申请数（次）',
    number: '1126',
    upTrend: '10%',
  },
  {
    title: '供应商数量（个）',
    number: '13',
    downTrend: '13%',
  },
  {
    title: '采购商品品类（类）',
    number: '4',
    upTrend: '10%',
  },
  {
    title: '申请人数量（人）',
    number: 90,
    downTrend: '44%',
    leftType: 'icon-file-paste',
  },
  {
    title: '申请完成率（%）',
    number: 80.5,
    upTrend: '70%',
  },
  {
    title: '到货及时率（%）',
    number: 78,
    upTrend: '16%',
  },
];
export const PRODUCT_LIST = [
  {
    description: 'SSL证书又叫服务器证书，腾讯云为您提供证书的一站式服务，包括免费、付费证书的申请、管理及部',
    index: 1,
    isSetup: true,
    name: 'SSL证书',
    type: 4,
  },
  {
    description: 'SSL证书又叫服务器证书，腾讯云为您提供证书的一站式服务，包括免费、付费证书的申请、管理及部',
    index: 1,
    isSetup: true,
    name: 'SSL证书',
    type: 4,
  },
];
