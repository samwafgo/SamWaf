type AdvancedColumn = {
  name: string;
  value: string;
  type?: any;
};
type TableItem = {
  width?: string | number;
  ellipsis?: any;
  colKey: string;
  title: string;
  sorter?: any;
  align?: string;
  fixed?: string;
  className?: string;
};
class DetailBase {
  /**
   * 下拉框选项数据
   *
   * @returns
   *
   * @memberOf DetailBase
   */
  getBaseInfoData(): Array<AdvancedColumn> {
    return [
      {
        name: '合同名称',
        value: '总部办公用品采购项目',
      },
      {
        name: '合同状态',
        value: '履行中',
        type: {
          key: 'contractStatus',
          value: 'inProgress',
        },
      },
      {
        name: '合同编号',
        value: 'BH00010',
      },
      {
        name: '合同类型',
        value: '主合同',
      },
      {
        name: '合同收付类型',
        value: '付款',
      },
      {
        name: '合同金额',
        value: '5,000,000元',
      },
      {
        name: '甲方',
        value: '腾讯科技（深圳）有限公司',
      },
      {
        name: '乙方',
        value: '欧尚',
      },
      {
        name: '合同签订日期',
        value: '2020-12-20',
      },
      {
        name: '合同生效日期',
        value: '2021-01-20',
      },
      {
        name: '合同结束日期',
        value: '2022-12-20',
      },
      {
        name: '合同附件',
        value: '总部办公用品采购项目合同.pdf',
        type: {
          key: 'contractAnnex',
          value: 'pdf',
        },
      },
      {
        name: '备注',
        value: '--',
      },
      {
        name: '创建时间',
        value: '2020-12-22 10:00:00',
      },
    ];
  }

  /**
   * 表格定义基础数据
   *
   * @returns
   *
   * @memberOf DetailBase
   */
  getTableColumns(): Array<TableItem> {
    return [
      {
        width: 300,
        ellipsis: true,
        colKey: 'index',
        title: '申请号',
        sorter: (a, b) => a.index.substr(3) - b.index.substr(3),
      },
      {
        width: 200,
        ellipsis: true,
        colKey: 'pdName',
        title: '产品名称',
        sorter: (a, b) => a.pdName.length - b.pdName.length,
      },
      {
        width: 200,
        ellipsis: true,
        colKey: 'pdNum',
        title: '产品编号',
      },
      {
        width: 200,
        ellipsis: true,
        colKey: 'purchaseNum',
        title: '采购数量',
        sorter: (a, b) => a.purchaseNum - b.purchaseNum,
      },
      {
        width: 200,
        ellipsis: true,
        colKey: 'adminName',
        title: '申请部门',
      },
      {
        width: 200,
        ellipsis: true,
        colKey: 'updateTime',
        title: '创建时间',
        sorter: (a, b) => Date.parse(a.updateTime) - Date.parse(b.updateTime),
      },
      {
        align: 'left',
        fixed: 'right',
        width: 200,
        className: 'test2',
        colKey: 'op',
        title: '操作',
      },
    ];
  }

  /**
   * 获取弹窗配置数据
   *
   * @memberOf DetailBase
   */
  getPropUpData(): any {
    const INITIAL_DATA = {
      name: '',
      warning: '',
      success: '',
      failB: '',
      warningB: '',
      loading: '',
      add: '',
      help: '',
    };

    return {
      formData: { ...INITIAL_DATA },
      courseOptions: [
        { label: '语文', value: '1' },
        { label: '数学', value: '2' },
        { label: '英语', value: '3' },
      ],
      options: [
        {
          label: '资源初始化后',
          value: 'beijing',
        },
        {
          label: '上海',
          value: 'shanghai',
        },
      ],
      options1: [
        {
          label: '资源初始化后',
          value: 'guangzhou',
        },
        {
          label: '深圳',
          value: 'shenzhen',
        },
        {
          label: '东莞',
          value: 'dongguang',
        },
      ],
      options2: [
        {
          label: '资源初始化后',
          value: 'nanjing',
        },
        {
          label: '苏州',
          value: '苏州',
        },
        {
          label: '无锡',
          value: 'wuxi',
        },
      ],
      tSelectOptions: [
        {
          label: 'Sanzhang',
          value: '1',
        },
        {
          label: 'ls',
          value: '2',
        },
        {
          label: 'James',
          value: '3',
        },
      ],
    };
  }
}

export default new DetailBase();
