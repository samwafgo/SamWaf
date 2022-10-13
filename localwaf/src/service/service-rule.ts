export const RULE = {
  rule_base: {
    salience: 10,
    rule_name: "试试",
    rule_domain_code: "CODDD",
  },
  rule_condition: {
    relation_detail: [{
      fact_name: "MF",
      attr: "主机",
      attr_type: "string",
      attr_judge: "==",
      attr_val: "值"
    },
    {
      fact_name: "MF",
      attr: "端口",
      attr_type: "int",
      attr_judge: "==",
      attr_val: "0"
    },
    ],
    relation_symbol: "&&"
  },
  rule_do_assignment: [{
    fact_name: "MF",
    attr: "主机",
    attr_type: "string",
    attr_val: "值"
  },
  {
    fact_name: "MF",
    attr: "源端口",
    attr_type: "int",
    attr_val: "0"
  },
  ],
  rule_do_method: [{
    fact_name: "MF",
    method_name: "DoSomeThing",
    parms: [{
      attr_type: "string",
      attr_val: "值"
    },
    {
      attr_type: "string",
      attr_val: "值"
    }
    ],
  }]
  ,
};

export const RULE_RELATION_DETAIL = {
  fact_name: "默认",
  attr: "HOST",
  attr_type: "",
  attr_judge: "==",
  attr_val: ""
};


export const RULE_DO_ASSIGNMENT = {
   fact_name: "",
   attr: "HOST",
   attr_type: "string",
   attr_val: ""
};


export const RULE_DO_METHOD = {
  fact_name: "",
  method_name: "",
  parms: [],
};

export const RULE_DO_METHOD_PARM = {
    attr_type: "string",
    attr_val: ""
};
