export const RULE = {
  is_manual_rule:"1",
  rule_content:"zxcv",
  rule_base: {
    salience: 10,
    rule_name: "试试",
    rule_domain_code: "请选择网站",
  },
  rule_condition: {
    relation_detail: [{
      fact_name: "MF",
      attr: "HOST",
      attr_type: "string",
      attr_judge: "==",
      attr_val: "值"
    },
    {
      fact_name: "MF",
      attr: "URL",
      attr_type: "int",
      attr_judge: "==",
      attr_val: "0"
    },
    ],
    relation_symbol: "&&"
  },
  rule_do_assignment: [{
    fact_name: "MF",
    attr: "HOST",
    attr_type: "string",
    attr_val: "值"
  },
  {
    fact_name: "MF",
    attr: "PORT",
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
  fact_name: "MF",
  attr: "HOST",
  attr_type: "",
  attr_judge: "==",
  attr_val: "",
  attr_val2: "True"
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
  parms: [
  ],
};

export const RULE_DO_METHOD_PARM = {
    attr_type: "string",
    attr_val: ""
};
