export const RULE = {
  rule_base: {
    salience: 10,
    rule_name: "试试",
    rule_domain_code: "CODDD",
  },
  rule_condition_detail: {
    relation_detail: [{
      fact_name: "MF",
      attr: "StringAttribute",
      attr_type: "string",
      attr_judge: "==",
      attr_val: "值"
    },
    {
      fact_name: "MF",
      attr: "IntAttribute",
      attr_type: "int",
      attr_judge: "==",
      attr_val: "0"
    },
    ],
    relation_symbol: "&&"
  },
  rule_do_assignment: [{
    fact_name: "MF",
    attr: "StringAttribute",
    attr_type: "string",
    attr_val: "值"
  },
  {
    fact_name: "MF",
    attr: "IntAttribute",
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
