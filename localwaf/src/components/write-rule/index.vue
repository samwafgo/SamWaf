<template>
  <div class="in-coder-panel">
    <textarea ref="mycode" v-model="code" class="text_cls" ></textarea>
  </div>
</template>

<script>

import 'codemirror/lib/codemirror.css'
import 'codemirror/addon/hint/show-hint.css'
const CodeMirror = require('codemirror/lib/codemirror')
require('codemirror/addon/edit/matchbrackets')
require('codemirror/addon/selection/active-line')
require('codemirror/mode/sql/sql')
require('codemirror/addon/hint/show-hint')
require('codemirror/addon/hint/sql-hint')

export default {
  props: {
    // 外部传入的内容，用于实现双向绑定
    valuecontent:{
      type:String,

    } ,
    // 外部传入的语法类型
    language: {
      type: String,
      default: null,
    },
  },
  watch: {
    valuecontent(newVal) {
      console.log('valuecontent',newVal)
    	//父组件传过来的值，这个需求需要传入点击的数据库表名，默认展示“SELECT * FROM student”
       this.editor.setValue(newVal)
    },
  },
  data() {
    return {
      code: '',
      editor: null,
      content: '',
   	}
  },
  mounted() {
    
    // 初始化
    this._initialize()
    let that = this
    that.$bus.$on('showcodeedit', (e) => {
       console.log('消息总线 来自父组件e', e)
       that.code = e
       that.editor.setValue(that.code)
    })
  },
  methods: {
    send_msg_to_parent () {


       console.log(this.$parent)
       //this.$parent.edtinput("asdfadf")
    	//this.$emit('edtinput',"sdsdsd" )
       console.log("ssss")
    },
  	//父组件调用清空的方法
    resetData() {
      this.editor.setValue('')
    },
    // 初始化
    _initialize() {
      const mime = 'text/x-mariadb'
      // let theme = 'ambiance'//设置主题，不设置的会使用默认主题
      this.editor = CodeMirror.fromTextArea(this.$refs.mycode, {
     	// 选择对应代码编辑器的语言，我这边选的是数据库，根据个人情况自行设置即可
        mode: mime,
        indentWithTabs: true,
        smartIndent: true,
        lineNumbers: true,
        matchBrackets: true,
        extraKeys: {
          // 触发提示按键
          Ctrl: 'autocomplete',
        },
        hintOptions: {
          // 自定义提示选项
          completeSingle: false, // 当匹配只有一项的时候是否自动补全
          tables: {}, // 代码提示
        },
      })
      this.editor.setValue(this.value || this.code)
      // 支持双向绑定
      let that =  this
      this.editor.on('change', (coder) => {
        this.code = coder.getValue()
        if (this.$emit) {
          // 通过监听Input事件可以拿到动态改变的code值
          //this.$emit('edtinput', this.code)
          console.log('在子组件里面edtinput', this.code)
          //this.$emit('update:valuecontent', this.code)
         /* setTimeout(() => {

          }, 0) */
          console.log(that.$parent)
          that.$bus.$emit("codeedit",this.code)
        }
      })
      this.editor.on('inputRead', () => {
        this.editor.showHint()
      })
    },
  },
}
</script>

<style lang="less">
.CodeMirror {
  height: 180px !important;
}
.in-coder-panel {
  border-radius: 5px;
  flex-grow: 1;
  display: flex;
  position: relative;
  .text_cls {
  }
  .cm-variable {
    font-size: 18px;
  }
}
.CodeMirror {
  flex-grow: 1;
  z-index: 1;
}
.CodeMirror-code {
  line-height: 19px;
}

.code-mode-select {
  position: absolute;
  z-index: 2;
  right: 10px;
  top: 10px;
  max-width: 130px;
}
</style>
