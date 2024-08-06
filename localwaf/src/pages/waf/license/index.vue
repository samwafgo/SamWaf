<template>
  <div>
    <t-card class="list-card-container">
      <t-alert theme="info" message="SamWaf授权针对大量服务器集中管理用户 仅管控中心端需要注册。如有疑问请联系samwafgo@gmail.com" close>
        <template #operation>
          <span @click="handleJumpOnlineUrl">在线文档</span>
        </template>
      </t-alert>
      <t-row >
        <div>
            <t-row><h1>授权信息</h1></t-row>
            <t-row v-if="regData.username !=''">
              <t-col :span="6">授权版本号：</t-col> <t-col :span="6">{{ regData.version }}</t-col>
              <t-col :span="6">授权用户编码：</t-col> <t-col :span="6">{{ regData.username }}</t-col>
              <t-col :span="6">授权类型：</t-col> <t-col :span="6">{{ regData.member_type }}</t-col>
              <t-col :span="6">授权机器码：</t-col> <t-col :span="6">{{ regData.machine_id }}</t-col>
              <t-col :span="6">授权截至日期：</t-col> <t-col :span="6">{{ regData.expiry_date }}</t-col>
              <t-col>  <t-button variant="outline" @click="HandleImportLicense">
                <cloud-upload-icon slot="icon"  />
                重新上传文件验证
              </t-button>
              </t-col>
            </t-row>
          <t-row v-if="regData.username ==''">
            <t-col :span="6">授权类型：</t-col> <t-col :span="6">免费版</t-col>
            <t-col :span="6">授权机器码：</t-col> <t-col :span="6">{{ clientData.machine_id }}</t-col>
            <t-col :span="6">授权数量：</t-col> <t-col :span="6">3台   </t-col>
            <t-col>  <t-button variant="outline" @click="HandleImportLicense">
              <cloud-upload-icon slot="icon"  />
              上传文件
            </t-button>
            </t-col>
          </t-row>

        </div>
      </t-row>


    </t-card>

    <!-- 导入授权文件弹窗 -->
    <t-dialog header="导入授权文件" :visible.sync="importLicenseFormVisible" @confirm="loadConfirmLicense">
      <t-upload :action="fileUploadUrl" :tips="tips" :headers="fileHeader" v-model="files" @fail="handleFail"
                @success="onSuccess" theme="file-input" placeholder="未选择文件"></t-upload>
    </t-dialog>
  </div>
</template>
<script lang="ts">
import Vue from 'vue';
import {getLicenseDetailApi,confirmLicenseApi} from '@/apis/license';
import {AesDecrypt, getBaseUrl} from "../../../utils/usuallytool";
import {
  CloudUploadIcon
} from 'tdesign-icons-vue';
const INITIAL_REG_DATA = {
  version: '',
  username: '',
  member_type: '',
  machine_id: '',
  expiry_date: '',
  is_expiry:false,
};
const INITIAL_CLIENT_DATA = {
  version: '',
  machine_id: '',
};
export default Vue.extend({
  name: 'ListBase',
  components: { CloudUploadIcon,},
  data() {
    return {
      importLicenseFormVisible: false,
      regData: {
        ...INITIAL_REG_DATA
      },
      clientData: {
        ...INITIAL_CLIENT_DATA
      },
      files: [],
      tips: '上传文件大小在 5M 以内',
      baseUrl: "",
      fileUploadUrl: "",
      fileHeader: {},
    };
  },
  computed: {
    offsetTop() {
      return this.$store.state.setting.isUseTabsRouter ? 48 : 0;
    },
  },
  mounted() {
    this.baseUrl = getBaseUrl()
    this.fileUploadUrl = this.baseUrl + "/license/checklicense"
    this.fileHeader['X-Token'] = localStorage.getItem("access_token") ? localStorage.getItem("access_token") : "" //此处换成自己获取回来的token，通常存在在cookie或者store里面

    this.loadCurrentLicense()
  },

  methods: {
    /**
     * 发送邮件
     **/

    sendMail(){
      const email = 'samwafgo@gmail.com'; // 设置收件人地址
      window.location.href = `mailto:${email}`;
    },
    handleFail({file}) {
      this.$message.error(`文件 ${file.name} 上传失败`);
    },
    onSuccess(e) {
      console.log('license upload1', e.response)
      let data = e.response
      console.log('license upload2', data)
      if (data.code === 0) {
        this.$message.success(data.msg);

        this.tips = data.msg;
      }else{
        this.files = []
        this.$message.warning(data.msg);
      }
      this.loadCurrentLicense()
    },
    //确认上传的文件
    loadConfirmLicense() {
      let that = this
      confirmLicenseApi({})
        .then((res) => {
          let resdata = res
          console.log(resdata)
          if (resdata.code === 0) {
            that.regData = resdata.data.license;
            that.clientData.machine_id = resdata.data.machine_id;
            that.clientData.version = resdata.data.version;
            that.$message.success(resdata.msg);
            that.importLicenseFormVisible=false
          }else{
            that.$message.warning(resdata.msg);
          }
        })
        .catch((e: Error) => {
          console.log(e);
        })
        .finally(() => {
        });
    },
    /**加载当前授权信息**/
    loadCurrentLicense() {
      let that = this
      getLicenseDetailApi({})
        .then((res) => {
          let resdata = res
          console.log(resdata)
          if (resdata.code === 0) {
            that.regData = resdata.data.license;
            that.clientData.machine_id = resdata.data.machine_id;
            that.clientData.version = resdata.data.version;
          }
        })
        .catch((e: Error) => {
          console.log(e);
        })
        .finally(() => {
        });
    },
    /**
     * 导入授权数据
     */
    HandleImportLicense() {
      this.importLicenseFormVisible = true
      this.tips = ""
      this.files = []
    },
    getContainer() {
      return document.querySelector('.tdesign-starter-layout');
    },
    //跳转界面
    handleJumpOnlineUrl() {
      window.open(this.samwafglobalconfig.getOnlineUrl() + "/guide/License.html");
    },
  },
});
</script>

<style lang="less" scoped>
@import '@/style/variables';

.payment-col {
  display: flex;

.trend-container {
  display: flex;
  align-items: center;
  margin-left: 8px;
}

}

.left-operation-container {
  padding: 0 0 6px 0;
  margin-bottom: 16px;

.selected-count {
  display: inline-block;
  margin-left: 8px;
  color: var(--td-text-color-secondary);
}

}

.search-input {
  width: 360px;
}

.t-button + .t-button {
  margin-left: @spacer;
}
</style>
