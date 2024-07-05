<template>
  <div>
    <t-card class="list-card-container">
      <t-row justify="space-between">
        <div class="left-operation-container">
          <t-button @click="handleAddHost"> 新建防护</t-button>
          <t-button variant="base" theme="default" @click="HandleExportExcel()"> 导出数据</t-button>
          <t-button variant="base" theme="default" @click="HandleImportExcel()"> 导入数据</t-button>

          <p v-if="!!selectedRowKeys.length" class="selected-count">已选{{ selectedRowKeys.length }}项</p>
        </div>
        <div class="right-operation-container">
          <t-form ref="form" :data="searchformData" :label-width="80" colon :style="{ marginBottom: '8px' }">

            <t-row>
              <span>网站：</span>
              <t-select v-model="searchformData.code" clearable :style="{ width: '150px' }">
                <t-option v-for="(item, index) in host_dic" :value="index" :label="item" :key="index">
                  {{ item }}
                </t-option>
              </t-select>
              <span>URL：</span>
              <t-input v-model="searchformData.url" class="search-input" placeholder="请输入" clearable>
              </t-input>
              <t-button theme="primary" :style="{ marginLeft: '8px' }" @click="getList('all')"> 查询</t-button>
            </t-row>
          </t-form>
        </div>
      </t-row>

      <div class="table-container">
        <t-alert theme="info" message="SamWaf核心功能，所有网站信息，防护功能开启等" close>
          <template #operation>
            <span @click="handleJumpOnlineUrl">主机在线文档</span>
          </template>
        </t-alert>
        <t-table :columns="columns" size="small" :data="data" :rowKey="rowKey" :verticalAlign="verticalAlign"
                 :hover="hover" :pagination="pagination" :selected-row-keys="selectedRowKeys" :loading="dataLoading"
                 @page-change="rehandlePageChange" @change="rehandleChange" @select-change="rehandleSelectChange"
                 :headerAffixedTop="true" :headerAffixProps="{ offsetTop: offsetTop, container: getContainer }">
          <template #guard_status="{ row }">
              <t-switch size="large" v-model="row.guard_status ===1" :label="['已防护', '未防护']"
                        @change="changeGuardStatus($event,row)">
              </t-switch>
          </template>
          <template #start_status="{ row }">
              <t-switch size="large" v-model="row.start_status===0" :label="['自动启动', '手工启动']"
                        @change="changeStartStatus($event,row)">
              </t-switch>
          </template>
          <template #ssl="{ row }">
            <p v-if="row.ssl === SSL_STATUS.NOT_SSL">否</p>
            <p v-if="row.ssl === SSL_STATUS.SSL">是</p>
          </template>
          <template #paymentType="{ row }">
            <p v-if="row.paymentType === CONTRACT_PAYMENT_TYPES.PAYMENT" class="payment-col">
              付款
              <trend class="dashboard-item-trend" type="up"/>
            </p>
            <p v-if="row.paymentType === CONTRACT_PAYMENT_TYPES.RECIPT" class="payment-col">
              收款
              <trend class="dashboard-item-trend" type="down"/>
            </p>
          </template>

          <template #op="slotProps">
            <!--<a class="t-button-link" @click="handleClickEdit(slotProps)">系统自带防御</a>-->
            <a class="t-button-link" v-if="slotProps.row.global_host!==1" @click="handleClickCopy(slotProps)">复制</a>
            <a class="t-button-link" v-if="slotProps.row.global_host!==1" @click="handleClickEdit(slotProps)">编辑</a>
            <a class="t-button-link" v-if="slotProps.row.global_host!==1" @click="handleClickDelete(slotProps)">删除</a>
          </template>
        </t-table>
      </div>
      <div>
        <router-view></router-view>
      </div>
    </t-card>

    <!-- 新建网站防御弹窗 -->
    <t-dialog :visible.sync="addFormVisible" :width="680" :footer="false">
      <div slot="header">
        新建网站防御
        <t-link theme="primary" :href="hostAddUrl" target="_blank">
          <link-icon slot="prefix-icon"></link-icon>
          访问SamWaf在线文档
        </t-link>
      </div>
      <div slot="body">
        <!-- 表单内容 -->
        <t-form :data="formData" ref="form" :rules="rules" @submit="onSubmit" :labelWidth="100">
          <t-tabs :defaultValue="1">
            <t-tab-panel :value="1" label="基础内容">
              <t-form-item label="网站" name="host">
                <t-tooltip class="placement top center" content="输入您需要防护的网站域名:如 www.samwaf.com" placement="top"
                           :overlay-style="{ width: '200px' }" show-arrow>
                  <t-input :style="{ width: '480px' }" v-model="formData.host" placeholder="请输入网站的网址"></t-input>
                </t-tooltip>
              </t-form-item>
              <t-form-item label="端口" name="port">
                <t-tooltip class="placement top center"
                           content="输入您需要防护的网站端口 1. http是80 https 是 443 2.如果已经安装了宝塔，Nginx，IIS等 您需要手工改动端口成非80，或者非443端口"
                           placement="top" :overlay-style="{ width: '200px' }" show-arrow>
                  <t-input-number :style="{ width: '150px' }" v-model="formData.port" placeholder="请输入网站的端口一般是80/443">
                  </t-input-number>
                </t-tooltip>
              </t-form-item>
              <t-form-item label="加密证书" name="ssl">
                <t-tooltip class="placement top center" content="如果是https需要选择加密证书，80端口不需要" placement="top"
                           :overlay-style="{ width: '200px' }" show-arrow>
                  <t-radio-group v-model="formData.ssl">
                    <t-radio value="0">非加密</t-radio>
                    <t-radio value="1">加密证书（需上传证书）</t-radio>
                  </t-radio-group>
                </t-tooltip>
              </t-form-item>
              <t-form-item label="启动状态" name="start_status">
                <t-tooltip class="placement top center" content="该功能是选择是否直接启动。" placement="top"
                           :overlay-style="{ width: '200px' }" show-arrow>
                  <t-radio-group v-model="formData.start_status">
                    <t-radio value="0">直接启动</t-radio>
                    <t-radio value="1">等待人工启动</t-radio>
                  </t-radio-group>
                </t-tooltip>
              </t-form-item>
              <t-form-item label="密钥串" name="keyfile" v-if="formData.ssl=='1'">
                <t-tooltip class="placement top center"
                           content="通常文件名：*.key 内容格式如下：-----BEGIN RSA PRIVATE KEY----- 全选复制填写进来" placement="top"
                           :overlay-style="{ width: '200px' }" show-arrow>
                  <t-textarea :style="{ width: '480px' }" v-model="formData.keyfile" placeholder="请输入内容" name="keyfile">
                  </t-textarea>
                </t-tooltip>
              </t-form-item>
              <t-form-item label="证书串" name="certfile" v-if="formData.ssl=='1'">
                <t-tooltip class="placement top center"
                           content="通常文件名：*.crt 内容格式如下：-----BEGIN CERTIFICATE----- 全选复制填写进来" placement="top"
                           :overlay-style="{ width: '200px' }" show-arrow>
                  <t-textarea :style="{ width: '480px' }" v-model="formData.certfile" placeholder="请输入内容"
                              name="certfile">
                  </t-textarea>
                </t-tooltip>
              </t-form-item>

              <!--<t-form-item label="后端域名" name="remote_host">
                <t-tooltip class="placement top center" content="后端域名通常同第一项网站域名相同（加上协议 http:// 或 https://）"
                           placement="top" :overlay-style="{ width: '200px' }" show-arrow>
                  <t-input :style="{ width: '480px' }" v-model="formData.remote_host" placeholder="请输入后端域名"></t-input>
                </t-tooltip>
              </t-form-item>-->
              <t-form-item label="后端IP" name="remote_ip">
                <t-tooltip class="placement top center" content="如SamWaf同网站在同一台服务器 填写127.0.0.1 如果是不同服务器请填写实际IP"
                           placement="top" :overlay-style="{ width: '200px' }" show-arrow>
                  <t-input :style="{ width: '480px' }" v-model="formData.remote_ip" placeholder="请输入后端IP"></t-input>
                </t-tooltip>
              </t-form-item>
              <t-form-item label="后端端口" name="remote_port">
                <t-tooltip class="placement top center"
                           content="情况1，在SamWaf和网站在同一台服务器，那么端口需要写成81等其他端口  情况2：如果不在同一台服务器，那么此处可以原来端口" placement="top"
                           :overlay-style="{ width: '200px' }" show-arrow>
                  <t-input-number :style="{ width: '150px' }" v-model="formData.remote_port"
                                  placeholder="请输入网站的端口一般是80/443">
                  </t-input-number>
                </t-tooltip>
              </t-form-item>

              <t-form-item label="备注" name="remarks">
                <t-textarea :style="{ width: '480px' }" v-model="formData.remarks" placeholder="请输入内容" name="remarks">
                </t-textarea>
              </t-form-item>
            </t-tab-panel>
            <t-tab-panel :value="2">
              <template #label>
                <file-safety-icon style="margin-right: 4px;color:red"/>
                引擎自带防护
              </template>

              <t-form-item label="Bot检测">
                <t-tooltip class="placement top center" content="检测搜索引擎是否是伪装的" placement="top"
                           :overlay-style="{ width: '200px' }" show-arrow>
                  <t-radio-group v-model="hostDefenseData.bot">
                    <t-radio value="0">关闭</t-radio>
                    <t-radio value="1">开启</t-radio>
                  </t-radio-group>
                </t-tooltip>
              </t-form-item>

              <t-form-item label="Sql注入检测">
                <t-tooltip class="placement top center" content="检测是否存在sql注入" placement="top"
                           :overlay-style="{ width: '200px' }" show-arrow>
                  <t-radio-group v-model="hostDefenseData.sqli">
                    <t-radio value="0">关闭</t-radio>
                    <t-radio value="1">开启</t-radio>
                  </t-radio-group>
                </t-tooltip>
              </t-form-item>

              <t-form-item label="XSS检测">
                <t-tooltip class="placement top center" content="检测是否存在xss攻击" placement="top"
                           :overlay-style="{ width: '200px' }" show-arrow>
                  <t-radio-group v-model="hostDefenseData.xss">
                    <t-radio value="0">关闭</t-radio>
                    <t-radio value="1">开启</t-radio>
                  </t-radio-group>
                </t-tooltip>
              </t-form-item>
              <t-form-item label="扫描工具检测">
                <t-tooltip class="placement top center" content="扫描工具检测" placement="top"
                           :overlay-style="{ width: '200px' }" show-arrow>
                  <t-radio-group v-model="hostDefenseData.scan">
                    <t-radio value="0">关闭</t-radio>
                    <t-radio value="1">开启</t-radio>
                  </t-radio-group>
                </t-tooltip>
              </t-form-item>
              <t-form-item label="RCE检测">
                <t-tooltip class="placement top center" content="RCE远程攻击检测" placement="top"
                           :overlay-style="{ width: '200px' }" show-arrow>
                  <t-radio-group v-model="hostDefenseData.rce">
                    <t-radio value="0">关闭</t-radio>
                    <t-radio value="1">开启</t-radio>
                  </t-radio-group>
                </t-tooltip>
              </t-form-item>
            </t-tab-panel>
            <t-tab-panel :value="3">
              <template #label>
                其他配置
              </template>
              <t-form-item label="日时排除URL" name="exclude_url_log">
                <t-tooltip class="placement top center" content="记录日志时排除URL开头的数据" placement="top"
                           :overlay-style="{ width: '200px' }" show-arrow>
                <t-textarea :style="{ width: '480px' }" v-model="formData.exclude_url_log" placeholder="请输入内容"
                            name="exclude_url_log">
                </t-textarea>
                </t-tooltip>
              </t-form-item>
            </t-tab-panel>
          </t-tabs>

          <t-form-item style="float: right">
            <t-button variant="outline" @click="onClickCloseBtn">取消</t-button>
            <t-button theme="primary" type="submit">确定</t-button>
          </t-form-item>
        </t-form>

      </div>
    </t-dialog>

    <!-- 编辑网站防御弹窗 -->
    <t-dialog header="编辑网站防御" :visible.sync="editFormVisible" :width="680" :footer="false">
      <div slot="body">
        <!-- 表单内容 -->
        <t-form :data="formEditData" ref="form" :rules="rules" @submit="onSubmitEdit" :labelWidth="100">
          <t-tabs :defaultValue="1">
            <t-tab-panel :value="1" label="基础内容">
              <t-form-item label="网站" name="host">
                <t-input :style="{ width: '480px' }" v-model="formEditData.host" placeholder="请输入网站的网址" disabled></t-input>
              </t-form-item>
              <t-form-item label="端口" name="port">
                <t-input-number :style="{ width: '150px' }" v-model="formEditData.port" placeholder="请输入网站的端口一般是80/443">
                </t-input-number>
              </t-form-item>
              <t-form-item label="加密证书" name="ssl">
                <t-radio-group v-model="formEditData.ssl">
                  <t-radio value="0">非加密</t-radio>
                  <t-radio value="1">加密证书（需填写证书）</t-radio>
                </t-radio-group>
              </t-form-item>
              <!--<t-form-item label="启动状态" name="start_status">
                <t-radio-group v-model="formEditData.start_status">
                  <t-radio value="0">直接启动</t-radio>
                  <t-radio value="1">等待人工启动</t-radio>
                </t-radio-group>
              </t-form-item>-->
              <t-form-item label="密钥串" name="keyfile" v-if="formEditData.ssl=='1'">
                <t-textarea :style="{ width: '480px' }" v-model="formEditData.keyfile" placeholder="请输入内容"
                            name="keyfile">
                </t-textarea>
              </t-form-item>
              <t-form-item label="证书串" name="certfile" v-if="formEditData.ssl=='1'">
                <t-textarea :style="{ width: '480px' }" v-model="formEditData.certfile" placeholder="请输入内容"
                            name="certfile">
                </t-textarea>
              </t-form-item>
              <!--<t-form-item label="后端域名" name="remote_host">
                <t-input :style="{ width: '480px' }" v-model="formEditData.remote_host" placeholder="请输入后端域名"></t-input>
              </t-form-item>-->
              <t-form-item label="后端IP" name="remote_ip">
                <t-input :style="{ width: '480px' }" v-model="formEditData.remote_ip" placeholder="请输入后端IP"></t-input>
              </t-form-item>
              <t-form-item label="后端端口" name="remote_port">
                <t-input-number :style="{ width: '150px' }" v-model="formEditData.remote_port"
                                placeholder="请输入网站的端口一般是80/443"></t-input-number>
              </t-form-item>

              <t-form-item label="备注" name="remarks">
                <t-textarea :style="{ width: '480px' }" v-model="formEditData.remarks" placeholder="请输入内容"
                            name="remarks">
                </t-textarea>
              </t-form-item>

            </t-tab-panel>
            <t-tab-panel :value="2">
              <template #label>
                <file-safety-icon style="margin-right: 4px;color:red"/>
                引擎自带防护
              </template>

              <t-form-item label="Bot检测">
                <t-tooltip class="placement top center" content="检测搜索引擎是否是伪装的" placement="top"
                           :overlay-style="{ width: '200px' }" show-arrow>
                  <t-radio-group v-model="hostDefenseData.bot">
                    <t-radio value="0">关闭</t-radio>
                    <t-radio value="1">开启</t-radio>
                  </t-radio-group>
                </t-tooltip>
              </t-form-item>

              <t-form-item label="Sql注入检测">
                <t-tooltip class="placement top center" content="检测是否存在sql注入" placement="top"
                           :overlay-style="{ width: '200px' }" show-arrow>
                  <t-radio-group v-model="hostDefenseData.sqli">
                    <t-radio value="0">关闭</t-radio>
                    <t-radio value="1">开启</t-radio>
                  </t-radio-group>
                </t-tooltip>
              </t-form-item>

              <t-form-item label="XSS检测">
                <t-tooltip class="placement top center" content="检测是否存在xss攻击" placement="top"
                           :overlay-style="{ width: '200px' }" show-arrow>
                  <t-radio-group v-model="hostDefenseData.xss">
                    <t-radio value="0">关闭</t-radio>
                    <t-radio value="1">开启</t-radio>
                  </t-radio-group>
                </t-tooltip>
              </t-form-item>
              <t-form-item label="扫描工具检测">
                <t-tooltip class="placement top center" content="扫描工具检测" placement="top"
                           :overlay-style="{ width: '200px' }" show-arrow>
                  <t-radio-group v-model="hostDefenseData.scan">
                    <t-radio value="0">关闭</t-radio>
                    <t-radio value="1">开启</t-radio>
                  </t-radio-group>
                </t-tooltip>
              </t-form-item>
              <t-form-item label="RCE检测">
                <t-tooltip class="placement top center" content="RCE远程攻击检测" placement="top"
                           :overlay-style="{ width: '200px' }" show-arrow>
                  <t-radio-group v-model="hostDefenseData.rce">
                    <t-radio value="0">关闭</t-radio>
                    <t-radio value="1">开启</t-radio>
                  </t-radio-group>
                </t-tooltip>
              </t-form-item>
            </t-tab-panel>
            <t-tab-panel :value="3">
              <template #label>
                其他配置
              </template>

              <t-form-item label="日时排除URL" name="exclude_url_log">
                <t-tooltip class="placement top center" content="记录日志时排除URL开头的数据" placement="top"
                           :overlay-style="{ width: '200px' }" show-arrow>
                  <t-textarea :style="{ width: '480px' }" v-model="formEditData.exclude_url_log" placeholder="请输入内容"
                              name="exclude_url_log">
                  </t-textarea>
                </t-tooltip>
              </t-form-item>
            </t-tab-panel>
          </t-tabs>
          <t-form-item style="float: right">
            <t-button variant="outline" @click="onClickCloseEditBtn">取消</t-button>
            <t-button theme="primary" type="submit">确定</t-button>
          </t-form-item>

        </t-form>
      </div>
    </t-dialog>

    <t-dialog header="确认删除当前所选网站?" :body="confirmBody" :visible.sync="confirmVisible" @confirm="onConfirmDelete"
              :onCancel="onCancel">
    </t-dialog>

    <t-dialog :visible.sync="ImportXlsxVisible" @confirm="ImportXlsxVisible=false">
      <t-upload :action="fileUploadUrl" :tips="tips" :headers="fileHeader" v-model="files" @fail="handleFail"
                @success="onSuccess" theme="file-input" placeholder="未选择文件"></t-upload>
    </t-dialog>

    <t-dialog header="防护状态提示" :visible.sync="guardConfirmVisible" @confirm="onGuardStatusConfirm"
              :onCancel="onGuardStatusCancel">
      <div slot="body">
        <div>防护状态【开启】，该网站进行实时防护。防护状态【关闭】，该网站会关闭实时防护。</div>
      </div>
    </t-dialog>

    <t-dialog header="启动状态提示" :visible.sync="startConfirmVisible" @confirm="onStartStatusConfirm"
              :onCancel="onStartStatusCancel">
      <div>启动状态【开启】会正常接收用户请求。 启动状态【关闭】会停止用户请求</div>
    </t-dialog>
  </div>
</template>
<script lang="ts">
import {AesDecrypt, getBaseUrl} from '@/utils/usuallytool';
import Vue from 'vue';
import {FileSafetyIcon, LinkIcon, SearchIcon} from 'tdesign-icons-vue';
import {prefix} from '@/config/global';

import {export_api} from '@/apis/common';
import {allhost, changeGuardStatus, changeStartStatus, hostlist,getHostDetail,delHost,addHost,editHost} from '@/apis/host';
import {
  CONTRACT_PAYMENT_TYPES,
  CONTRACT_STATUS,
  CONTRACT_STATUS_OPTIONS,
  CONTRACT_TYPES,
  GUARD_STATUS,
  SSL_STATUS,
  START_STATUS
} from '@/constants';

const INITIAL_DATA = {
  host: 'www.baidu.com',
  port: 80,
  remote_host: 'http://www.baidu.com',
  remote_ip: '127.0.0.1',
  remote_port: 81,
  ssl: '0',
  remote_system: "默认",
  remote_app: "默认",
  guard_status: '',
  remarks: '',
  defense_json: '{"bot":1,"sqli":1,"xss":1,"scan"1,"rce":1}',
  start_status: '0',
  exclude_url_log:'',
};
export default Vue.extend({
  name: 'ListBase',
  components: {
    SearchIcon,
    FileSafetyIcon,
    LinkIcon
  },
  data() {
    return {
      files: [],
      tips: '上传文件大小在 5M 以内',
      baseUrl: "",
      fileUploadUrl: "",
      fileHeader: {},
      addFormVisible: false,
      editFormVisible: false,
      guardVisible: false,
      confirmVisible: false,
      ImportXlsxVisible: false,
      formData: {
        ...INITIAL_DATA
      },
      formEditData: {
        ...INITIAL_DATA
      },
      //主机防御细节
      hostDefenseData: {
        bot: "1",
        sqli: "1",
        xss: "1",
        scan: "1",
        rce: "1",
      },
      rules: {
        host: [{
          required: true,
          message: '请输入网站名称',
          type: 'error'
        }],
        port: [{
          required: true,
          message: '请输入网站端口',
          type: 'error'
        }],
        remote_ip: [{
          required: true,
          message: '请输入远端IP',
          type: 'error'
        }],
        remote_port: [{
          required: true,
          message: '请输入远端端口',
          type: 'error'
        }],
      },
      remote_system_options: [{
        label: '宝塔',
        value: '1'
      },
        {
          label: '小皮面板(phpstudy)',
          value: '2'
        },
        {
          label: 'PHPnow',
          value: '3'
        },
        {
          label: '默认',
          value: '4'
        },
      ],
      remote_app_options: [{
        label: '纯网站',
        value: '1'
      },
        {
          label: 'API业务系统',
          value: '2'
        },
        {
          label: '业务加管理',
          value: '3'
        },
        {
          label: '默认',
          value: '4'
        },
      ],
      GUARD_STATUS,
      SSL_STATUS,
      START_STATUS,
      CONTRACT_STATUS,
      CONTRACT_STATUS_OPTIONS,
      CONTRACT_TYPES,
      CONTRACT_PAYMENT_TYPES,
      prefix,
      dataLoading: false,
      data: [], //列表数据信息
      detail_data: [], //加载详情信息用于编辑
      selectedRowKeys: [],
      value: 'first',
      columns: [
        {
          title: '网站',
          align: 'left',
          width: 200,
          ellipsis: true,
          colKey: 'host',
        },
        {
          title: '网站端口',
          width: 100,
          ellipsis: true,
          colKey: 'port',
        },
        {
          title: '启动状态',
          colKey: 'start_status',
          width: 100,
          cell: {
            col: 'start_status'
          }
        },
        {
          title: '防护状态',
          colKey: 'guard_status',
          width: 100,
          cell: {
            col: 'guard_status'
          }
        },
        {
          title: '加密证书',
          width: 100,
          ellipsis: true,
          colKey: 'ssl',
          cell: {
            col: 'ssl'
          }
        },
        {
          title: '备注',
          width: 200,
          ellipsis: true,
          colKey: 'remarks',
        },
        {
          title: '添加时间',
          width: 200,
          ellipsis: true,
          colKey: 'create_time',
        },

        {
          align: 'left',
          width: 200,
          colKey: 'op',
          title: '操作',
        },
      ],
      rowKey: 'code',
      tableLayout: 'auto',
      verticalAlign: 'top',
      hover: true,
      rowClassName: (rowKey: string) => `${rowKey}-class`,
      // 与pagination对齐
      pagination: {
        total: 0,
        current: 1,
        pageSize: 10
      },
      //顶部搜索
      searchformData: {
        remarks: "",
        code: ""
      },
      //索引区域
      deleteIdx: -1,
      guardStatusIdx: -1,
      startStatusIdx: -1,

      //来源页面
      sourcePage: "",
      hostAddUrl: this.samwafglobalconfig.getOnlineUrl() + '/guide/Host.html#_2-新增可被防火墙保护的网站',
      //主机字典
      host_dic: {},

      //弹窗确认
      guardConfirmVisible: false,//更改防护状态的弹窗控制
      startConfirmVisible: false,//更改启动状态的弹窗控制
    };
  },
  computed: {
    confirmBody() {
      if (this.deleteIdx > -1) {
        const {
          host
        } = this.data?.[this.deleteIdx];
        return `删除后，${host}的所有网站信息和规则将被清空，且无法恢复`;
      }
      return '';
    },
    offsetTop() {
      return this.$store.state.setting.isUseTabsRouter ? 48 : 0;
    },
  },
  mounted() {
    this.loadHostList()
    this.getList("")
    this.baseUrl = getBaseUrl()
    this.fileUploadUrl = this.baseUrl + "/import"
    this.fileHeader['X-Token'] = localStorage.getItem("access_token") ? localStorage.getItem("access_token") : "" //此处换成自己获取回来的token，通常存在在cookie或者store里面
    console.log(this.baseUrl)
    if (this.$route.query != null && this.$route.query.sourcePage != "") {
      this.sourcePage = this.$route.query.sourcePage;
      if (this.sourcePage == "HomeFrist") {
        this.addFormVisible = true
      }
    }
  },

  methods: {
    loadHostList() {
      let that = this;
      allhost("").then((res) => {
        let resdata = res
        console.log(resdata)
        if (resdata.code === 0) {
          let host_options = resdata.data;
          for (let i = 0; i < host_options.length; i++) {
            that.host_dic[host_options[i].value] = host_options[i].label
          }
        }
      })
        .catch((e: Error) => {
          console.log(e);
        })
    },
    getList(keyword) {
      let that = this
      hostlist({
        pageSize: that.pagination.pageSize,
        pageIndex: that.pagination.current,
        ...that.searchformData
      }).then((res) => {
        let resdata = res
        console.log(resdata)
        if (resdata.code === 0) {

          //const { list = [] } = resdata.data.list;

          this.data = resdata.data.list;
          this.data_attach = []
          for (var i = 0; i < this.data.length; i++) {
            this.data[i].guard_status_visiable = false //可扩充
          }
          console.log('getList', this.data)
          this.pagination = {
            ...this.pagination,
            total: resdata.data.total,
          };
        }
      })
        .catch((e: Error) => {
          console.log(e);
        })
        .finally(() => {
          this.dataLoading = false;
        });
      this.dataLoading = true;
    },
    getContainer() {
      return document.querySelector('.tdesign-starter-layout');
    },
    rehandlePageChange(curr, pageInfo) {
      console.log('分页变化', curr, pageInfo);
      this.pagination.current = curr.current
      if (this.pagination.pageSize != curr.pageSize) {
        this.pagination.current = 1
        this.pagination.pageSize = curr.pageSize
      }
      this.getList("")
    },
    rehandleSelectChange(selectedRowKeys: number[]) {
      this.selectedRowKeys = selectedRowKeys;
    },
    rehandleChange(changeParams, triggerAndData) {
      console.log('统一Change', changeParams, triggerAndData);
    },
    handleClickDetail(e) {
      console.log(e)
      const {
        code
      } = e.row
      console.log('hostlist', code)
      this.$router.push({
        path: '/waf-host/wafhostdetail',
        query: {
          code: code,
        },
      },);
    },
    handleClickCopy(e) {

      console.log(e)
      const {
        code, global_host
      } = e.row
      if (global_host === 1) {
        this.$message.warning("全局网站不能操作");
        return
      }
      console.log(code)
      this.addFormVisible = true
      let that = this
      getHostDetail({
        CODE: code,
      })
        .then((res) => {
          let resdata = res
          console.log(resdata)
          if (resdata.code === 0) {
            let detail_data_tmp = resdata.data;
            detail_data_tmp.ssl = detail_data_tmp.ssl.toString()
            detail_data_tmp.start_status = detail_data_tmp.start_status.toString()
            that.formData= {
              ...detail_data_tmp
            }
            that.formData.code = null
            let defenseJson = JSON.parse(detail_data_tmp.defense_json)
            that.hostDefenseData.bot = defenseJson.bot.toString()
            that.hostDefenseData.sqli = defenseJson.sqli.toString()
            that.hostDefenseData.xss = defenseJson.xss.toString()
            that.hostDefenseData.scan = defenseJson.scan.toString()
            that.hostDefenseData.rce = defenseJson.rce.toString()
          }
        })
        .catch((e: Error) => {
          console.log(e);
        })
        .finally(() => {
        });
    },
    handleClickEdit(e) {

      console.log(e)
      const {
        code, global_host
      } = e.row
      if (global_host === 1) {
        this.$message.warning("全局网站只能配置保护状态");
        return
      }
      console.log(code)
      this.editFormVisible = true
      this.getDetail(code)
    },
    handleAddHost() {
      //添加host
      this.addFormVisible = true
    },
    onSubmit({
               result,
               firstError
             }): void {
      let that = this
      if (!firstError) {

        let postdata = {
          ...that.formData
        }
        postdata.host = postdata.host.toLowerCase();
        if (postdata.host.indexOf("http://") >=0 || postdata.host.indexOf("https://") >=0) {
          that.$message.warning("主机请不要填写http和https 直接写域名即可");
           return
        }
        postdata.remote_host = "http://" + postdata.host
        postdata['ssl'] = Number(postdata['ssl'])
        postdata['start_status'] = Number(postdata['start_status'])
        let defenseData = {
          bot: parseInt(this.hostDefenseData.bot),
          sqli: parseInt(this.hostDefenseData.sqli),
          xss: parseInt(this.hostDefenseData.xss),
          scan: parseInt(this.hostDefenseData.scan),
          rce: parseInt(this.hostDefenseData.rce),
        }
        postdata['defense_json'] = JSON.stringify(defenseData)
        addHost( {
            ...postdata
          })
          .then((res) => {
            let resdata = res
            console.log(resdata)
            if (resdata.code === 0) {
              that.$message.success(resdata.msg);
              that.addFormVisible = false;
              that.pagination.current = 1

              that.formData = {
                host: 'www.baidu.com',
                port: 80,
                remote_host: 'http://www.baidu.com',
                remote_ip: '127.0.0.1',
                remote_port: 81,
                ssl: '0',
                remote_system: "默认",
                remote_app: "默认",
                guard_status: '',
                remarks: '',
                defense_json: '{"bot":1,"sqli":1,"xss":1,"scan"1,"rce":1}',
                start_status: '0',
              };
              that.getList("")
            } else {
              that.$message.warning(resdata.msg);
            }
          })
          .catch((e: Error) => {
            console.log(e);
          })
          .finally(() => {
          });
      } else {
        console.log('Errors: ', result);
        that.$message.warning(firstError);
      }
    },
    onSubmitEdit({
                   result,
                   firstError
                 }): void {
      let that = this
      if (!firstError) {

        let postdata = {
          ...that.formEditData
        }

        postdata['ssl'] = Number(postdata['ssl'])
        postdata['start_status'] = Number(postdata['start_status'])
        let defenseData = {
          bot: parseInt(this.hostDefenseData.bot),
          sqli: parseInt(this.hostDefenseData.sqli),
          xss: parseInt(this.hostDefenseData.xss),
          scan: parseInt(this.hostDefenseData.scan),
          rce: parseInt(this.hostDefenseData.rce),
        }
        postdata['defense_json'] = JSON.stringify(defenseData)
        console.log(postdata)
        editHost( {
            ...postdata
          })
          .then((res) => {
            let resdata = res
            console.log(resdata)
            if (resdata.code === 0) {
              that.$message.success(resdata.msg);
              that.editFormVisible = false;
              that.pagination.current = 1
              that.getList("")
            } else {
              that.$message.warning(resdata.msg);
            }
          })
          .catch((e: Error) => {
            console.log(e);
          })
          .finally(() => {
          });
      } else {
        console.log('Errors: ', result);
        that.$message.warning(firstError);
      }
    },
    onClickCloseBtn(): void {
      this.addFormVisible = false;
      this.formData = {};
      this.hostDefenseData = {
        bot: "1",
        sqli: "1",
        xss: "1",
        scan: "1",
        rce: "1",
      }
    },
    onClickCloseEditBtn(): void {
      this.editFormVisible = false;
      this.formEditData = {};
      this.hostDefenseData = {
        bot: "1",
        sqli: "1",
        xss: "1",
        scan: "1",
        rce: "1",
      }
    },
    handleClickDelete(row) {
      const {
        code, global_host
      } = row.row
      if (global_host === 1) {
        this.$message.warning("全局网站只能配置保护状态");
        //return
      }
      console.log(row)
      this.deleteIdx = row.rowIndex;
      this.confirmVisible = true;
    },
    onConfirmDelete() {
      this.confirmVisible = false;
      console.log('delete', this.data)
      console.log('delete', this.data[this.deleteIdx])
      let {
        code
      } = this.data[this.deleteIdx]
      let that = this
      delHost({
            CODE: code,
          })
        .then((res) => {
          let resdata = res
          console.log(resdata)
          if (resdata.code === 0) {

            that.pagination.current = 1
            that.getList("")
            that.$message.success(resdata.msg);
          } else {
            that.$message.warning(resdata.msg);
          }
        })
        .catch((e: Error) => {
          console.log(e);
        })
        .finally(() => {
        });


      this.resetIdx();
    },
    onCancel() {
      this.resetIdx();
    },
    resetIdx() {
      this.deleteIdx = -1;
    },
    getDetail(id) {
      let that = this
      getHostDetail({
            CODE: id,
          })
        .then((res) => {
          let resdata = res
          console.log(resdata)
          if (resdata.code === 0) {
            that.detail_data = resdata.data;
            that.detail_data.ssl = that.detail_data.ssl.toString()
            that.detail_data.start_status = that.detail_data.start_status.toString()
            that.formEditData = {
              ...that.detail_data
            }
            let defenseJson = JSON.parse(that.detail_data.defense_json)
            that.hostDefenseData.bot = defenseJson.bot.toString()
            that.hostDefenseData.sqli = defenseJson.sqli.toString()
            that.hostDefenseData.xss = defenseJson.xss.toString()
            that.hostDefenseData.scan = defenseJson.scan.toString()
            that.hostDefenseData.rce = defenseJson.rce.toString()
            console.log(that.hostDefenseData)
            console.log(that.formEditData)
          }
        })
        .catch((e: Error) => {
          console.log(e);
        })
        .finally(() => {
        });
    },
    /**
     * 导出Excel数据
     */
    HandleExportExcel() {
      let that = this
      //window.open('https:\\www.baidu.com','_blank')
      //
      export_api({table_name: "hosts"}).then((res) => {
        let resdata = res
        console.log(resdata)
        let blob = new Blob([res], {type: "application/force-download"}) // Blob 对象表示一个不可变、原始数据的类文件对象
        console.log(blob);
        let fileReader = new FileReader()   // FileReader 对象允许Web应用程序异步读取存储在用户计算机上的文件的内容
        fileReader.readAsDataURL(blob)
        //开始读取指定的Blob中的内容。一旦完成，result属性中将包含一个data: URL格式的Base64字符串以表示所读取文件的内容
        fileReader.onload = (e) => {
          let a = document.createElement('a')
          a.download = `hosts.xlsx`
          a.href = e.target.result
          document.body.appendChild(a)
          a.click()
          document.body.removeChild(a)
        }
      })
        .catch((e: Error) => {
          console.log(e);
        })
    },
    /**
     * 导入Excel数据
     */
    HandleImportExcel() {
      this.ImportXlsxVisible = true
      this.tips = ""
      this.files= []
    },
    changeGuardStatus(e, row) {

      console.log(e, row)
      let {code} = row
      let rowIndex = this.data.findIndex(function (value, index, arr) {
        console.log("findIndex", value, index, arr)
        return value['code'] == code
      })
      console.log("rowIndex", rowIndex)
      this.guardStatusIdx = rowIndex
      console.log(e)
      this.guardConfirmVisible = true
    },
    changeStartStatus(e, row) {

      console.log(e, row)
      let {code} = row
      let rowIndex = this.data.findIndex(function (value, index, arr) {
        console.log("findIndex", value, index, arr)
        return value['code'] == code
      })
      console.log("rowIndex", rowIndex)
      this.startStatusIdx = rowIndex
      console.log(e)
      this.startConfirmVisible = true
    },
    handleFail({file}) {
      this.$message.error(`文件 ${file.name} 上传失败`);
    },
    onSuccess(e) {

      let data = JSON.parse(AesDecrypt(e.response.data))
      console.log('host upload', data)
      let lastMsg = "成功数量 :" + data.SuccessInt;
      if (data.FailInt > 0) {
        lastMsg += "失败数量 :" + data.FailInt + " 错误原因:" + data.Msg;
      }

      this.tips = lastMsg;
      this.getList("")
    },
    //跳转界面
    handleJumpOnlineUrl() {
      window.open(this.samwafglobalconfig.getOnlineUrl() + "/guide/Host.html");
    },
    //更改teatarea
    updateTextareaEdit(event) {
      //this.formEditData = event.target.value;

    },
    //更改teatarea
    updateTextareaAdd(event) {
      //this.formAddData = event.target.value;

    },

    //弹窗部分代码
    onGuardStatusConfirm(){

      let that = this
      console.log("this.guardStatusIdx", this.guardStatusIdx)
      if (this.guardStatusIdx == -1) {
        return
      }

      console.log("this.data", this.data[that.guardStatusIdx])
      let {
        code, guard_status
      } = this.data[this.guardStatusIdx]
      changeGuardStatus({
        CODE: code,
        GUARD_STATUS: guard_status == 1 ? 0 : 1,
      })
        .then((res) => {
          let resdata = res
          console.log(resdata)
          if (resdata.code === 0) {
            that.getList("")
            that.$message.success(resdata.msg)
            that.guardStatusIdx = -1;
            this.guardConfirmVisible = false
          } else {
            that.$message.warning(resdata.msg);
            this.guardStatusIdx = -1;
            this.guardConfirmVisible = false

          }
        })
        .catch((e: Error) => {
          console.log(e);
        })
        .finally(() => {
        });
    },
    onGuardStatusCancel(){
      this.guardConfirmVisible = false
      this.guardStatusIdx = -1;
    },
    onStartStatusConfirm() {
      let that = this
      this.startConfirmVisible = false

      let {
        code, start_status
      } = this.data[this.startStatusIdx]
      console.log("code,start_status", code, start_status)
      changeStartStatus({
          CODE: code,
          START_STATUS: start_status === 1 ? 0 : 1,
        }
      )
        .then((res) => {
          let resdata = res
          console.log(resdata)
          if (resdata.code === 0) {
            that.getList("")
            that.$message.success(resdata.msg)
            this.startStatusIdx = -1;
          } else {
            that.$message.warning(resdata.msg);
            this.startStatusIdx = -1;
          }
        })
        .catch((e: Error) => {
          console.log(e);
        })
        .finally(() => {
        });
    },
    onStartStatusCancel() {
      this.startConfirmVisible = false
      this.startStatusIdx = -1;
    },
    //end method
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
