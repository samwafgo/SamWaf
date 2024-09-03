<template>
  <div>
    <t-card class="list-card-container">
      <t-row justify="space-between">
        <div class="left-operation-container">
          <t-button @click="handleAddHost"> {{ $t('page.host.new_protection') }}</t-button>
          <t-button variant="base" theme="default" @click="HandleExportExcel()"> {{ $t('page.host.export_data') }}</t-button>
          <t-button variant="base" theme="default" @click="HandleImportExcel()"> {{ $t('page.host.import_data') }}</t-button>

        </div>
        <div class="right-operation-container">
          <t-form ref="form" :data="searchformData" :label-width="80" colon :style="{ marginBottom: '8px' }">

            <t-row>
              <span>{{ $t('page.host.website') }}</span>
              <t-select v-model="searchformData.code" clearable :style="{ width: '150px' }">
                <t-option v-for="(item, index) in host_dic" :value="index" :label="item" :key="index">
                  {{ item }}
                </t-option>
              </t-select>
              <span>URL：</span>
              <t-input v-model="searchformData.url" class="search-input" :placeholder="$t('common.placeholder')" clearable>
              </t-input>
              <t-button theme="primary" :style="{ marginLeft: '8px' }" @click="getList('all')"> {{ $t('common.search') }}</t-button>
            </t-row>
          </t-form>
        </div>
      </t-row>

      <div class="table-container">
        <t-alert theme="info" :message="$t('page.host.core_features')" close>
          <template #operation>
            <span @click="handleJumpOnlineUrl">{{ $t('common.online_document') }}</span>
          </template>
        </t-alert>
        <t-table :columns="columns" size="small" :data="data" :rowKey="rowKey" :verticalAlign="verticalAlign"
                 :hover="hover" :pagination="pagination" :selected-row-keys="selectedRowKeys" :loading="dataLoading"
                 @page-change="rehandlePageChange" @change="rehandleChange" @select-change="rehandleSelectChange"
                 :headerAffixedTop="true" :headerAffixProps="{ offsetTop: offsetTop, container: getContainer }">
          <template #guard_status="{ row }">
              <t-switch size="large" v-model="row.guard_status ===1" :label="[$t('page.host.guard_status_on'), $t('page.host.guard_status_off')]"
                   @change="changeGuardStatus($event,row)">
              </t-switch>
          </template>
          <template #start_status="{ row }">
              <t-switch size="large" v-model="row.start_status===0" :label="[$t('page.host.auto_start_on'), $t('page.host.auto_start_off')]"
                        @change="changeStartStatus($event,row)">
              </t-switch>
          </template>
          <template #ssl="{ row }">
            <p v-if="row.ssl === SSL_STATUS.NOT_SSL">{{ $t('page.host.ssl_no') }}</p>
            <p v-if="row.ssl === SSL_STATUS.SSL">{{ $t('page.host.ssl_yes') }}</p>
          </template>
          <template #op="slotProps">
            <a class="t-button-link" v-if="slotProps.row.global_host!==1" @click="handleClickCopy(slotProps)">{{ $t('common.copy') }}</a>
            <a class="t-button-link" v-if="slotProps.row.global_host!==1" @click="handleClickEdit(slotProps)">{{ $t('common.edit') }}</a>
            <a class="t-button-link" v-if="slotProps.row.global_host!==1" @click="handleClickDelete(slotProps)">{{ $t('common.delete') }}</a>
          </template>
        </t-table>
      </div>
      <div>
        <router-view></router-view>
      </div>
    </t-card>

    <!-- New WebSite Dialog -->
    <t-dialog :visible.sync="addFormVisible" :width="680" :footer="false">
      <div slot="header">
        {{ $t('page.host.website_protection') }}
        <t-link theme="primary" :href="hostAddUrl" target="_blank">
          <link-icon slot="prefix-icon"></link-icon>
          {{ $t('common.online_document') }}
        </t-link>
      </div>
      <div slot="body">
        <t-form :data="formData" ref="form" :rules="rules" @submit="onSubmit" :labelWidth="160">
          <t-tabs :defaultValue="1">
            <t-tab-panel :value="1" :label="$t('page.host.tab_base')">
              <t-form-item :label="$t('page.host.website')" name="host">
                <t-tooltip class="placement top center" :content="$t('page.host.host_tips')" placement="top"
                           :overlay-style="{ width: '200px' }" show-arrow>
                  <t-input :style="{ width: '480px' }" v-model="formData.host" :placeholder="$t('common.placeholder')"></t-input>
                </t-tooltip>
              </t-form-item>
              <t-form-item :label="$t('page.host.port')" name="port">
                <t-tooltip class="placement top center"
                           :content="$t('page.host.port_tips')"
                           placement="top" :overlay-style="{ width: '200px' }" show-arrow>
                  <t-input-number :style="{ width: '150px' }" v-model="formData.port" :placeholder="$t('page.host.port_placeholder')">
                  </t-input-number>
                </t-tooltip>
              </t-form-item>
              <t-form-item :label="$t('page.host.ssl')" name="ssl">
                <t-tooltip class="placement top center" :content="$t('page.host.ssl_tips')" placement="top"
                           :overlay-style="{ width: '200px' }" show-arrow>
                  <t-radio-group v-model="formData.ssl">
                    <t-radio value="0">{{ $t('page.host.ssl_option_no') }}</t-radio>
                    <t-radio value="1">{{ $t('page.host.ssl_option_yes') }}</t-radio>
                  </t-radio-group>
                </t-tooltip>
              </t-form-item>
              <t-form-item :label="$t('page.host.start_status')" name="start_status">
                <t-tooltip class="placement top center" :content="$t('page.host.start_status_content')" placement="top"
                           :overlay-style="{ width: '200px' }" show-arrow>
                  <t-radio-group v-model="formData.start_status">
                    <t-radio value="0">{{ $t('page.host.auto_start_on') }}</t-radio>
                    <t-radio value="1">{{ $t('page.host.auto_start_off') }}</t-radio>
                  </t-radio-group>
                </t-tooltip>
              </t-form-item>
              <t-form-item :label="$t('page.host.keyfile')" name="keyfile" v-if="formData.ssl=='1'">
                <t-tooltip class="placement top center"
                           :content="$t('page.host.keyfile_content')" placement="top"
                           :overlay-style="{ width: '200px' }" show-arrow>
                  <t-textarea :style="{ width: '480px' }" v-model="formData.keyfile" :placeholder="$t('common.placeholder')" name="keyfile">
                  </t-textarea>
                </t-tooltip>
              </t-form-item>
              <t-form-item :label="$t('page.host.certfile')" name="certfile" v-if="formData.ssl=='1'">
                <t-tooltip class="placement top center"
                           :content="$t('page.host.certfile_content')" placement="top"
                           :overlay-style="{ width: '200px' }" show-arrow>
                  <t-textarea :style="{ width: '480px' }" v-model="formData.certfile" :placeholder="$t('common.placeholder')"
                              name="certfile">
                  </t-textarea>
                </t-tooltip>
              </t-form-item>
              <t-form-item :label="$t('page.host.remote_ip')" name="remote_ip">
                <t-tooltip class="placement top center" :content="$t('page.host.remote_ip_content')"
                           placement="top" :overlay-style="{ width: '200px' }" show-arrow>
                  <t-input :style="{ width: '480px' }" v-model="formData.remote_ip" :placeholder="$t('common.placeholder')+$t('page.host.remote_ip')"></t-input>
                </t-tooltip>
              </t-form-item>
              <t-form-item :label="$t('page.host.remote_port')"  name="remote_port">
                <t-tooltip class="placement top center"
                           :content="$t('page.host.remote_port_content')" placement="top"
                           :overlay-style="{ width: '200px' }" show-arrow>
                  <t-input-number :style="{ width: '150px' }" v-model="formData.remote_port"
                                  :placeholder="$t('page.host.port_placeholder')">
                  </t-input-number>
                </t-tooltip>
              </t-form-item>

              <t-form-item :label="$t('common.remarks')" name="remarks">
                <t-textarea :style="{ width: '480px' }" v-model="formData.remarks" :placeholder="$t('common.placeholder_content')" name="remarks">
                </t-textarea>
              </t-form-item>
            </t-tab-panel>
            <t-tab-panel :value="2">
              <template #label>
                <file-safety-icon style="margin-right: 4px;color:red"/>
                {{$t('page.host.tab_engine')}}
              </template>

              <t-form-item :label="$t('page.host.bot_detection')">
                <t-tooltip class="placement top center" :content="$t('page.host.bot_detection_tips')" placement="top"
                           :overlay-style="{ width: '200px' }" show-arrow>
                  <t-radio-group v-model="hostDefenseData.bot">
                    <t-radio value="0">{{$t('common.off')}}</t-radio>
                    <t-radio value="1">{{$t('common.on')}}</t-radio>
                  </t-radio-group>
                </t-tooltip>
              </t-form-item>

              <t-form-item :label="$t('page.host.sql_injection_detection')">
                <t-tooltip class="placement top center" :content="$t('page.host.sql_injection_detection_tips')" placement="top"
                           :overlay-style="{ width: '200px' }" show-arrow>
                  <t-radio-group v-model="hostDefenseData.sqli">
                    <t-radio value="0">{{$t('common.off')}}</t-radio>
                    <t-radio value="1">{{$t('common.on')}}</t-radio>
                  </t-radio-group>
                </t-tooltip>
              </t-form-item>

              <t-form-item :label="$t('page.host.xss_detection')">
                <t-tooltip class="placement top center" :content="$t('page.host.xss_detection_tips')" placement="top"
                           :overlay-style="{ width: '200px' }" show-arrow>
                  <t-radio-group v-model="hostDefenseData.xss">
                    <t-radio value="0">{{$t('common.off')}}</t-radio>
                    <t-radio value="1">{{$t('common.on')}}</t-radio>
                  </t-radio-group>
                </t-tooltip>
              </t-form-item>
              <t-form-item :label="$t('page.host.scan_detection')">
                <t-tooltip class="placement top center" :content="$t('page.host.scan_detection_tips')" placement="top"
                           :overlay-style="{ width: '200px' }" show-arrow>
                  <t-radio-group v-model="hostDefenseData.scan">
                    <t-radio value="0">{{$t('common.off')}}</t-radio>
                    <t-radio value="1">{{$t('common.on')}}</t-radio>
                  </t-radio-group>
                </t-tooltip>
              </t-form-item>
              <t-form-item :label="$t('page.host.rce_detection')">
                <t-tooltip class="placement top center" :content="$t('page.host.rce_detection_tips')" placement="top"
                           :overlay-style="{ width: '200px' }" show-arrow>
                  <t-radio-group v-model="hostDefenseData.rce">
                    <t-radio value="0">{{$t('common.off')}}</t-radio>
                    <t-radio value="1">{{$t('common.on')}}</t-radio>
                  </t-radio-group>
                </t-tooltip>
              </t-form-item>
            </t-tab-panel>
            <t-tab-panel :value="3">
              <template #label>
                {{$t('page.host.tab_other')}}
              </template>
              <t-form-item :label="$t('page.host.exclude_url_log')" name="exclude_url_log">
                <t-tooltip class="placement top center" :content="$t('page.host.exclude_url_log_tips')" placement="top"
                           :overlay-style="{ width: '200px' }" show-arrow>
                <t-textarea :style="{ width: '480px' }" v-model="formData.exclude_url_log" :placeholder="$t('common.placeholder')"
                            name="exclude_url_log">
                </t-textarea>
                </t-tooltip>
              </t-form-item>
            </t-tab-panel>
          </t-tabs>

          <t-form-item style="float: right;margin-top:5px">
            <t-button variant="outline" @click="onClickCloseBtn">{{ $t('common.close') }}</t-button>
            <t-button theme="primary" type="submit">{{ $t('common.confirm') }}</t-button>
          </t-form-item>
        </t-form>

      </div>
    </t-dialog>

    <!-- Edit WebSite Dialog -->
    <t-dialog :header="$t('common.edit')" :visible.sync="editFormVisible" :width="680" :footer="false">
      <div slot="body">
        <t-form :data="formEditData" ref="form" :rules="rules" @submit="onSubmitEdit" :labelWidth="160">
          <t-tabs :defaultValue="1">
            <t-tab-panel :value="1" :label="$t('page.host.tab_base')">
              <t-form-item :label="$t('page.host.website')" name="host">
                <t-input :style="{ width: '480px' }" v-model="formEditData.host" :content="$t('page.host.host_tips')" disabled></t-input>
              </t-form-item>
              <t-form-item :label="$t('page.host.port')" name="port">
                <t-input-number :style="{ width: '150px' }" v-model="formEditData.port" :content="$t('page.host.port_tips')">
                </t-input-number>
              </t-form-item>
              <t-form-item :label="$t('page.host.ssl')" name="ssl">
                <t-radio-group v-model="formEditData.ssl">
                  <t-radio value="0">{{ $t('page.host.ssl_option_no') }}</t-radio>
                  <t-radio value="1">{{ $t('page.host.ssl_option_yes') }}</t-radio>
                </t-radio-group>
              </t-form-item>
              <t-form-item :label="$t('page.host.keyfile')" name="keyfile" v-if="formEditData.ssl=='1'">
                <t-textarea :style="{ width: '480px' }" v-model="formEditData.keyfile" :placeholder="$t('common.placeholder')"
                            name="keyfile">
                </t-textarea>
              </t-form-item>
              <t-form-item :label="$t('page.host.certfile')" name="certfile" v-if="formEditData.ssl=='1'">
                <t-textarea :style="{ width: '480px' }" v-model="formEditData.certfile" :placeholder="$t('common.placeholder')"
                            name="certfile">
                </t-textarea>
              </t-form-item>
              <t-form-item :label="$t('page.host.remote_ip')" name="remote_ip">
                <t-input :style="{ width: '480px' }" v-model="formEditData.remote_ip" :placeholder="$t('common.placeholder')+$t('page.host.remote_ip')"></t-input>
              </t-form-item>
              <t-form-item :label="$t('page.host.remote_port')" name="remote_port">
                <t-input-number :style="{ width: '150px' }" v-model="formEditData.remote_port"
                                :placeholder="$t('page.host.port_placeholder')"></t-input-number>
              </t-form-item>

              <t-form-item  :label="$t('common.remarks')"  name="remarks">
                <t-textarea :style="{ width: '480px' }" v-model="formEditData.remarks" :placeholder="$t('common.placeholder_content')"
                            name="remarks">
                </t-textarea>
              </t-form-item>

            </t-tab-panel>
            <t-tab-panel :value="2">
              <template #label>
                <file-safety-icon style="margin-right: 4px;color:red"/>
                {{$t('page.host.tab_engine')}}
              </template>

              <t-form-item :label="$t('page.host.bot_detection')">
                <t-tooltip class="placement top center" :content="$t('page.host.bot_detection_tips')" placement="top"
                           :overlay-style="{ width: '200px' }" show-arrow>
                  <t-radio-group v-model="hostDefenseData.bot">
                    <t-radio value="0">{{$t('common.off')}}</t-radio>
                    <t-radio value="1">{{$t('common.on')}}</t-radio>
                  </t-radio-group>
                </t-tooltip>
              </t-form-item>

              <t-form-item :label="$t('page.host.sql_injection_detection')">
                <t-tooltip class="placement top center" :content="$t('page.host.sql_injection_detection_tips')" placement="top"
                           :overlay-style="{ width: '200px' }" show-arrow>
                  <t-radio-group v-model="hostDefenseData.sqli">
                    <t-radio value="0">{{$t('common.off')}}</t-radio>
                    <t-radio value="1">{{$t('common.on')}}</t-radio>
                  </t-radio-group>
                </t-tooltip>
              </t-form-item>

              <t-form-item :label="$t('page.host.xss_detection')">
                <t-tooltip class="placement top center" :content="$t('page.host.xss_detection_tips')" placement="top"
                           :overlay-style="{ width: '200px' }" show-arrow>
                  <t-radio-group v-model="hostDefenseData.xss">
                    <t-radio value="0">{{$t('common.off')}}</t-radio>
                    <t-radio value="1">{{$t('common.on')}}</t-radio>
                  </t-radio-group>
                </t-tooltip>
              </t-form-item>
              <t-form-item :label="$t('page.host.scan_detection')">
                <t-tooltip class="placement top center" :content="$t('page.host.scan_detection_tips')" placement="top"
                           :overlay-style="{ width: '200px' }" show-arrow>
                  <t-radio-group v-model="hostDefenseData.scan">
                    <t-radio value="0">{{$t('common.off')}}</t-radio>
                    <t-radio value="1">{{$t('common.on')}}</t-radio>
                  </t-radio-group>
                </t-tooltip>
              </t-form-item>
              <t-form-item :label="$t('page.host.rce_detection')">
                <t-tooltip class="placement top center" :content="$t('page.host.rce_detection_tips')" placement="top"
                           :overlay-style="{ width: '200px' }" show-arrow>
                  <t-radio-group v-model="hostDefenseData.rce">
                    <t-radio value="0">{{$t('common.off')}}</t-radio>
                    <t-radio value="1">{{$t('common.on')}}</t-radio>
                  </t-radio-group>
                </t-tooltip>
              </t-form-item>
            </t-tab-panel>
            <t-tab-panel :value="3">
              <template #label>
                {{$t('page.host.tab_other')}}
              </template>

              <t-form-item :label="$t('page.host.exclude_url_log')" name="exclude_url_log">
                <t-tooltip class="placement top center" :content="$t('page.host.exclude_url_log_tips')" placement="top"
                           :overlay-style="{ width: '200px' }" show-arrow>
                  <t-textarea :style="{ width: '480px' }" v-model="formEditData.exclude_url_log" :placeholder="$t('common.placeholder')"
                              name="exclude_url_log">
                  </t-textarea>
                </t-tooltip>
              </t-form-item>
            </t-tab-panel>
          </t-tabs>
          <t-form-item style="float: right;margin-top:5px">
            <t-button variant="outline" @click="onClickCloseEditBtn">{{ $t('common.close') }}</t-button>
            <t-button theme="primary" type="submit">{{ $t('common.confirm') }}</t-button>
          </t-form-item>

        </t-form>
      </div>
    </t-dialog>

    <t-dialog :header="$t('common.confirm_delete')" :body="confirmBody" :visible.sync="confirmVisible" @confirm="onConfirmDelete"
              :onCancel="onCancel">
    </t-dialog>

    <t-dialog :visible.sync="ImportXlsxVisible" @confirm="ImportXlsxVisible=false">
      <t-upload :action="fileUploadUrl" :tips="tips" :headers="fileHeader" v-model="files" @fail="handleFail"
                @success="onSuccess" theme="file-input" :placeholder="$t('page.host.upload_tips')"></t-upload>
    </t-dialog>

    <t-dialog :header="$t('page.host.guard_status_confirm')" :visible.sync="guardConfirmVisible" @confirm="onGuardStatusConfirm"
              :onCancel="onGuardStatusCancel">
      <div slot="body">
        <div>{{$t('page.host.guard_status_confirm_content')}}</div>
      </div>
    </t-dialog>

    <t-dialog :header="$t('page.host.start_status_confirm')" :visible.sync="startConfirmVisible" @confirm="onStartStatusConfirm"
              :onCancel="onStartStatusCancel">
      <div>{{$t('page.host.start_status_confirm_content')}}</div>
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
      tips: this.$t('page.host.upload_file_limit_size'),
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
          message: this.$t('common.placeholder'+this.$t('page.host.host')),
          type: 'error'
        }],
        port: [{
          required: true,
          message: this.$t('common.placeholder'+this.$t('page.host.port')),
          type: 'error'
        }],
        remote_ip: [{
          required: true,
          message: this.$t('common.placeholder'+this.$t('page.host.remote_ip')),
          type: 'error'
        }],
        remote_port: [{
          required: true,
          message: this.$t('common.placeholder'+this.$t('page.host.remote_port')),
          type: 'error'
        }],
      },
      remote_system_options: [{
        label: this.$t('page.host.back_system_type_baota'),
        value: '1'
      },
        {
          label: this.$t('page.host.back_system_type_phpstudy'),
          value: '2'
        },
        {
          label: this.$t('page.host.back_system_type_phpnow'),
          value: '3'
        },
        {
          label: this.$t('page.host.back_system_type_default'),
          value: '4'
        },
      ],
      remote_app_options: [{
        label: this.$t('page.host.back_system_biz_website'),
        value: '1'
      },
        {
          label: this.$t('page.host.back_system_biz_api'),
          value: '2'
        },
        {
          label: this.$t('page.host.back_system_biz_mange'),
          value: '3'
        },
        {
          label: this.$t('page.host.back_system_biz_default'),
          value: '4'
        },
      ],
      GUARD_STATUS,
      SSL_STATUS,
      START_STATUS,
      prefix,
      dataLoading: false,
      data: [], //列表数据信息
      detail_data: [], //加载详情信息用于编辑
      selectedRowKeys: [],
      value: 'first',
      columns: [
        {
          title: this.$t('page.host.host'),
          align: 'left',
          width: 200,
          ellipsis: true,
          colKey: 'host',
        },
        {
          title: this.$t('page.host.port'),
          width: 100,
          ellipsis: true,
          colKey: 'port',
        },
        {
          title: this.$t('page.host.start_status'),
          colKey: 'start_status',
          width: 100,
          cell: {
            col: 'start_status'
          }
        },
        {
          title: this.$t('page.host.guard_status'),
          colKey: 'guard_status',
          width: 100,
          cell: {
            col: 'guard_status'
          }
        },
        {
          title:this.$t('page.host.ssl'),
          width: 100,
          ellipsis: true,
          colKey: 'ssl',
          cell: {
            col: 'ssl'
          }
        },
        {
          title: this.$t('common.remarks'),
          width: 200,
          ellipsis: true,
          colKey: 'remarks',
        },
        {
          title: this.$t('common.create_time'),
          width: 200,
          ellipsis: true,
          colKey: 'create_time',
        },

        {
          align: 'left',
          width: 200,
          colKey: 'op',
          title: this.$t('common.op'),
        },
      ],
      rowKey: 'code',
      tableLayout: 'auto',
      verticalAlign: 'top',
      hover: true,
      rowClassName: (rowKey: string) => `${rowKey}-class`,
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
        return $t('page.host.delete_confirm_clear_relation');
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
        this.$message.warning(this.$t('page.host.forbid_for_global_site'));
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
        this.$message.warning(this.$t('page.host.forbid_for_global_site_only_change_guard_status'));
        return
      }
      console.log(code)
      this.editFormVisible = true
      this.getDetail(code)
    },
    handleAddHost() {
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
           that.$message.warning(this.$t('page.host.host_rule_msg'));
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
