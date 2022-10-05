<template>
  <div class="list-card">
    <!-- 搜索区域 -->
    <div class="list-card-operation">
      <t-button @click="formVisible = true">新建产品</t-button>
      <t-input v-model="searchValue" class="search-input" placeholder="请输入你需要搜索的内容" clearable>
        <template #suffix-icon>
          <search-icon v-if="searchValue === ''" size="20px" />
        </template>
      </t-input>
    </div>
    <!-- 卡片列表 -->
    <template v-if="pagination.total > 0 && !dataLoading">
      <div class="list-card-items">
        <t-row :gutter="[16, 16]">
          <t-col
            :lg="4"
            :xs="6"
            :xl="3"
            v-for="product in productList.slice(
              pagination.pageSize * (pagination.current - 1),
              pagination.pageSize * pagination.current,
            )"
            :key="product.index"
          >
            <product-card :product="product" @delete-item="handleDeleteItem" @manage-product="handleManageProduct" />
          </t-col>
        </t-row>
      </div>
      <div class="list-card-pagination">
        <t-pagination
          v-model="pagination.current"
          :total="pagination.total"
          :pageSizeOptions="[12, 24, 36]"
          :page-size.sync="pagination.pageSize"
          @page-size-change="onPageSizeChange"
          @current-change="onCurrentChange"
        />
      </div>
    </template>
    <div v-else-if="dataLoading" class="list-card-loading">
      <t-loading text="加载中..."></t-loading>
    </div>
    <!-- 产品管理弹窗 -->
    <t-dialog header="新建产品" :visible.sync="formVisible" :width="680" :footer="false">
      <div slot="body">
        <!-- 表单内容 -->
        <t-form :data="formData" ref="form" :rules="rules" @submit="onSubmit" :labelWidth="100">
          <t-form-item label="产品名称" name="name">
            <t-input :style="{ width: '480px' }" v-model="formData.name" placeholder="请输入产品名称"></t-input>
          </t-form-item>
          <t-form-item label="产品状态" name="status">
            <t-radio-group v-model="formData.status">
              <t-radio value="0">已停用</t-radio>
              <t-radio value="1">已启用</t-radio>
            </t-radio-group>
          </t-form-item>
          <t-form-item label="产品描述" name="description">
            <t-input :style="{ width: '480px' }" v-model="formData.description" placeholder="请输入产品描述"></t-input>
          </t-form-item>
          <t-form-item label="产品类型" name="type">
            <t-select v-model="formData.type" clearable :style="{ width: '480px' }">
              <t-option v-for="(item, index) in options" :value="item.value" :label="item.label" :key="index">
                {{ item.label }}
              </t-option>
            </t-select>
          </t-form-item>
          <t-form-item label="备注" name="mark">
            <t-textarea :style="{ width: '480px' }" v-model="textareaValue" placeholder="请输入内容" name="description">
            </t-textarea>
          </t-form-item>
          <t-form-item style="float: right">
            <t-button variant="outline" @click="onClickCloseBtn">取消</t-button>
            <t-button theme="primary" type="submit">确定</t-button>
          </t-form-item>
        </t-form>
      </div>
    </t-dialog>
    <!-- 删除操作弹窗 -->
    <t-dialog
      header="确认删除所选产品？"
      :body="confirmBody"
      :visible.sync="confirmVisible"
      @confirm="onConfirmDelete"
      :onCancel="onCancel"
    >
    </t-dialog>
  </div>
</template>
<script lang="ts">
import { prefix } from '@/config/global';
import { SearchIcon } from 'tdesign-icons-vue';
import ProductCard from '@/components/product-card/index.vue';

const INITIAL_DATA = {
  name: '',
  status: '',
  description: '',
  type: '',
  mark: '',
  amount: 0,
};

export default {
  name: 'ListCard',
  components: {
    SearchIcon,
    ProductCard,
  },
  data() {
    return {
      pagination: { current: 1, pageSize: 12, total: 0 },
      prefix,
      productList: [],
      value: 'first',
      rowKey: 'index',
      tableLayout: 'auto',
      verticalAlign: 'top',
      bordered: true,
      hover: true,
      rowClassName: (rowKey) => `${rowKey}-class`,
      formData: { ...INITIAL_DATA },
      options: [
        { label: '网关', value: '1' },
        { label: '人工智能', value: '2' },
        { label: 'CVM', value: '3' },
      ],
      formVisible: false,
      textareaValue: '',
      rules: {
        name: [{ required: true, message: '请输入产品名称', type: 'error' }],
      },
      searchValue: '',
      confirmVisible: false, // 控制确认弹窗
      deleteProduct: undefined,
      dataLoading: false,
    };
  },
  computed: {
    confirmBody(): string {
      const { deleteProduct } = this;
      return deleteProduct ? `删除后，${deleteProduct.name}的所有产品信息将被清空, 且无法恢复` : '';
    },
  },
  mounted() {
    this.dataLoading = true;
    this.$request
      .get('/api/get-card-list')
      .then((res) => {
        if (res.code === 0) {
          const { list = [] } = res.data;
          this.productList = list;
          this.pagination = {
            ...this.pagination,
            total: list.length,
          };
        }
      })
      .catch((e: Error) => {
        console.log(e);
      })
      .finally(() => {
        this.dataLoading = false;
      });
  },
  methods: {
    onPageSizeChange(size: number): void {
      this.pagination.pageSize = size;
      this.pagination.current = 1;
    },
    onCurrentChange(current: number): void {
      this.pagination.current = current;
    },
    onSubmit({ result, firstError }): void {
      if (!firstError) {
        this.$message.success('提交成功');
        this.formVisible = false;
      } else {
        console.log('Errors: ', result);
        this.$message.warning(firstError);
      }
    },
    onClickCloseBtn(): void {
      this.formVisible = false;
      this.formData = {};
    },
    handleDeleteItem(product): void {
      this.confirmVisible = true;
      this.deleteProduct = product;
    },
    onConfirmDelete(): void {
      const { index } = this.deleteProduct;
      this.productList.splice(index - 1, 1);
      this.confirmVisible = false;
      this.$message.success('删除成功');
    },
    onCancel(): void {
      this.deleteProduct = undefined;
      this.formData = {};
    },
    handleManageProduct(product): void {
      this.formVisible = true;
      this.formData = { ...product, status: product?.isSetup ? '1' : '0' };
    },
  },
};
</script>
<style scoped lang="less">
.list-card-operation {
  display: flex;
  justify-content: space-between;

  .search-input {
    width: 360px;
  }
}

.list-card-items {
  margin: 14px 0 24px 0;
}
</style>
