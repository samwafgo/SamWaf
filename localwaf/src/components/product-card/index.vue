<template>
  <t-card theme="poster2">
    <template #avatar>
      <t-avatar size="56px">
        <template #icon>
          <shop-icon v-if="product.type === 1" />
          <calendar-icon v-if="product.type === 2" />
          <service-icon v-if="product.type === 3" />
          <user-avatar-icon v-if="product.type === 4" />
          <laptop-icon v-if="product.type === 5" />
        </template>
      </t-avatar>
    </template>
    <template #status>
      <t-tag :theme="product.isSetup ? 'success' : 'default'" :disabled="!product.isSetup">{{
        product.isSetup ? '已启用' : '已停用'
      }}</t-tag>
    </template>
    <template #content>
      <p class="list-card-item_detail--name">{{ product.name }}</p>
      <p class="list-card-item_detail--desc">{{ product.description }}</p>
    </template>
    <template #footer>
      <t-avatar-group cascading="left-up" :max="2">
        <t-avatar>{{ typeMap[product.type - 1] }}</t-avatar>
        <t-avatar
          ><template #icon>
            <add-icon />
          </template>
        </t-avatar>
      </t-avatar-group>
    </template>
    <template #actions>
      <t-dropdown
        :disabled="!product.isSetup"
        trigger="click"
        :options="[
          {
            content: '管理',
            value: 'manage',
            onClick: () => handleManageProduct(product),
          },
          {
            content: '删除',
            value: 'delete',
            onClick: () => handleDeleteItem(product),
          },
        ]"
      >
        <t-button theme="default" :disabled="!product.isSetup" shape="square" variant="text">
          <more-icon />
        </t-button>
      </t-dropdown>
    </template>
  </t-card>
</template>
<script lang="ts">
import { ShopIcon, CalendarIcon, ServiceIcon, UserAvatarIcon, LaptopIcon, MoreIcon, AddIcon } from 'tdesign-icons-vue';

export default {
  name: 'ListCard',
  components: {
    ShopIcon,
    CalendarIcon,
    ServiceIcon,
    UserAvatarIcon,
    LaptopIcon,
    MoreIcon,
    AddIcon,
  },
  props: {
    product: {
      type: Object,
    },
  },
  data() {
    return { typeMap: ['A', 'B', 'C', 'D', 'E'] };
  },
  methods: {
    handleClickManage(product) {
      this.$emit('manage-product', product);
    },
    handleClickDelete(product) {
      this.$emit('delete-item', product);
    },
  },
};
</script>

<style lang="less" scoped>
@import '@/style/variables';

.list-card-item {
  display: flex;
  flex-direction: column;
  cursor: pointer;

  &_detail {
    min-height: 140px;

    &--name {
      margin-bottom: 8px;
      font-size: 16px;
      font-weight: 400;
      color: var(--td-text-color-primary);
    }

    &--desc {
      color: var(--td-text-color-secondary);
      font-size: 12px;
      line-height: 20px;
      overflow: hidden;
      text-overflow: ellipsis;
      display: -webkit-box;
      -webkit-line-clamp: 2;
      -webkit-box-orient: vertical;
      height: 40px;
    }
  }
}
</style>
