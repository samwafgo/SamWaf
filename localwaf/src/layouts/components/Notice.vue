<template>
  <t-popup
    expand-animation
    placement="bottom-right"
    trigger="click"
    :visible="isNoticeVisible"
    @visible-change="onPopupVisibleChange"
  >
    <template #content>
      <div class="header-msg">
        <div class="header-msg-top">
          <p>通知</p>
          <t-button v-if="unreadMsg.length > 0" class="clear-btn" variant="text" theme="primary" @click="setRead('all')"
            >清空</t-button
          >
        </div>
        <t-list v-if="unreadMsg.length > 0" class="narrow-scrollbar" :split="true">
          <t-list-item v-for="(item, index) in unreadMsg" :key="index">
            <div>
              <p class="msg-content">{{ item.content }}</p>
              <p class="msg-type">{{ item.type }}</p>
            </div>
            <p class="msg-time">{{ item.date }}</p>
            <template #action>
              <t-button size="small" variant="outline" @click="setRead('radio', item)"> 设为已读 </t-button>
            </template>
          </t-list-item>
        </t-list>

        <div v-else class="empty-list">
          <img src="https://tdesign.gtimg.com/pro-template/personal/nothing.png" alt="空" />
          <p>暂无通知</p>
        </div>
        <div class="header-msg-bottom">
          <t-button
            v-if="unreadMsg.length > 0"
            class="header-msg-bottom-link"
            variant="text"
            theme="primary"
            @click="goDetail"
            >查看全部</t-button
          >
        </div>
      </div>
    </template>
    <t-badge :count="unreadMsg.length" :offset="[15, 21]">
      <t-button theme="default" shape="square" variant="text" @click="isNoticeVisible = true">
        <mail-icon />
      </t-button>
    </t-badge>
  </t-popup>
</template>

<script lang="ts">
import Vue from 'vue';
import { mapState, mapGetters } from 'vuex';
import { MailIcon } from 'tdesign-icons-vue';

import { NotificationItem } from '@/interface';

export default Vue.extend({
  components: {
    MailIcon,
  },
  data() {
    return {
      isNoticeVisible: false,
    };
  },
  computed: {
    ...mapState('notification', ['msgData']),
    ...mapGetters('notification', ['unreadMsg']),
  },
  methods: {
    onPopupVisibleChange(visible: boolean, context) {
      if (context.trigger === 'trigger-element-click') {
        this.isNoticeVisible = true;
        return;
      }
      this.isNoticeVisible = visible;
    },
    goDetail() {
      this.$router.push('/detail/secondary');
      this.isNoticeVisible = false;
    },
    setRead(type: string, item?: NotificationItem) {
      const changeMsg = this.msgData;
      if (type === 'all') {
        changeMsg.forEach((e) => {
          e.status = false;
        });
      } else {
        changeMsg.forEach((e) => {
          if (e.id === item.id) {
            e.status = false;
          }
        });
      }
      this.$store.commit('notification/setMsgData', changeMsg);
    },
  },
});
</script>

<style lang="less" scoped>
@import '@/style/variables.less';

.header-msg {
  width: 400px;
  height: 500px;

  .empty-list {
    height: calc(100% - 104px);
    text-align: center;
    padding-top: 135px;
    font-size: 14px;
    color: var(--td-text-color-secondary);

    img {
      width: 63px;
    }

    p {
      margin-top: 30px;
    }
  }

  &-top {
    position: relative;
    height: 56px;
    font-size: 16px;
    color: var(--td-text-color-primary);
    text-align: center;
    line-height: 56px;
    border-bottom: 1px solid var(--td-component-border);

    .clear-btn {
      position: absolute;
      top: 12px;
      right: 24px;
    }
  }

  &-bottom {
    height: 48px;
    align-items: center;
    display: flex;
    justify-content: center;

    &-link {
      text-decoration: none;
      font-size: 14px;
      color: var(--td-brand-color);
      line-height: 48px;
      cursor: pointer;
    }
  }

  .t-list {
    height: calc(100% - 104px);
  }

  .t-list-item {
    overflow: hidden;
    width: 100%;
    padding: 16px 24px;
    border-radius: @border-radius;
    font-size: 14px;
    color: var(--td-text-color-primary);
    line-height: 22px;
    cursor: pointer;

    &:hover {
      transition: background 0.2s ease;
      background: var(--td-bg-color-container-hover);

      .msg-content {
        color: var(--td-brand-color-8);
      }

      .t-list-item__action {
        button {
          bottom: 16px;
          opacity: 1;
        }
      }

      .msg-time {
        bottom: -6px;
        opacity: 0;
      }
    }

    .msg-content {
      margin-bottom: 16px;
    }

    .msg-type {
      color: var(--td-text-color-secondary);
    }

    .t-list-item__action {
      button {
        opacity: 0;
        position: absolute;
        right: 24px;
        bottom: -6px;
      }
    }

    .msg-time {
      transition: all 0.2s ease;
      opacity: 1;
      position: absolute;
      right: 24px;
      bottom: 16px;
      color: var(--td-text-color-secondary);
    }
  }
}
</style>
