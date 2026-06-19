<script setup>
import { NLayout, NLayoutHeader, NLayoutSider, NLayoutContent, NMenu } from "naive-ui";
import { h, computed } from "vue";
import { state, lock, bumpIdle } from "../store.js";
import { useDialog, useMessage } from "naive-ui";
import TopBar from "./TopBar.vue";
import EntriesTab from "./entries/EntriesTab.vue";
import HistoryTab from "./history/HistoryTab.vue";
import SettingsTab from "./settings/SettingsTab.vue";

const dialog = useDialog();
const message = useMessage();

const menuOptions = [
  { label: "条目管理", key: "entries" },
  { label: "历史版本", key: "history" },
  { label: "设置", key: "settings" },
];

const current = computed(() => {
  switch (state.activeTab) {
    case "history":
      return HistoryTab;
    case "settings":
      return SettingsTab;
    default:
      return EntriesTab;
  }
});

function onLock() {
  if (state.dirty) {
    dialog.warning({
      title: "有未保存的修改",
      content: "锁定会丢失本地修改，确认锁定？",
      positiveText: "锁定",
      negativeText: "取消",
      onPositiveClick: () => doLock(),
    });
  } else {
    doLock();
  }
}

function doLock() {
  lock();
  message.info("已锁定");
}

// any user interaction resets idle timer
function resetIdle() {
  bumpIdle();
}
</script>

<template>
  <n-layout position="absolute" @mousemove="resetIdle" @keydown="resetIdle">
    <n-layout-header bordered>
      <TopBar @lock="onLock" />
    </n-layout-header>
    <n-layout has-sider position="absolute" style="top: 56px">
      <n-layout-sider
        bordered
        :width="180"
        content-style="padding: 8px"
      >
        <n-menu
          v-model:value="state.activeTab"
          :options="menuOptions"
          :indent="18"
          :root-indent="18"
        />
      </n-layout-sider>
      <n-layout-content content-style="padding: 16px">
        <component :is="current" />
      </n-layout-content>
    </n-layout>
  </n-layout>
</template>
