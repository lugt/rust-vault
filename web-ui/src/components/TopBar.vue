<script setup>
import { NSpace, NTag, NButton, NText } from "naive-ui";
import { state } from "../store.js";

defineEmits(["lock"]);
</script>

<template>
  <div class="topbar">
    <n-text strong style="font-size: 1.05em">Vault</n-text>
    <n-space :size="8" align="center" style="margin-left: 16px">
      <n-tag size="small" type="info" :bordered="false">v{{ state.currentVersion }}</n-tag>
      <n-tag
        size="small"
        :type="state.dirty ? 'warning' : 'default'"
        :bordered="false"
      >
        {{ state.dirty ? "有未保存修改" : "已保存" }}
      </n-tag>
    </n-space>
    <div style="flex: 1"></div>
    <n-button size="small" @click="$emit('lock')">🔒 锁定</n-button>
  </div>
</template>

<style scoped>
.topbar {
  height: 56px;
  display: flex;
  align-items: center;
  padding: 0 16px;
  background: #fff;
}
</style>
