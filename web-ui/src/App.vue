<script setup>
import { NMessageProvider, NDialogProvider, NConfigProvider, zhCN, dateZhCN } from "naive-ui";
import { state } from "./store.js";
import LockScreen from "./components/LockScreen.vue";
import AppShell from "./components/AppShell.vue";
</script>

<template>
  <n-config-provider :locale="zhCN" :date-locale="dateZhCN">
    <n-message-provider>
      <n-dialog-provider>
        <LockScreen v-if="!state.unlocked" :external-reason="state._lockReason" @reason-shown="state._lockReason = ''" />
        <AppShell v-else />
      </n-dialog-provider>
    </n-message-provider>
  </n-config-provider>
</template>
