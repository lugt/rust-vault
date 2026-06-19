<script setup>
import { ref } from "vue";
import { NDescriptions, NDescriptionsItem, NButton, NSpace, NText } from "naive-ui";
import { copyText } from "../../clipboard.js";
import { useMessage, useDialog } from "naive-ui";
import { setEntries, allEntries } from "../../wasm.js";
import { state, markDirty } from "../../store.js";
import { saveToServer } from "../../save.js";

const props = defineProps({ entry: Object });
const emit = defineEmits(["edit", "delete"]);

const message = useMessage();
const dialog = useDialog();
const revealed = ref(false);
const saving = ref(false);

function reveal() {
  revealed.value = !revealed.value;
}

async function copy(v, label) {
  await copyText(v);
  message.success(`已复制${label}（30s 后自动清空）`);
}

function doDelete() {
  dialog.warning({
    title: "删除条目",
    content: `确认删除「${props.entry.name}」？需点「保存」后才生效。`,
    positiveText: "删除",
    negativeText: "取消",
    onPositiveClick: () => {
      const all = allEntries().filter((e) => e.name !== props.entry.name);
      setEntries(all);
      markDirty(true);
      emit("delete");
      message.success("已删除（待保存）");
    },
  });
}

async function doSave() {
  saving.value = true;
  await saveToServer(message, dialog);
  saving.value = false;
}
</script>

<template>
  <div>
    <n-space justify="space-between" align="center" style="margin-bottom: 12px">
      <nText strong style="font-size: 1.2em">{{ entry.name }}</nText>
      <n-space :size="8">
        <n-button size="small" @click="$emit('edit')">✏ 编辑</n-button>
        <n-button size="small" type="error" ghost @click="doDelete">🗑 删除</n-button>
        <n-button
          size="small"
          type="primary"
          :disabled="!state.dirty"
          :loading="saving"
          @click="doSave"
        >💾 保存</n-button>
      </n-space>
    </n-space>
    <nDescriptions label-placement="left" bordered :column="1" size="small">
      <nDescriptionsItem label="URL">
        <span v-if="entry.url">{{ entry.url }}</span>
        <span v-else class="muted">—</span>
      </nDescriptionsItem>
      <nDescriptionsItem label="Username">
        <span>{{ entry.username || "—" }}</span>
        <n-button size="tiny" text @click="copy(entry.username, '用户名')">复制</n-button>
      </nDescriptionsItem>
      <nDescriptionsItem label="Password">
        <span style="font-family: monospace">{{
          revealed ? entry.password : "••••••••"
        }}</span>
        <n-button size="tiny" text @click="reveal">{{ revealed ? "隐藏" : "显示" }}</n-button>
        <n-button size="tiny" text @click="copy(entry.password, '密码')">复制</n-button>
      </nDescriptionsItem>
      <nDescriptionsItem label="Note">
        <span style="white-space: pre-wrap">{{ entry.note || "—" }}</span>
      </nDescriptionsItem>
    </nDescriptions>
    <p class="muted" style="margin-top: 12px">改动后请到「设置」或顶栏提示点「保存」写入服务器。</p>
  </div>
</template>
