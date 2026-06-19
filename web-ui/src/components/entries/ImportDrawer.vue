<script setup>
import { ref, computed, watch } from "vue";
import {
  NDrawer, NDrawerContent, NButton, NSpace, NAlert,
  NRadioGroup, NRadioButton, NUpload, NInput, NTag, NDivider, NText,
} from "naive-ui";
import { useMessage } from "naive-ui";
import { parseCsv } from "../../csv.js";
import { allEntries, setEntries } from "../../wasm.js";
import { markDirty } from "../../store.js";

const props = defineProps({ show: Boolean });
const emit = defineEmits(["update:show", "imported"]);
const message = useMessage();

const mode = ref("file"); // "file" | "paste"
const pasteText = ref("");
const parsed = ref(null); // { entries, errors }
const conflictMode = ref("skip"); // "skip" | "overwrite"

watch(
  () => props.show,
  (v) => { if (!v) { pasteText.value = ""; parsed.value = null; } }
);

watch(pasteText, (v) => {
  if (mode.value === "paste" && v.trim()) {
    parsed.value = parseCsv(v);
  } else {
    parsed.value = null;
  }
});

function onFileChange({ file }) {
  if (!file?.file) return;
  const reader = new FileReader();
  reader.onload = (e) => {
    parsed.value = parseCsv(e.target.result);
  };
  reader.readAsText(file.file, "utf-8");
}

const existing = computed(() => {
  if (!parsed.value) return new Set();
  const cur = allEntries().map((e) => e.name);
  return new Set(cur);
});

const stats = computed(() => {
  if (!parsed.value) return null;
  const { entries } = parsed.value;
  const dupes = entries.filter((e) => existing.value.has(e.name));
  const news = entries.filter((e) => !existing.value.has(e.name));
  return { total: entries.length, new: news.length, dupes: dupes.length };
});

function doImport() {
  if (!parsed.value?.entries?.length) return;

  const cur = allEntries();
  const curMap = new Map(cur.map((e) => [e.name, e]));

  for (const entry of parsed.value.entries) {
    if (curMap.has(entry.name)) {
      if (conflictMode.value === "overwrite") {
        curMap.set(entry.name, entry);
      }
      // else skip
    } else {
      curMap.set(entry.name, entry);
    }
  }

  setEntries([...curMap.values()]);
  markDirty(true);

  const s = stats.value;
  const detail =
    conflictMode.value === "overwrite"
      ? `+${s.new} 新增，~${s.dupes} 覆盖`
      : `+${s.new} 新增，${s.dupes} 跳过`;
  message.success(`已导入 ${s.new + (conflictMode.value === "overwrite" ? s.dupes : 0)} 条（${detail}），请点「保存」写入服务器`);
  emit("imported");
  emit("update:show", false);
}
</script>

<template>
  <n-drawer
    :show="show"
    :width="480"
    placement="right"
    @update:show="(v) => emit('update:show', v)"
  >
    <n-drawer-content title="批量导入 CSV" closable>
      <!-- mode switch -->
      <n-radio-group v-model:value="mode" size="small" style="margin-bottom: 12px">
        <n-radio-button value="file">选择文件</n-radio-button>
        <n-radio-button value="paste">粘贴内容</n-radio-button>
      </n-radio-group>

      <!-- file picker -->
      <template v-if="mode === 'file'">
        <n-upload
          accept=".csv,text/csv"
          :max="1"
          :default-upload="false"
          @change="onFileChange"
        >
          <n-button>选择 CSV 文件</n-button>
        </n-upload>
      </template>

      <!-- paste -->
      <template v-else>
        <n-input
          v-model:value="pasteText"
          type="textarea"
          :rows="10"
          placeholder="粘贴 CSV 内容（第一行需为表头 name,url,username,password,note）"
          style="font-family: monospace; font-size: 12px"
        />
      </template>

      <!-- format hint -->
      <p style="margin: 8px 0; font-size: 12px; color: #999">
        表头：<code>name,url,username,password,note</code>（列顺序任意，url/note 可缺省）
      </p>

      <!-- parse errors -->
      <n-alert v-if="parsed?.errors?.length" type="warning" style="margin-top: 8px">
        <div v-for="e in parsed.errors" :key="e">{{ e }}</div>
      </n-alert>

      <!-- stats preview -->
      <template v-if="stats">
        <n-divider style="margin: 12px 0" />
        <n-space>
          <n-tag type="info">共 {{ stats.total }} 条</n-tag>
          <n-tag type="success">+{{ stats.new }} 新增</n-tag>
          <n-tag v-if="stats.dupes > 0" type="warning">{{ stats.dupes }} 重复</n-tag>
        </n-space>

        <!-- conflict resolution -->
        <div v-if="stats.dupes > 0" style="margin-top: 12px">
          <n-text depth="3" style="font-size: 13px">重复条目处理：</n-text>
          <n-radio-group v-model:value="conflictMode" size="small" style="margin-left: 8px">
            <n-radio-button value="skip">跳过</n-radio-button>
            <n-radio-button value="overwrite">覆盖</n-radio-button>
          </n-radio-group>
        </div>
      </template>

      <template #footer>
        <n-space>
          <n-button @click="emit('update:show', false)">取消</n-button>
          <n-button
            type="primary"
            :disabled="!stats || stats.total === 0 || (stats.new === 0 && conflictMode === 'skip')"
            @click="doImport"
          >导入</n-button>
        </n-space>
      </template>
    </n-drawer-content>
  </n-drawer>
</template>
