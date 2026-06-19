<script setup>
import { ref, computed, watch } from "vue";
import { NSpace, NInput, NButton, NList, NListItem, NThing, NEmpty, NTag } from "naive-ui";
import { state, markDirty, bumpIdle } from "../../store.js";
import { searchEntries, allEntries } from "../../wasm.js";
import EntryDetail from "./EntryDetail.vue";
import EntryEditor from "./EntryEditor.vue";
import ImportDrawer from "./ImportDrawer.vue";

const query = ref("");
const selected = ref(null); // entry object
const editorOpen = ref(false);
const editorMode = ref("add"); // add | edit
const importOpen = ref(false);
let debounce = null;

const hits = ref([]);

function refresh() {
  if (!state.unlocked) return;
  hits.value = searchEntries(query.value || "");
  // keep selection valid
  if (selected.value && !hits.value.some((h) => h.name === selected.value.name)) {
    selected.value = null;
  }
}

watch(query, () => {
  clearTimeout(debounce);
  debounce = setTimeout(refresh, 180);
});

watch(
  () => state.unlocked,
  (v) => {
    if (v) refresh();
  },
  { immediate: true }
);

function onSelect(entry) {
  selected.value = entry;
  state.selectedName = entry.name;
  bumpIdle();
}

function openAdd() {
  editorMode.value = "add";
  editorOpen.value = true;
  bumpIdle();
}

function openEdit() {
  if (!selected.value) return;
  editorMode.value = "edit";
  editorOpen.value = true;
}

function onSaved(entry, mode) {
  // after set_entries in editor, refresh list and reselect
  refresh();
  if (mode === "add" && entry) {
    selected.value = hits.value.find((h) => h.name === entry.name) || null;
  } else if (entry) {
    selected.value = hits.value.find((h) => h.name === entry.name) || null;
  }
  markDirty(true);
  editorOpen.value = false;
}

function onDeleted() {
  selected.value = null;
  state.selectedName = null;
  refresh();
  markDirty(true);
}

function onImported() {
  refresh();
  selected.value = null;
}
</script>

<template>
  <div class="entries-tab">
    <div class="left-col">
      <n-space vertical :size="8">
        <n-input
          v-model:value="query"
          placeholder="搜索…（name:xx tag:xx 或纯文本）"
          clearable
        />
        <n-button type="primary" block @click="openAdd">+ 新增条目</n-button>
        <n-button block @click="importOpen = true">⬆ 批量导入 CSV</n-button>
      </n-space>
      <div class="list-wrap">
        <n-empty v-if="hits.length === 0" description="无条目" style="margin-top: 32px" />
        <n-list v-else hoverable clickable>
          <nListItem
            v-for="h in hits"
            :key="h.name"
            :class="{ active: selected && selected.name === h.name }"
            @click="onSelect(h)"
          >
            <nThing>
              <template #header>{{ h.name }}</template>
              <template #description>
                <span class="muted">{{ h.username || "—" }}</span>
                <span class="muted" style="margin-left: 8px">{{ h.url || "" }}</span>
              </template>
            </nThing>
            <template #suffix>
              <nTag size="tiny" :bordered="false">{{ h.score?.toFixed(2) }}</nTag>
            </template>
          </nListItem>
        </n-list>
      </div>
    </div>
    <div class="right-col">
      <EntryDetail
        v-if="selected"
        :entry="selected"
        @edit="openEdit"
        @delete="onDeleted"
      />
      <n-empty v-else description="从左侧选择一个条目查看详情" style="margin-top: 64px" />
    </div>
    <EntryEditor
      v-model:show="editorOpen"
      :mode="editorMode"
      :entry="selected"
      @saved="onSaved"
    />
    <ImportDrawer
      v-model:show="importOpen"
      @imported="onImported"
    />
  </div>
</template>

<style scoped>
.entries-tab {
  display: grid;
  grid-template-columns: 320px 1fr;
  gap: 16px;
  height: calc(100vh - 56px - 32px);
}
.left-col,
.right-col {
  background: #fff;
  border: 1px solid #efeff5;
  border-radius: 6px;
  padding: 12px;
  overflow-y: auto;
}
.list-wrap {
  margin-top: 12px;
}
.active {
  background: #f0f4ff;
}
</style>
