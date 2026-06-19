<script setup>
import { ref, onMounted } from "vue";
import { NCard, NList, NListItem, NThing, NButton, NSpace, NTag, NEmpty, NSpin } from "naive-ui";
import { useMessage, useDialog } from "naive-ui";
import { apiGet, apiPost } from "../../api.js";
import { state, lock } from "../../store.js";

const message = useMessage();
const dialog = useDialog();
const loading = ref(false);
const currentVersion = ref(null);
const items = ref([]);

async function load() {
  loading.value = true;
  try {
    const { res } = await apiGet("/history");
    if (!res.ok) {
      message.error("加载历史失败: " + res.status);
      return;
    }
    const body = await res.json();
    currentVersion.value = body.current_version;
    items.value = body.history || [];
  } catch (e) {
    message.error("加载历史出错: " + (e?.message || e));
  } finally {
    loading.value = false;
  }
}

onMounted(load);

function recover(h) {
  dialog.warning({
    title: `恢复 v${h.version}`,
    content: `将 v${h.version} 恢复为当前版本（当前版本会归档到历史）。恢复后需用 v${h.version} 对应的旧主口令重新解锁。继续？`,
    positiveText: "恢复",
    negativeText: "取消",
    onPositiveClick: async () => {
      try {
        const { res } = await apiPost("/recover", { from_version: h.version });
        if (!res.ok) {
          message.error(`恢复失败: ${res.status} ${await res.text()}`);
          return;
        }
        const b = await res.json();
        state.currentVersion = b.version;
        message.success(`已恢复为 v${b.version}，请用旧主口令重新解锁`);
        lock();
      } catch (e) {
        message.error("恢复出错: " + (e?.message || e));
      }
    },
  });
}
</script>

<template>
  <n-card title="历史版本" :bordered="false">
    <p class="muted">
      当前版本：
      <n-tag size="small" type="info" :bordered="false">
        {{ currentVersion === null ? "(空)" : "v" + currentVersion }}
      </n-tag>
    </p>
    <n-spin :show="loading">
      <n-empty v-if="items.length === 0" description="暂无历史" />
      <n-list v-else>
        <nListItem v-for="h in items" :key="h.version">
          <nThing>
            <template #header>v{{ h.version }}</template>
            <template #description>
              <span class="muted">归档于 {{ h.archived_at }}</span>
            </template>
          </nThing>
          <template #suffix>
            <n-button size="small" type="primary" ghost @click="recover(h)">恢复</n-button>
          </template>
        </nListItem>
      </n-list>
    </n-spin>
  </n-card>
</template>
