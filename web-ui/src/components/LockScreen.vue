<script setup>
import { ref, watch } from "vue";
import { NCard, NForm, NFormItem, NInput, NButton, NSpace, NAlert } from "naive-ui";
import { state, persistConn, bumpIdle } from "../store.js";
import { apiGet } from "../api.js";
import { doUnlock } from "../wasm.js";
import { useMessage } from "naive-ui";

const props = defineProps({ externalReason: String });
const emit = defineEmits(["reason-shown"]);

const message = useMessage();
const pw = ref("");
const error = ref("");
const busy = ref(false);

watch(
  () => props.externalReason,
  (v) => {
    if (v) {
      message.warning(v);
      emit("reason-shown");
    }
  }
);

async function unlock() {
  error.value = "";
  busy.value = true;
  try {
    if (!state.apiUrl) throw new Error("API endpoint 未填写");
    if (!state.token) throw new Error("API token 未填写");
    if (!pw.value) throw new Error("主口令未填写");

    const { res, url } = await apiGet();
    if (res.status === 404) throw new Error(`vault 未初始化（404）。先用 vault-cli init。url=${url}`);
    if (res.status === 401) throw new Error(`API token 错误（401）。url=${url}`);
    if (!res.ok) throw new Error(`GET 失败: ${res.status} url=${url}`);
    const snap = await res.json();
    state.currentVersion = snap.version;
    await doUnlock(pw.value, JSON.stringify(snap));
    state.masterPw = pw.value;
    state.unlocked = true;
    state.dirty = false;
    persistConn();
    bumpIdle();
    pw.value = "";
    message.success(`已解锁 · v${state.currentVersion}`);
  } catch (e) {
    const msg = e?.message || String(e);
    // decrypt failures from WASM typically mention decrypt/unwrap/kdf
    error.value = msg;
    if (/decrypt|unwrap|kdf|aead/i.test(msg)) {
      error.value = "解密失败——主口令可能错误。" + msg;
    }
  } finally {
    busy.value = false;
  }
}
</script>

<template>
  <div class="lock-wrap">
    <n-card title="Vault" style="width: 460px" :bordered="true">
      <p class="muted">端到端加密密码库 · 主口令永不离开浏览器</p>
      <n-form @keyup.enter="unlock">
        <n-form-item label="API endpoint">
          <n-input v-model:value="state.apiUrl" placeholder="https://host/keychain/vault" />
        </n-form-item>
        <n-form-item label="API token">
          <n-input
            v-model:value="state.token"
            type="password"
            show-password-on="click"
            placeholder="Bearer token"
          />
        </n-form-item>
        <n-form-item label="主口令">
          <n-input
            v-model:value="pw"
            type="password"
            show-password-on="click"
            placeholder="主口令（仅存内存，不保存）"
            autofocus
          />
        </n-form-item>
        <n-space vertical>
          <n-button type="primary" block :loading="busy" @click="unlock">解锁</n-button>
        </n-space>
      </n-form>
      <n-alert v-if="error" type="error" :show-icon="true" style="margin-top: 12px" closable @close="error = ''">
        {{ error }}
      </n-alert>
      <details style="margin-top: 12px">
        <summary class="muted">关于 E2E 加密</summary>
        <p class="muted">
          主口令仅用于在浏览器内解密，不会随请求发送。服务器只存储加密密文，即使 VPS
          被完全入侵，没有主口令也无法解密数据。Token 与 API 地址可缓存以便下次自动回填。
        </p>
      </details>
    </n-card>
  </div>
</template>

<style scoped>
.lock-wrap {
  display: flex;
  align-items: center;
  justify-content: center;
  min-height: 100vh;
  padding: 24px;
}
</style>
