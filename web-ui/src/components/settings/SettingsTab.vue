<script setup>
import { ref } from "vue";
import {
  NCard,
  NForm,
  NFormItem,
  NInput,
  NButton,
  NSpace,
} from "naive-ui";
import { useMessage, useDialog } from "naive-ui";
import { state, persistConn, lock } from "../../store.js";
import { apiPost } from "../../api.js";
import { saveToServer } from "../../save.js";
import { rekeyHandle as rk } from "../../wasm.js";

const message = useMessage();
const dialog = useDialog();

// rekey form
const newPw = ref("");
const newPw2 = ref("");

// clear confirm
const clearText = ref("");

async function saveConn() {
  persistConn();
  message.success("已保存连接配置（API / token）");
}

async function doRekey() {
  if (!newPw.value) return message.error("新口令不能为空");
  if (newPw.value !== newPw2.value) return message.error("两次输入不一致");
  try {
    const body = rk(newPw.value);
    const { res } = await apiPost("/rekey", body);
    if (!res.ok) {
      message.error(`rekey 失败: ${res.status} ${await res.text()}`);
      return;
    }
    const b = await res.json();
    state.currentVersion = b.version;
    message.success(`已换密码 · v${b.version}，请用新口令重新解锁`);
    lock();
  } catch (e) {
    message.error("rekey 出错: " + (e?.message || e));
  }
}

async function doSave() {
  await saveToServer(message, dialog);
}

async function doClear() {
  if (clearText.value !== "CLEAR") {
    return message.error('请输入 CLEAR 确认');
  }
  dialog.error({
    title: "高危：清空 vault",
    content: "将清空当前 vault（当前快照归档到历史），之后需 vault-cli init 重新初始化。确认？",
    positiveText: "确认清空",
    negativeText: "取消",
    onPositiveClick: async () => {
      try {
        const { res } = await apiPost("/clear", {});
        if (res.status !== 204) {
          message.error(`清空失败: ${res.status} ${await res.text()}`);
          return;
        }
        clearText.value = "";
        message.success("已清空，请用 vault-cli init 重新初始化");
        lock();
      } catch (e) {
        message.error("清空出错: " + (e?.message || e));
      }
    },
  });
}
</script>

<template>
  <n-space vertical :size="16">
    <n-card title="连接配置" :bordered="false">
      <n-form label-placement="top">
        <n-form-item label="API endpoint">
          <n-input v-model:value="state.apiUrl" placeholder="https://host/keychain/vault" />
        </n-form-item>
        <n-form-item label="API token">
          <n-input
            v-model:value="state.token"
            type="password"
            show-password-on="click"
            placeholder="Bearer token（可缓存）"
          />
        </n-form-item>
        <n-button type="primary" @click="saveConn">保存连接配置</n-button>
      </n-form>
      <p class="muted">主口令仅存内存，不在此保存。token 与 API 地址会缓存到 localStorage。</p>
    </n-card>

    <n-card title="保存" :bordered="false">
      <p class="muted">将本地未保存的条目改动写入服务器。</p>
      <n-button
        type="primary"
        :disabled="!state.dirty"
        @click="doSave"
      >💾 保存到服务器</n-button>
    </n-card>

    <n-card title="更换主口令（Rekey）" :bordered="false">
      <p class="muted">重新包裹 CEK，不重加密 CSV。会创建新版本，之后需用新口令解锁。</p>
      <n-form label-placement="top">
        <n-form-item label="新主口令">
          <n-input v-model:value="newPw" type="password" show-password-on="click" />
        </n-form-item>
        <n-form-item label="确认新主口令">
          <n-input v-model:value="newPw2" type="password" show-password-on="click" />
        </n-form-item>
        <n-button type="warning" @click="doRekey">🔑 换密码</n-button>
      </n-form>
    </n-card>

    <n-card title="清空 vault（高危）" :bordered="false">
      <p class="muted">清空当前 vault，当前快照归档到历史。之后需 vault-cli init 重新初始化。</p>
      <n-form label-placement="top">
        <n-form-item label='输入 CLEAR 确认'>
          <n-input v-model:value="clearText" placeholder="CLEAR" />
        </n-form-item>
        <n-button type="error" @click="doClear">⚠️ 清空</n-button>
      </n-form>
    </n-card>
  </n-space>
</template>
