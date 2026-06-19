<script setup>
import { ref, watch } from "vue";
import { NDrawer, NDrawerContent, NForm, NFormItem, NInput, NButton, NSpace } from "naive-ui";
import { useMessage } from "naive-ui";
import { setEntries, allEntries } from "../../wasm.js";
import { markDirty, state } from "../../store.js";

const props = defineProps({
  show: Boolean,
  mode: String, // add | edit
  entry: Object,
});
const emit = defineEmits(["update:show", "saved"]);

const message = useMessage();

const form = ref({ name: "", url: "", username: "", password: "", note: "" });

watch(
  () => props.show,
  (v) => {
    if (!v) return;
    if (props.mode === "edit" && props.entry) {
      form.value = { ...props.entry };
    } else {
      form.value = { name: "", url: "", username: "", password: "", note: "" };
    }
  }
);

function close() {
  emit("update:show", false);
}

function submit() {
  const name = form.value.name.trim();
  if (!name) {
    message.error("Name 不能为空");
    return;
  }
  const all = allEntries();
  if (props.mode === "add") {
    if (all.some((e) => e.name === name)) {
      message.error(`已存在同名条目「${name}」`);
      return;
    }
    all.push({
      name,
      url: form.value.url.trim(),
      username: form.value.username.trim(),
      password: form.value.password,
      note: form.value.note,
    });
    setEntries(all);
    markDirty(true);
    message.success("已新增（待保存）");
    emit("saved", { name }, "add");
  } else {
    // edit: match by original entry name (state.selectedName), allow rename
    const origName = props.entry.name;
    if (name !== origName && all.some((e) => e.name === name)) {
      message.error(`已存在同名条目「${name}」`);
      return;
    }
    const i = all.findIndex((e) => e.name === origName);
    if (i < 0) {
      message.error("原条目已不存在");
      return;
    }
    all[i] = {
      name,
      url: form.value.url.trim(),
      username: form.value.username.trim(),
      password: form.value.password,
      note: form.value.note,
    };
    setEntries(all);
    state.selectedName = name;
    markDirty(true);
    message.success("已修改（待保存）");
    emit("saved", { name }, "edit");
  }
}
</script>

<template>
  <n-drawer
    :show="show"
    :width="420"
    placement="right"
    @update:show="(v) => emit('update:show', v)"
  >
    <n-drawer-content
      :title="mode === 'add' ? '新增条目' : '编辑条目'"
      closable
    >
      <n-form label-placement="top">
        <n-form-item label="Name">
          <n-input v-model:value="form.name" placeholder="条目名（唯一）" />
        </n-form-item>
        <n-form-item label="URL">
          <n-input v-model:value="form.url" placeholder="https://…" />
        </n-form-item>
        <n-form-item label="Username">
          <n-input v-model:value="form.username" />
        </n-form-item>
        <n-form-item label="Password">
          <n-input
            v-model:value="form.password"
            type="password"
            show-password-on="click"
          />
        </n-form-item>
        <n-form-item label="Note">
          <n-input v-model:value="form.note" type="textarea" :rows="3" />
        </n-form-item>
      </n-form>
      <template #footer>
        <n-space>
          <n-button @click="close">取消</n-button>
          <n-button type="primary" @click="submit">
            {{ mode === "add" ? "添加" : "保存修改" }}
          </n-button>
        </n-space>
      </template>
    </n-drawer-content>
  </n-drawer>
</template>
