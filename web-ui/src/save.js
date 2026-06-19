// Save flow: encrypt current entries, PUT with If-Match, handle 409 conflict.
import { state } from "./store.js";
import { apiPut, apiGet } from "./api.js";
import { putEntries, doUnlock, setEntries, allEntries } from "./wasm.js";

/** Returns true on success. Caller shows messages. */
export async function saveToServer(message, dialog) {
  if (!state.unlocked) return false;
  if (!state.dirty) {
    message.info("没有未保存的修改");
    return true;
  }
  const ourEntries = allEntries(); // capture before any refetch
  try {
    const write = putEntries();
    const { res, url } = await apiPut(write, state.currentVersion);
    if (res.status === 409) {
      const body = await res.json();
      const cur = body.current_version;
      const ok = await new Promise((resolve) => {
        dialog.warning({
          title: "版本冲突",
          content: `服务器已是 v${cur}（本地基于 v${state.currentVersion}）。强制覆盖会丢失服务端的改动。覆盖？`,
          positiveText: "强制覆盖",
          negativeText: "取消",
          onPositiveClick: () => resolve(true),
          onNegativeClick: () => resolve(false),
          onClose: () => resolve(false),
        });
      });
      if (!ok) return false;
      // refetch, re-decrypt with current master pw, apply our entries, re-save
      const { res: r2 } = await apiGet();
      const newSnap = await r2.json();
      state.currentVersion = newSnap.version;
      await doUnlock(state.masterPw, JSON.stringify(newSnap));
      setEntries(ourEntries);
      const w2 = putEntries();
      const { res: r3 } = await apiPut(w2, state.currentVersion);
      if (!r3.ok) {
        message.error("强制覆盖失败: " + r3.status);
        return false;
      }
      const b3 = await r3.json();
      state.currentVersion = b3.version;
      state.dirty = false;
      message.success(`已保存（强制覆盖）· v${state.currentVersion}`);
      return true;
    }
    if (!res.ok) {
      message.error(`保存失败: ${res.status}`);
      return false;
    }
    const body = await res.json();
    state.currentVersion = body.version || state.currentVersion + 1;
    state.dirty = false;
    message.success(`已保存 · v${state.currentVersion}`);
    return true;
  } catch (e) {
    message.error("保存出错: " + (e?.message || e));
    return false;
  }
}
