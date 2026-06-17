/* tslint:disable */
/* eslint-disable */

/**
 * Holds the decrypted, in-memory list of entries.
 */
export class VaultHandle {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    /**
     * Returns the decrypted entries as a JSON array (name/url/username only).
     */
    all(): any;
    /**
     * Number of decrypted entries.
     */
    count(): number;
    /**
     * Group by domain. Returns `[{key, count}, ...]` sorted by count desc.
     */
    group_by_domain(): any;
    /**
     * Group by first letter of name.
     */
    group_by_letter(): any;
    /**
     * Group by tag. Returns `[{key, count}, ...]`.
     */
    group_by_tag(): any;
    /**
     * Search with a query string. Returns hits sorted by score desc.
     */
    search(query: string): any;
}

/**
 * Decrypts a snapshot and returns a handle to the in-memory vault.
 */
export function unlock(password: string, snapshot_json: string): VaultHandle;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly __wbg_vaulthandle_free: (a: number, b: number) => void;
    readonly unlock: (a: number, b: number, c: number, d: number) => [number, number, number];
    readonly vaulthandle_all: (a: number) => [number, number, number];
    readonly vaulthandle_count: (a: number) => number;
    readonly vaulthandle_group_by_domain: (a: number) => [number, number, number];
    readonly vaulthandle_group_by_letter: (a: number) => [number, number, number];
    readonly vaulthandle_group_by_tag: (a: number) => [number, number, number];
    readonly vaulthandle_search: (a: number, b: number, c: number) => [number, number, number];
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __externref_table_dealloc: (a: number) => void;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
