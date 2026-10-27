/** Test-only exclusive Web Locks subset. It deliberately has no timeout,
 * expiry or steal path: the returned callback promise owns the lock. */
export function createTestLocks(): Pick<LockManager, "request"> {
  type Pending = {
    callback: (lock: Lock | null) => unknown | PromiseLike<unknown>;
    resolve: (value: unknown) => void;
    reject: (reason: unknown) => void;
    signal?: AbortSignal;
    abort?: () => void;
  };
  type Queue = { held: boolean; waiting: Pending[] };
  const queues = new Map<string, Queue>();

  function drain(name: string, queue: Queue): void {
    if (queue.held) return;
    const pending = queue.waiting.shift();
    if (!pending) {
      if (queues.get(name) === queue) queues.delete(name);
      return;
    }
    // Reserve synchronously so two ifAvailable requests cannot both win before
    // either asynchronous callback starts.
    queue.held = true;
    if (pending.abort)
      pending.signal?.removeEventListener("abort", pending.abort);
    const finish = () => {
      queue.held = false;
      drain(name, queue);
    };
    void Promise.resolve()
      .then(() => pending.callback({ name, mode: "exclusive" }))
      .then(
        (value) => {
          finish();
          pending.resolve(value);
        },
        (error: unknown) => {
          finish();
          pending.reject(error);
        },
      );
  }

  function request<T>(
    name: string,
    callback: LockGrantedCallback<T>,
  ): Promise<T>;
  function request<T>(
    name: string,
    options: LockOptions,
    callback: LockGrantedCallback<T>,
  ): Promise<T>;
  function request<T>(
    name: string,
    optionsOrCallback: LockOptions | LockGrantedCallback<T>,
    possibleCallback?: LockGrantedCallback<T>,
  ): Promise<T> {
    const options: LockOptions =
      typeof optionsOrCallback === "function" ? {} : optionsOrCallback;
    const callback =
      typeof optionsOrCallback === "function"
        ? optionsOrCallback
        : possibleCallback;
    if (
      !callback ||
      (options.mode !== undefined && options.mode !== "exclusive") ||
      options.steal
    ) {
      return Promise.reject(
        new TypeError("Unsupported test Web Locks options"),
      );
    }
    if (options.signal?.aborted) {
      return Promise.reject(new DOMException("Aborted", "AbortError"));
    }
    let queue = queues.get(name);
    if (options.ifAvailable && queue && (queue.held || queue.waiting.length)) {
      return Promise.resolve().then(() => callback(null));
    }
    if (!queue) {
      queue = { held: false, waiting: [] };
      queues.set(name, queue);
    }
    return new Promise<T>((resolve, reject) => {
      const pending: Pending = {
        callback,
        // Each value can only originate from this same generic callback.
        resolve: (value) => resolve(value as T),
        reject,
        signal: options.signal,
      };
      if (options.signal) {
        pending.abort = () => {
          const index = queue.waiting.indexOf(pending);
          if (index < 0) return;
          queue.waiting.splice(index, 1);
          reject(new DOMException("Aborted", "AbortError"));
          drain(name, queue);
        };
        options.signal.addEventListener("abort", pending.abort, { once: true });
      }
      queue.waiting.push(pending);
      drain(name, queue);
    });
  }

  return { request };
}

/** Browser-shaped storage without any production journal dependency or events.
 * A real storage event is delivered to other documents, not the writing one. */
export function createTestStorage(): Storage {
  const values = new Map<string, string>();
  const api: Storage = {
    get length() {
      return values.size;
    },
    clear: () => values.clear(),
    getItem: (key) => values.get(String(key)) ?? null,
    key: (index) => Array.from(values.keys())[index] ?? null,
    removeItem: (key) => {
      values.delete(String(key));
    },
    setItem: (key, value) => {
      values.set(String(key), String(value));
    },
  };
  // Native Storage exposes named values as its own enumerable properties while
  // methods/length live on its prototype. Keep enumeration faithful without
  // making the backing Map or this method object visible to journal snapshots.
  return new Proxy(Object.create(null) as Storage, {
    ownKeys: () => Array.from(values.keys()),
    getOwnPropertyDescriptor: (_target, key) =>
      typeof key === "string" && values.has(key)
        ? {
            configurable: true,
            enumerable: true,
            writable: true,
            value: values.get(key),
          }
        : undefined,
    get: (_target, key) =>
      key in api
        ? Reflect.get(api, key)
        : typeof key === "string"
          ? values.get(key)
          : undefined,
    set: (_target, key, value) => {
      if (typeof key !== "string") return false;
      values.set(key, String(value));
      return true;
    },
    deleteProperty: (_target, key) => {
      if (typeof key === "string") values.delete(key);
      return true;
    },
    has: (_target, key) =>
      key in api || (typeof key === "string" && values.has(key)),
  });
}
