import { describe, expect, it, vi } from "vitest";
import { ApiError } from "../api/error";
import type { Job, MetadataJob, PolicyJob } from "../api/targets";
import { ReviewJournal, type JournalFactory } from "./review-journal";
import { createTestLocks, createTestStorage } from "../test/web-locks";
import {
  RoutingChanges,
  knownTicket,
  matchesTicket,
  observedJob,
  type Intent,
  type Observation,
  type Scope,
} from "./routing-changes";

const scope: Scope = {
  administratorId: "administrator-a",
  nodeId: "local-a",
  peer: "remote-a",
};
const intent: Intent = {
  action: "create",
  kind: "pools",
  resourceId: null,
  memberId: null,
  expectedRevision: "3",
  targetRevision: "2",
  controllerId: "local-a",
  controllerEpoch: "4",
  commandId: "5",
};
const pendingJob: PolicyJob = {
  node_id: "remote-a",
  job_id: "job-a",
  controller_epoch: "4",
  command_id: "5",
  expected_policy_revision: "3",
  state: "pending",
  policy_revision: null,
  outcome_code: null,
  attempts: 1,
  next_attempt: "0",
};
const savedJob: PolicyJob = {
  ...pendingJob,
  routing: { kind: "pool", id: "pool-a" },
  state: "saved",
  policy_revision: "4",
};
const metadataJob: MetadataJob = {
  resource: "proxy_endpoints",
  node_id: "remote-a",
  job_id: "endpoint-job-a",
  controller_epoch: "4",
  command_id: "5",
  expected_policy_revision: null,
  policy_revision: null,
  expected_metadata_revision: "2",
  metadata_revision: null,
  state: "pending",
  outcome_code: null,
  attempts: 1,
  next_attempt: "0",
  endpoint: { listener_id: "listener-a", generation: "a".repeat(64) },
};
const observation = (
  generation: number,
  job: Job | null = null,
  writable = true,
): Observation => ({
  generation,
  policyRevision: "4",
  controllerId: "local-a",
  controllerEpoch: "4",
  lastTerminalCommand: "5",
  targetRevision: "2",
  writable,
  job: observedJob(job),
});

describe("in-memory routing changes", () => {
  it("claims before dispatch and keeps cancellation unknown despite late success", async () => {
    const changes = new RoutingChanges();
    const listener = vi.fn();
    const unsubscribe = changes.subscribe(listener);
    const token = (await changes.begin(scope, intent))!;
    expect(await changes.begin(scope, intent)).toBeNull();
    expect(changes.observe(token, observation(1))).toBe(false);
    expect(await changes.continue(token, 1)).toBe(false);
    const failure = new ApiError("network");
    expect(changes.fail(token, failure)).toBe(true);
    const failed = changes.snapshot();
    expect(changes.find(scope)).toMatchObject({
      phase: "unknown",
      observation: null,
    });
    expect(changes.find(scope)?.error).not.toBe(failure);
    expect(changes.succeed(token)).toBe(false);
    expect(changes.notStarted(token)).toBe(false);
    expect(changes.wait(token)).toBe(false);
    expect(changes.fail(token, new ApiError("format"))).toBe(false);
    expect(changes.snapshot()).toBe(failed);
    expect(listener).toHaveBeenCalledTimes(2);
    unsubscribe();

    const unenteredScope = { ...scope, peer: null };
    const unentered = (await changes.begin(unenteredScope, intent))!;
    expect(changes.notStarted(unentered)).toBe(true);
    expect(changes.succeed(unentered)).toBe(false);
    const successful = (await changes.begin(unenteredScope, intent))!;
    expect(changes.succeed(successful)).toBe(true);
    expect(changes.find(scope)?.token).toBe(token);
    expect(listener).toHaveBeenCalledTimes(2);
  });

  it("owns non-secret immutable metadata and requires a fresh writable observation", async () => {
    const changes = new RoutingChanges();
    const sourceScope = { ...scope };
    const sourceIntent = { ...intent, name: "must not be retained" };
    const token = (await changes.begin(sourceScope, sourceIntent))!;
    sourceScope.peer = "changed";
    sourceIntent.expectedRevision = "99";
    changes.fail(token, new ApiError("network"));
    expect(await changes.continue(token, 1)).toBe(false);
    changes.observe(token, observation(1));
    expect(await changes.continue(token, 2)).toBe(false);
    changes.invalidateObservation(token);
    expect(await changes.continue(token, 1)).toBe(false);
    changes.observe(token, observation(2, null, false));
    expect(await changes.continue(token, 2)).toBe(false);
    for (const state of ["pending", "blocked"] as const) {
      changes.observe(token, observation(2, { ...metadataJob, state }));
      expect(await changes.continue(token, 2)).toBe(false);
    }

    const current = { ...savedJob, routing: { ...savedJob.routing! } };
    const read = observation(2, current);
    changes.observe(token, read);
    current.routing.id = "changed";
    const record = changes.find(scope)!;
    expect(record.intent).toEqual(intent);
    expect(record.observation?.job?.routing?.id).toBe("pool-a");
    expect(Object.keys(record.intent)).not.toContain("name");
    expect(Object.keys(record.observation!.job!)).not.toContain("attempts");
    for (const frozen of [
      changes.snapshot(),
      record,
      record.scope,
      record.intent,
      record.error,
      record.observation,
      record.observation?.job,
      record.observation?.job?.routing,
    ])
      expect(Object.isFrozen(frozen)).toBe(true);
    expect(await changes.continue(token, 2)).toBe(true);
    expect(await changes.begin(scope, intent)).not.toBe(token);
  });

  it("isolates administrator, local node and peer scopes without capacity eviction", async () => {
    const changes = new RoutingChanges();
    const unresolved = (await changes.begin(scope, intent))!;
    changes.fail(unresolved, new ApiError("network"));
    const separateScopes = [
      { ...scope, administratorId: "administrator-b" },
      { ...scope, nodeId: "local-b" },
      { ...scope, peer: "remote-b" },
      { ...scope, peer: null },
    ];
    const separate = await Promise.all(
      separateScopes.map((value) => changes.begin(value, intent)),
    );
    expect(separate.every((token) => token !== null)).toBe(true);
    for (let index = 0; index < 27; index++)
      expect(
        await changes.begin({ ...scope, peer: `cold-${index}` }, intent),
      ).not.toBeNull();
    expect(changes.snapshot()).toHaveLength(32);
    const full = changes.snapshot();
    const extra = { ...scope, peer: "new-remote" };
    expect(changes.available(extra)).toBe(false);
    expect(await changes.begin(extra, intent)).toBeNull();
    expect(changes.snapshot()).toBe(full);
    expect(changes.find(scope)?.token).toBe(unresolved);
    expect(changes.notStarted(separate[0]!)).toBe(true);
    expect(changes.available(extra)).toBe(true);
    expect(await changes.begin(extra, intent)).not.toBeNull();
    expect(changes.find(scope)?.phase).toBe("unknown");
  });

  it("correlates tickets without adopting replacements or allowing pending work to continue", async () => {
    const changes = new RoutingChanges();
    const token = (await changes.begin(scope, intent))!;
    const wrong: Job[] = [
      { ...pendingJob, node_id: "remote-b" },
      { ...pendingJob, controller_epoch: "5" },
      { ...pendingJob, command_id: "6" },
      { ...pendingJob, expected_policy_revision: "4" },
      { ...pendingJob, routing: { kind: "address", id: "address-a" } },
      { ...pendingJob, preset: { kind: "pool", id: "pool-a" } },
      { ...pendingJob, user_creation: true },
      metadataJob,
    ];
    for (const job of wrong)
      expect(changes.captureTicket(token, job)).toBe(false);
    expect(changes.captureTicket(token, pendingJob)).toBe(true);
    expect(changes.notStarted(token)).toBe(false);
    expect(changes.succeed(token)).toBe(true);
    expect(changes.find(scope)?.phase).toBe("waiting");
    changes.observe(token, observation(1, pendingJob));
    expect(await changes.continue(token, 1)).toBe(false);
    changes.observe(token, observation(1, { ...pendingJob, state: "blocked" }));
    expect(await changes.continue(token, 1)).toBe(false);
    const record = changes.find(scope)!;
    expect(matchesTicket(record.ticket!, savedJob)).toBe(true);
    expect(knownTicket(record, savedJob)).toBe(true);
    expect(changes.captureTicket(token, savedJob)).toBe(true);
    const retained = changes.find(scope)!;
    const replacement = { ...savedJob, job_id: "job-b", command_id: "6" };
    expect(knownTicket(retained, replacement)).toBe(false);
    expect(changes.captureTicket(token, replacement)).toBe(false);
    expect(
      changes.captureTicket(token, {
        ...savedJob,
        routing: { kind: "pool", id: "different-pool" },
      }),
    ).toBe(false);
    changes.observe(token, observation(1, replacement));
    expect(changes.find(scope)?.ticket).toBe(retained.ticket);
    expect(changes.find(scope)?.phase).toBe("waiting");
    expect(await changes.continue(token, 1)).toBe(true);

    const preset = (await changes.begin(scope, {
      ...intent,
      kind: "pool_preset",
      action: "set_preset",
      resourceId: "pool-a",
    }))!;
    const presetJob: PolicyJob = {
      ...pendingJob,
      preset: { kind: "pool", id: "pool-a" },
    };
    expect(changes.captureTicket(preset, savedJob)).toBe(false);
    expect(
      changes.captureTicket(preset, {
        ...presetJob,
        preset: { kind: "pool", id: "pool-b" },
      }),
    ).toBe(false);
    changes.fail(preset, new ApiError("network"));
    expect(changes.captureTicket(preset, presetJob)).toBe(true);
    expect(changes.find(scope)?.phase).toBe("unknown");
    expect(changes.succeed(preset)).toBe(false);
    expect(knownTicket(changes.find(scope)!, presetJob)).toBe(true);

    const memberScope = { ...scope, peer: "remote-b" };
    const membership = (await changes.begin(memberScope, {
      ...intent,
      action: "add_member",
      resourceId: "pool-a",
      memberId: "address-a",
    }))!;
    const memberJob = { ...pendingJob, node_id: "remote-b" };
    expect(
      changes.captureTicket(membership, {
        ...memberJob,
        routing: { kind: "pool", id: "pool-b" },
      }),
    ).toBe(false);
    expect(
      changes.captureTicket(membership, {
        ...memberJob,
        routing: { kind: "pool", id: "pool-a" },
      }),
    ).toBe(true);
  });

  it("only classifies the exact pre-write server guards as rejected", async () => {
    for (const code of [
      "invalid_origin",
      "invalid_csrf",
      "authentication_required",
    ]) {
      const changes = new RoutingChanges();
      const token = (await changes.begin(scope, intent))!;
      changes.fail(token, new ApiError("server", code, 403));
      expect(changes.find(scope)?.phase).toBe("rejected");
      expect(await changes.continue(token, 1)).toBe(false);
      changes.observe(token, observation(1));
      expect(await changes.continue(token, 1)).toBe(true);
    }
    for (const error of [
      new ApiError("server", "policy_denied", 403),
      new ApiError("server", "invalid_csrf", 409),
      new ApiError("server", "policy_conflict", 409),
      new ApiError("server", "policy_busy", 503),
      new ApiError("format", "invalid_csrf", 403),
      new ApiError("network"),
    ]) {
      const changes = new RoutingChanges();
      const token = (await changes.begin(scope, intent))!;
      changes.fail(token, error);
      expect(changes.find(scope)?.phase).toBe("unknown");
    }
  });
});

describe("persistent routing review notes", () => {
  const persistentScope: Scope = {
    administratorId: "A".repeat(22),
    nodeId: "AQEBAQEBAQEBAQEBAQEBAQ",
    peer: "AgICAgICAgICAgICAgICAg",
  };
  const persistentIntent: Intent = {
    ...intent,
    controllerId: persistentScope.nodeId,
  };
  const job: PolicyJob = {
    ...pendingJob,
    node_id: persistentScope.peer!,
    job_id: "AwMDAwMDAwMDAwMDAwMDAw",
  };
  const environment = () => {
    const backing = createTestStorage();
    let rejectWrites = false;
    const storage = new Proxy(backing, {
      get: (target, key, receiver) =>
        key === "setItem"
          ? (name: string, value: string) => {
              if (rejectWrites) throw new Error("private storage fault");
              target.setItem(name, value);
            }
          : Reflect.get(target, key, receiver),
    });
    const locks = createTestLocks();
    const listeners = new Set<() => void>();
    const factory: JournalFactory = (namespace, codec) =>
      new ReviewJournal(namespace, codec, {
        storage: () => storage,
        locks,
        listen: (listener) => {
          listeners.add(listener);
          return () => {
            listeners.delete(listener);
          };
        },
      });
    return {
      storage,
      factory,
      locks,
      rejectWrites: (reject: boolean) => {
        rejectWrites = reject;
      },
      notify: () => listeners.forEach((listener) => listener()),
    };
  };

  it("writes ahead, restores only metadata and requires a fresh explicit acknowledgement", async () => {
    const { storage, factory, locks } = environment();
    const changes = new RoutingChanges(factory);
    const begin = changes.begin(persistentScope, persistentIntent);
    expect(changes.find(persistentScope)?.phase).toBe("pending");
    expect(await changes.begin(persistentScope, persistentIntent)).toBeNull();
    const token = (await begin)!;
    expect(storage.length).toBe(1);
    expect(changes.captureTicket(token, job)).toBe(true);
    expect(changes.fail(token, new ApiError("network", "not persisted"))).toBe(
      true,
    );
    const raw = storage.getItem(storage.key(0)!)!;
    expect(raw).not.toContain("not persisted");
    expect(raw).not.toContain("observation");
    changes.release(token);
    // Web Locks releases after its owning callback returns, not synchronously
    // inside release(). Queue on that exact lock as a deterministic barrier.
    await locks.request(
      `vproxy.review.v1.routing.scope:${JSON.parse(raw).key}`,
      () => {},
    );

    const restored = new RoutingChanges(factory);
    const record = restored.find(persistentScope)!;
    expect(record).toMatchObject({
      phase: "unknown",
      error: null,
      observation: null,
      restored: true,
    });
    expect(record.token).not.toBe(token);
    expect(record.ticket?.job_id).toBe(job.job_id);
    expect(knownTicket(record, job)).toBe(false);
    expect(restored.captureTicket(record.token, job)).toBe(false);
    expect(await restored.continue(record.token, 2)).toBe(false);
    restored.observe(record.token, {
      ...observation(2),
      controllerId: persistentScope.nodeId,
    });
    expect(await restored.continue(record.token, 2, () => false)).toBe(false);
    expect(storage.length).toBe(1);
    expect(await restored.continue(record.token, 2)).toBe(true);
    expect(storage.length).toBe(0);
  });

  it("retains the scope lock after cancellation until the actual owner releases it", async () => {
    const { storage, factory } = environment();
    const changes = new RoutingChanges(factory);
    const token = (await changes.begin(persistentScope, persistentIntent))!;
    changes.fail(token, new ApiError("network"));
    // Removing browser data does not cancel the owner or release its Web Lock.
    storage.clear();
    const competing = new RoutingChanges(factory);
    expect(await competing.begin(persistentScope, persistentIntent)).toBeNull();
    expect(changes.find(persistentScope)?.phase).toBe("unknown");
    changes.release(token);
    expect(changes.find(persistentScope)?.phase).toBe("unknown");
  });

  it("rejects a changed observation both inside and after asynchronous clearing", async () => {
    const { storage, factory } = environment();
    const changes = new RoutingChanges(factory);
    const token = (await changes.begin(persistentScope, persistentIntent))!;
    changes.fail(token, new ApiError("network"));
    changes.release(token);
    changes.observe(token, observation(2));
    let finish!: (cleared: boolean) => void;
    const completed = new Promise<boolean>((resolve) => {
      finish = resolve;
    });
    let current: () => boolean = () => false;
    const clear = vi
      .spyOn(ReviewJournal.prototype, "clear")
      .mockImplementation((_key, _id, valid) => {
        current = valid;
        return completed;
      });
    try {
      const continuing = changes.continue(token, 2);
      expect(current()).toBe(true);
      const previous = changes.find(persistentScope)!.observation;
      changes.observe(token, observation(2));
      expect(changes.find(persistentScope)!.observation).not.toBe(previous);
      expect(current()).toBe(false);
      // Even if clearing had already succeeded before this response arrived,
      // the changed observation must not release the runtime's review fence.
      finish(true);
      expect(await continuing).toBe(false);
      expect(changes.find(persistentScope)?.phase).toBe("unknown");
      expect(storage.length).toBe(1);
    } finally {
      clear.mockRestore();
    }
  });

  it("does not drop an accepted request's fence when persistence fails", async () => {
    const { storage, factory, rejectWrites } = environment();
    const changes = new RoutingChanges(factory);
    const token = (await changes.begin(persistentScope, persistentIntent))!;
    // The browser-shaped storage Proxy deliberately supplies methods from its
    // own API. Intercept the real get boundary instead of spying on a shadow
    // property that its method lookup would never execute.
    rejectWrites(true);
    expect(changes.fail(token, new ApiError("network"))).toBe(false);
    expect(changes.find(persistentScope)?.phase).toBe("unknown");
    expect(changes.available(persistentScope)).toBe(false);
    expect(storage.length).toBe(1);
    rejectWrites(false);
    changes.release(token);
    expect(new RoutingChanges(factory).find(persistentScope)?.phase).toBe(
      "unknown",
    );
  });

  it("rejects extra persisted fields rather than loading payload or cached authority", async () => {
    const { storage, factory } = environment();
    const changes = new RoutingChanges(factory);
    const token = (await changes.begin(persistentScope, persistentIntent))!;
    changes.fail(token, new ApiError("network"));
    changes.release(token);
    const key = storage.key(0)!;
    const envelope = JSON.parse(storage.getItem(key)!);
    envelope.value.intent.name = "must not become a form";
    storage.setItem(key, JSON.stringify(envelope));
    const restored = new RoutingChanges(factory);
    expect(restored.issue()).toBe("invalid");
    expect(restored.snapshot()).toHaveLength(0);
    expect(restored.available(persistentScope)).toBe(false);
  });

  it("bounds the runtime union across external replacement batches without evicting unknown work", async () => {
    const { storage, factory, notify } = environment();
    const changes = new RoutingChanges(factory);
    const unsubscribe = changes.subscribe(() => {});
    const id = (number: number) =>
      Buffer.from(new Uint8Array(16).fill(number)).toString("base64url");
    const initial: { scope: Scope; token: object }[] = [];
    for (let index = 0; index < 32; index++) {
      const scope = { ...persistentScope, peer: id(index + 10) };
      const token = (await changes.begin(scope, persistentIntent))!;
      changes.fail(token, new ApiError("network"));
      changes.release(token);
      initial.push({ scope, token });
    }
    expect(changes.snapshot()).toHaveLength(32);
    const envelope = JSON.parse(storage.getItem(storage.key(0)!)!);
    const batch = (first: number) => {
      storage.clear();
      for (let index = 0; index < 32; index++) {
        const peer = id(first + index);
        const key = `${persistentScope.administratorId}:${persistentScope.nodeId}:${peer}`;
        const copy = structuredClone(envelope);
        copy.id = crypto.randomUUID();
        copy.key = key;
        copy.value.scope.peer = peer;
        storage.setItem(
          `vproxy.review.v1.routing.${key}`,
          JSON.stringify(copy),
        );
      }
      notify();
    };
    try {
      for (const first of [50, 90]) {
        batch(first);
        await Promise.resolve();
        expect(changes.snapshot()).toHaveLength(32);
        for (const original of initial)
          expect(changes.find(original.scope)?.token).toBe(original.token);
        expect(changes.available({ ...persistentScope, peer: id(first) })).toBe(
          false,
        );
      }
      const original = initial[0];
      changes.observe(original.token, observation(3));
      expect(await changes.continue(original.token, 3)).toBe(true);
      expect(changes.snapshot()).toHaveLength(32);
      expect(changes.find({ ...persistentScope, peer: id(90) })).toMatchObject({
        phase: "unknown",
        restored: true,
      });
      expect(changes.find(initial[1].scope)?.token).toBe(initial[1].token);
      expect(storage.length).toBe(32);
    } finally {
      unsubscribe();
    }
  });
});
