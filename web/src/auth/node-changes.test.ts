import { describe, expect, it, vi } from "vitest";
import { ApiError } from "../api/error";
import { drainFixture } from "../api/runtime.fixtures";
import { serviceInput } from "../api/proxyService.fixtures";
import type { Owner, Target } from "../api/targets";
import { createTestLocks, createTestStorage } from "../test/web-locks";
import {
  NodeChanges,
  type Intent,
  type Observation,
  type Scope,
} from "./node-changes";
import {
  JOURNAL_PREFIX,
  ReviewJournal,
  type JournalEnvironment,
  type JournalFactory,
} from "./review-journal";

const scope: Scope = { administratorId: "administrator-a", nodeId: "local-a" };
const intent: Intent = {
  kind: "target",
  action: "configure",
  targetId: "target-a",
  expectedRevision: "3",
};
const owner: Owner = {
  controller_node_id: null,
  epoch: "2",
  last_terminal_command: "0",
};
const target: Target = {
  node_id: "target-a",
  name: "Test node",
  origin: "https://target.example",
  server_ip: null,
  active: true,
  retired: false,
  revision: "4",
  observed_epoch: null,
  observed_command: null,
  observed_policy_revision: null,
  rollback_detected: false,
};
const observation = (generation: number): Observation => ({
  generation,
  owner,
  target,
});

describe("in-memory node changes", () => {
  it("claims a scope synchronously and keeps a stable snapshot until a real change", async () => {
    const changes = new NodeChanges();
    const listener = vi.fn();
    const unsubscribe = changes.subscribe(listener);
    const empty = changes.snapshot();
    expect(changes.find(scope)).toBeNull();
    expect(changes.available(scope)).toBe(true);
    expect(changes.snapshot()).toBe(empty);
    const beginning = changes.begin(scope, intent);
    expect(changes.find(scope)?.phase).toBe("pending");
    const token = await beginning;
    expect(token).not.toBeNull();
    const claimed = changes.snapshot();
    expect(claimed).not.toBe(empty);
    expect(changes.find(scope)).toMatchObject({
      token,
      scope,
      intent,
      phase: "pending",
    });
    expect(changes.available(scope)).toBe(false);
    expect(await changes.begin(scope, intent)).toBeNull();
    expect(changes.observe(token!, observation(1))).toBe(false);
    expect(await changes.continue(token!, 1)).toBe(false);
    expect(changes.invalidateObservation(token!)).toBe(false);
    expect(changes.snapshot()).toBe(claimed);
    expect(listener).toHaveBeenCalledTimes(1);
    unsubscribe();
    expect(changes.notStarted(token!)).toBe(true);
    expect(listener).toHaveBeenCalledTimes(1);
    expect(changes.available(scope)).toBe(true);
  });

  it("preserves the first failure and cannot be cleared by a late success or not-started report", async () => {
    const changes = new NodeChanges();
    const token = (await changes.begin(scope, intent))!;
    const failure = new ApiError("network");
    expect(changes.fail(token, failure)).toBe(true);
    const failed = changes.snapshot();
    expect(changes.find(scope)).toMatchObject({
      phase: "unknown",
      observation: null,
    });
    expect(changes.find(scope)?.error).toBeInstanceOf(ApiError);
    expect(changes.find(scope)?.error).not.toBe(failure);
    expect(
      changes.fail(token, new ApiError("server", "invalid_csrf", 403)),
    ).toBe(false);
    expect(changes.succeed(token)).toBe(false);
    expect(changes.notStarted(token)).toBe(false);
    expect(changes.snapshot()).toBe(failed);
  });

  it.each(["invalid_origin", "invalid_csrf", "authentication_required"])(
    "classifies only the reviewed 403 %s guard as rejected, still requiring review",
    async (code) => {
      const changes = new NodeChanges();
      const token = (await changes.begin(scope, intent))!;
      changes.fail(token, new ApiError("server", code, 403));
      expect(changes.find(scope)?.phase).toBe("rejected");
      expect(await changes.continue(token, 2)).toBe(false);
      changes.observe(token, observation(2));
      expect(await changes.continue(token, 2)).toBe(true);
      expect(changes.find(scope)).toBeNull();
    },
  );

  it.each([
    new ApiError("server", "invalid_csrf", 409),
    new ApiError("server", "policy_denied", 403),
    new ApiError("server", "policy_conflict", 409),
    new ApiError("server", "policy_busy", 503),
    new ApiError("format"),
  ])("does not guess an outcome from a generic failure", async (error) => {
    const changes = new NodeChanges();
    const token = (await changes.begin(scope, intent))!;
    changes.fail(token, error);
    expect(changes.find(scope)?.phase).toBe("unknown");
  });

  it("requires a fresh observation in the caller's generation and never replays work", async () => {
    const changes = new NodeChanges();
    const token = (await changes.begin(scope, intent))!;
    changes.fail(token, new ApiError("network"));
    expect(await changes.continue(token, 1)).toBe(false);
    expect(changes.observe(token, observation(1))).toBe(true);
    expect(await changes.continue(token, 2)).toBe(false);
    expect(changes.invalidateObservation(token)).toBe(true);
    expect(await changes.continue(token, 1)).toBe(false);
    expect(changes.observe(token, observation(2))).toBe(true);
    expect(await changes.continue(token, 1)).toBe(false);
    expect(await changes.continue(token, 2)).toBe(true);
    expect(changes.snapshot()).toEqual([]);
    expect(await changes.begin(scope, intent)).not.toBe(token);
  });

  it("ignores an old or fabricated token after a new attempt claims the same scope", async () => {
    const changes = new NodeChanges();
    const old = (await changes.begin(scope, intent))!;
    expect(changes.succeed(old)).toBe(true);
    const current = (await changes.begin(scope, intent))!;
    const snapshot = changes.snapshot();
    for (const stale of [old, {}]) {
      expect(changes.succeed(stale)).toBe(false);
      expect(changes.notStarted(stale)).toBe(false);
      expect(changes.fail(stale, new ApiError("network"))).toBe(false);
      expect(changes.observe(stale, observation(1))).toBe(false);
      expect(changes.invalidateObservation(stale)).toBe(false);
      expect(await changes.continue(stale, 1)).toBe(false);
    }
    expect(changes.snapshot()).toBe(snapshot);
    expect(changes.find(scope)?.token).toBe(current);
    expect(changes.find(scope)?.phase).toBe("pending");
  });

  it("isolates different administrators and local nodes, including owner intents", async () => {
    const changes = new NodeChanges();
    const otherAdministrator = { ...scope, administratorId: "administrator-b" };
    const otherNode = { ...scope, nodeId: "local-b" };
    const first = (await changes.begin(scope, intent))!;
    const second = (await changes.begin(otherAdministrator, intent))!;
    const third = (await changes.begin(otherNode, {
      kind: "owner",
      action: "takeover",
      controllerId: null,
      expectedEpoch: "2",
    }))!;
    changes.fail(first, new ApiError("network"));
    expect(changes.find(scope)?.phase).toBe("unknown");
    expect(changes.find(otherAdministrator)).toMatchObject({
      token: second,
      phase: "pending",
    });
    expect(changes.find(otherNode)).toMatchObject({
      token: third,
      phase: "pending",
    });
    changes.succeed(second);
    expect(changes.find(scope)?.token).toBe(first);
    expect(changes.find(otherNode)?.token).toBe(third);
  });

  it("owns immutable copies of scope, intent and observed metadata", async () => {
    const changes = new NodeChanges();
    const inputScope = { ...scope };
    const inputIntent = { ...intent };
    const token = (await changes.begin(inputScope, inputIntent))!;
    inputScope.nodeId = "changed";
    inputIntent.targetId = "changed";
    changes.fail(token, new ApiError("network"));
    const readOwner = { ...owner };
    const readTarget = { ...target };
    changes.observe(token, {
      generation: 1,
      owner: readOwner,
      target: readTarget,
    });
    readOwner.epoch = "99";
    readTarget.origin = "https://changed.example";
    const record = changes.find(scope)!;
    expect(record.intent).toEqual(intent);
    expect(record.observation).toEqual(observation(1));
    expect(Object.isFrozen(changes.snapshot())).toBe(true);
    expect(Object.isFrozen(record)).toBe(true);
    expect(Object.isFrozen(record.scope)).toBe(true);
    expect(Object.isFrozen(record.intent)).toBe(true);
    expect(Object.isFrozen(record.observation)).toBe(true);
    expect(Object.isFrozen(record.observation?.owner)).toBe(true);
    expect(Object.isFrozen(record.observation?.target)).toBe(true);
  });

  it("bounds cold scopes at 32 without evicting an unresolved attempt", async () => {
    const changes = new NodeChanges();
    const unresolved = (await changes.begin(scope, intent))!;
    changes.fail(unresolved, new ApiError("network"));
    const tokens = await Promise.all(
      Array.from({ length: 31 }, (_, index) =>
        changes.begin({ ...scope, nodeId: `local-${index + 1}` }, intent),
      ),
    );
    expect(tokens.every((token) => token !== null)).toBe(true);
    const full = changes.snapshot();
    const fresh = { ...scope, nodeId: "new-local" };
    expect(changes.available(fresh)).toBe(false);
    expect(await changes.begin(fresh, intent)).toBeNull();
    expect(changes.snapshot()).toBe(full);
    expect(changes.find(scope)?.token).toBe(unresolved);
    expect(changes.find(scope)?.phase).toBe("unknown");
    expect(changes.succeed(tokens[0]!)).toBe(true);
    expect(changes.available(fresh)).toBe(true);
    expect(await changes.begin(fresh, intent)).not.toBeNull();
    expect(changes.snapshot()).toHaveLength(32);
    expect(changes.find(scope)?.token).toBe(unresolved);
  });
});

const durableScope: Scope = {
  administratorId: "A".repeat(22),
  nodeId: "AQEBAQEBAQEBAQEBAQEBAQ",
};
const durableIntent: Intent = {
  kind: "target",
  action: "configure",
  targetId: "AgICAgICAgICAgICAgICAg",
  expectedRevision: "3",
};

function journalFixture() {
  const storage = createTestStorage();
  const locks = createTestLocks();
  const listeners = new Set<() => void>();
  let unavailable = false;
  const environment: JournalEnvironment = {
    storage: () => {
      if (unavailable) throw new Error("Synthetic storage unavailable");
      return storage;
    },
    locks,
    listen: (listener) => {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
  };
  const factory: JournalFactory = (namespace, codec) =>
    new ReviewJournal(namespace, codec, environment);
  const name = (value: Scope) =>
    `${JOURNAL_PREFIX}nodes.${value.administratorId}:${value.nodeId}`;
  return {
    factory,
    storage,
    listeners,
    name,
    failStorage: () => {
      unavailable = true;
    },
    external: () => listeners.forEach((listener) => listener()),
    // Wait for the actual lock owner's finally, not an arbitrary timer.
    drained: (value: Scope = durableScope) =>
      locks.request(
        `${JOURNAL_PREFIX}nodes.scope:${value.administratorId}:${value.nodeId}`,
        () => {},
      ),
    locks,
  };
}

describe("persistent node review notes", () => {
  it("restores only the exact service operation, refuses altered nodes and payloads, and never grants replay", async () => {
    const journal = journalFixture();
    const model = new NodeChanges(journal.factory);
    const { configuration: _, ...operation } = serviceInput();
    const serviceScope = {
      ...durableScope,
      nodeId: operation.expected_node_id,
    };
    const intent: Intent = { kind: "proxy-service", operation };
    const token = (await model.begin(serviceScope, intent))!;
    expect(model.runtimeAccepted(token)).toBe(false);
    expect(model.serviceAccepted(token)).toBe(true);
    model.release(token);
    await journal.drained();
    const restored = new NodeChanges(journal.factory),
      note = restored.find(serviceScope)!;
    expect(note).toMatchObject({
      phase: "unknown",
      restored: true,
      observation: null,
      intent,
    });
    expect(await restored.continue(note.token, 1)).toBe(false);
    const key = journal.name(serviceScope),
      raw = journal.storage.getItem(key)!;
    expect(raw).not.toMatch(/configuration|listeners|password|csrf/);
    const parsed = JSON.parse(raw);
    parsed.value.intent.operation.configuration = serviceInput().configuration;
    journal.storage.setItem(key, JSON.stringify(parsed));
    expect(new NodeChanges(journal.factory).issue()).toBe("invalid");
  });
  it("retains only the original runtime drain identity, restores unknown and cannot mistake it for an owner or maintenance ticket", async () => {
    const journal = journalFixture(),
      model = new NodeChanges(journal.factory);
    const runtime: Intent = {
      kind: "runtime-drain",
      targetId: durableIntent.targetId,
      targetRevision: "4",
      request: { ...drainFixture(), expected_node_id: durableIntent.targetId },
    };
    const token = (await model.begin(durableScope, {
      ...runtime,
      secret: "not-stored",
      url: "https://not-stored.example",
    } as Intent))!;
    expect(model.runtimeAccepted(token)).toBe(true);
    expect(model.maintenanceTicket(token, durableIntent.targetId)).toBe(false);
    expect(model.succeed(token)).toBe(false);
    const raw = journal.storage.getItem(journal.name(durableScope))!;
    expect(raw).not.toMatch(/secret|url|not-stored|observation|error/);
    const restored = new NodeChanges(journal.factory),
      note = restored.find(durableScope)!;
    expect(note).toMatchObject({
      phase: "unknown",
      restored: true,
      observation: null,
      intent: runtime,
    });
    expect(await restored.continue(note.token, 1)).toBe(false);
    model.release(token);
    await journal.drained();
    const parsed = JSON.parse(raw);
    parsed.value.intent.request.password = "forbidden";
    journal.storage.setItem(journal.name(durableScope), JSON.stringify(parsed));
    expect(new NodeChanges(journal.factory).issue()).toBe("invalid");
  });
  it("retains a bounded maintenance intent and only its first delivered ticket, never a payload or later observation", async () => {
    const journal = journalFixture();
    const model = new NodeChanges(journal.factory);
    const maintenance: Extract<Intent, { kind: "maintenance" }> = {
      kind: "maintenance",
      targetId: durableIntent.targetId,
      accepting: false,
      expectedRevision: "3",
      expectedEpoch: "2",
      targetRevision: "4",
      commandId: "5",
      jobId: null,
    };
    const token = (await model.begin(durableScope, {
      ...maintenance,
      password: "not-for-storage",
      body: { accepting: true },
    } as Intent))!;
    const id = "AwMDAwMDAwMDAwMDAwMDAw";
    expect(model.maintenanceTicket(token, id)).toBe(true);
    expect(model.maintenanceTicket(token, durableIntent.targetId)).toBe(false);
    expect(model.find(durableScope)?.intent).toEqual({
      ...maintenance,
      jobId: id,
    });
    expect(model.find(durableScope)?.phase).toBe("unknown");
    expect(model.succeed(token)).toBe(false);
    const raw = journal.storage.getItem(journal.name(durableScope))!;
    expect(raw).not.toMatch(/password|body|not-for-storage|observation|error/);
    const recovered = new NodeChanges(journal.factory);
    const note = recovered.find(durableScope)!;
    expect(note).toMatchObject({
      intent: { ...maintenance, jobId: id },
      phase: "unknown",
      observation: null,
      restored: true,
    });
    expect(await recovered.continue(note.token, 1)).toBe(false);
    model.release(token);
    await journal.drained();
    recovered.observe(note.token, observation(1));
    expect(await recovered.continue(note.token, 1)).toBe(true);
    expect(journal.storage.getItem(journal.name(durableScope))).toBeNull();
  });
  it("restores only non-secret intent with a new token and requires a fresh acknowledgement", async () => {
    const journal = journalFixture();
    const changes = new NodeChanges(journal.factory);
    const token = await changes.begin(durableScope, {
      ...durableIntent,
      payload: {
        password: "not-for-storage",
        origin: "https://private.example",
      },
      csrf: "not-for-storage",
    } as Intent);
    expect(token).not.toBeNull();
    try {
      const raw = journal.storage.getItem(journal.name(durableScope))!;
      expect(JSON.parse(raw).value).toEqual({
        scope: durableScope,
        intent: durableIntent,
        phase: "pending",
      });
      expect(raw).not.toMatch(
        /password|origin|csrf|not-for-storage|observation|error/,
      );
      changes.fail(token!, new ApiError("network"));
      changes.observe(token!, observation(8));
      const restored = new NodeChanges(journal.factory);
      const recovered = restored.find(durableScope)!;
      expect(recovered).toMatchObject({
        scope: durableScope,
        intent: durableIntent,
        phase: "unknown",
        restored: true,
        error: null,
        observation: null,
      });
      expect(recovered.token).not.toBe(token);
      expect(
        restored.find({
          ...durableScope,
          administratorId: "AgICAgICAgICAgICAgICAg",
        }),
      ).toBeNull();
      expect(await restored.continue(recovered.token, 8)).toBe(false);
      restored.observe(recovered.token, observation(9));
      expect(await restored.continue(recovered.token, 9)).toBe(false);
      expect(changes.succeed(token!)).toBe(false);
      expect(changes.notStarted(token!)).toBe(false);
      changes.release(token!);
      await journal.drained();
      expect(await restored.continue(recovered.token, 9, () => false)).toBe(
        false,
      );
      expect(await restored.continue(recovered.token, 9)).toBe(true);
      expect(journal.storage.getItem(journal.name(durableScope))).toBeNull();
      expect(restored.snapshot()).toEqual([]);
    } finally {
      changes.release(token!);
    }
  });

  it("keeps the live lease after abort classification and does not adopt an externally replaced note", async () => {
    const journal = journalFixture();
    const changes = new NodeChanges(journal.factory);
    const otherTab = new NodeChanges(journal.factory);
    const unsubscribe = changes.subscribe(() => {});
    expect(journal.listeners.size).toBe(1);
    const token = await changes.begin(durableScope, durableIntent);
    const otherScope = { ...durableScope, nodeId: "AgICAgICAgICAgICAgICAg" };
    const other = await otherTab.begin(otherScope, durableIntent);
    expect(token).not.toBeNull();
    expect(other).not.toBeNull();
    try {
      expect(await otherTab.begin(durableScope, durableIntent)).toBeNull();
      const recovered = otherTab.find(durableScope)!;
      changes.fail(token!, new ApiError("network"));
      otherTab.observe(recovered.token, observation(1));
      expect(await otherTab.continue(recovered.token, 1)).toBe(false);
      changes.release(token!);
      await journal.drained();
      const name = journal.name(durableScope);
      const replacement = JSON.parse(journal.storage.getItem(name)!);
      replacement.id = "00000000-0000-4000-8000-000000000001";
      replacement.value.intent = { ...durableIntent, action: "pause" };
      journal.storage.setItem(name, JSON.stringify(replacement));
      journal.external();
      await vi.waitFor(() =>
        expect(changes.find(durableScope)?.token).toBe(token),
      );
      expect(changes.find(durableScope)?.intent).toEqual(durableIntent);
      changes.observe(token!, observation(2));
      expect(await changes.continue(token!, 2)).toBe(false);
      expect(JSON.parse(journal.storage.getItem(name)!).id).toBe(
        replacement.id,
      );
      journal.storage.removeItem(name);
      journal.external();
      expect(changes.find(durableScope)?.token).toBe(token);
      expect(changes.available(durableScope)).toBe(false);
    } finally {
      unsubscribe();
      expect(journal.listeners.size).toBe(0);
      changes.release(token!);
      otherTab.notStarted(other!);
      otherTab.release(other!);
    }
  });

  it("refuses dispatch without storage and keeps a successful server result unknown if cleanup cannot persist", async () => {
    const initial = journalFixture();
    const blocked = new NodeChanges(initial.factory);
    initial.failStorage();
    expect(await blocked.begin(durableScope, durableIntent)).toBeNull();
    expect(blocked.snapshot()).toEqual([]);
    expect(blocked.issue()).toBe("unavailable");
    expect(blocked.available(durableScope)).toBe(false);

    const journal = journalFixture();
    const changes = new NodeChanges(journal.factory);
    const token = await changes.begin(durableScope, durableIntent);
    expect(token).not.toBeNull();
    const before = journal.storage.getItem(journal.name(durableScope));
    try {
      journal.failStorage();
      expect(changes.succeed(token!)).toBe(false);
      expect(changes.find(durableScope)).toMatchObject({
        phase: "unknown",
        observation: null,
      });
      expect(changes.issue()).toBe("unavailable");
      expect(journal.storage.getItem(journal.name(durableScope))).toBe(before);
      changes.release(token!);
      expect(changes.find(durableScope)?.phase).toBe("unknown");
    } finally {
      changes.release(token!);
    }
  });

  it("rechecks the session after a queued registry lock before saving or admitting work", async () => {
    const journal = journalFixture();
    const requests = vi.spyOn(journal.locks, "request");
    let release!: () => void;
    let entered!: () => void;
    const holding = new Promise<void>((resolve) => {
      release = resolve;
    });
    const started = new Promise<void>((resolve) => {
      entered = resolve;
    });
    const registry = journal.locks.request(
      `${JOURNAL_PREFIX}nodes.registry`,
      async () => {
        entered();
        await holding;
      },
    );
    await started;
    const changes = new NodeChanges(journal.factory);
    let current = true;
    const beginning = changes.begin(durableScope, durableIntent, () => current);
    expect(changes.find(durableScope)?.phase).toBe("pending");
    try {
      await vi.waitFor(() =>
        expect(
          requests.mock.calls.filter(
            ([name]) => name === `${JOURNAL_PREFIX}nodes.registry`,
          ),
        ).toHaveLength(2),
      );
      current = false;
    } finally {
      release();
      await registry;
    }
    expect(await beginning).toBeNull();
    expect(changes.snapshot()).toEqual([]);
    expect(journal.storage.length).toBe(0);
    expect(changes.issue()).toBeNull();
  });

  it("rejects malformed node metadata without deleting it or recovering a partial intent", async () => {
    const journal = journalFixture();
    const seed = new NodeChanges(journal.factory);
    const token = await seed.begin(durableScope, durableIntent);
    const name = journal.name(durableScope);
    const envelope = JSON.parse(journal.storage.getItem(name)!);
    seed.fail(token!, new ApiError("network"));
    seed.release(token!);
    await journal.drained();
    const malformed = [
      { ...envelope.value, payload: { password: "not-for-storage" } },
      { ...envelope.value, observation: observation(1) },
      { ...envelope.value, scope: { ...durableScope, nodeId: "bad-id" } },
      { ...envelope.value, phase: ["unknown"] },
      {
        ...envelope.value,
        intent: { ...durableIntent, expectedRevision: "03" },
      },
      { ...envelope.value, intent: { ...durableIntent, action: "rotate" } },
      {
        ...envelope.value,
        intent: {
          kind: "owner",
          action: "takeover",
          controllerId: durableIntent.targetId,
          expectedEpoch: "2",
        },
      },
    ];
    for (const value of malformed) {
      const raw = JSON.stringify({ ...envelope, value });
      journal.storage.setItem(name, raw);
      const changes = new NodeChanges(journal.factory);
      expect(changes.snapshot()).toEqual([]);
      expect(changes.issue()).toBe("invalid");
      expect(await changes.begin(durableScope, durableIntent)).toBeNull();
      expect(journal.storage.getItem(name)).toBe(raw);
    }
  });

  it("bounds retained memory across external replacement batches and restores omitted notes only into explicitly freed slots", async () => {
    const journal = journalFixture();
    const changes = new NodeChanges(journal.factory);
    const changed = vi.fn();
    const unsubscribe = changes.subscribe(changed);
    const batch = (offset: number): Scope[] =>
      Array.from({ length: 32 }, (_, index) => ({
        administratorId: durableScope.administratorId,
        nodeId: `${(offset + index).toString(16).padStart(21, "0")}A`,
      }));
    const retain = async (model: NodeChanges, scopes: Scope[]) => {
      for (const scope of scopes) {
        const token = await model.begin(scope, durableIntent);
        expect(token).not.toBeNull();
        try {
          expect(model.fail(token!, new ApiError("network"))).toBe(true);
        } finally {
          model.release(token!);
          await journal.drained(scope);
        }
      }
    };
    const acknowledge = async (model: NodeChanges) => {
      for (const record of [...model.snapshot()]) {
        model.observe(record.token, observation(1));
        expect(await model.continue(record.token, 1)).toBe(true);
      }
    };
    try {
      await retain(changes, batch(0));
      const original = changes.snapshot();
      const otherTab = new NodeChanges(journal.factory);
      await acknowledge(otherTab);
      expect(journal.storage.length).toBe(0);
      for (const offset of [100, 200]) {
        await retain(otherTab, batch(offset));
        const notifications = changed.mock.calls.length;
        journal.external();
        await vi.waitFor(() =>
          expect(changed.mock.calls.length).toBeGreaterThan(notifications),
        );
        expect(changes.snapshot()).toHaveLength(32);
        changes
          .snapshot()
          .forEach((record, index) =>
            expect(record.token).toBe(original[index].token),
          );
        expect(changes.find(batch(offset)[0])).toBeNull();
        expect(changes.available(batch(offset)[0])).toBe(false);
        expect(journal.storage.length).toBe(32);
        if (offset === 100) await acknowledge(otherTab);
      }
      const omitted = batch(200)[0];
      const old = original[0];
      changes.observe(old.token, observation(2));
      expect(await changes.continue(old.token, 2)).toBe(true);
      const restored = changes.find(omitted)!;
      expect(restored).toMatchObject({
        phase: "unknown",
        restored: true,
        error: null,
        observation: null,
      });
      expect(restored.token).not.toBe(old.token);
      expect(restored.token).not.toBe(otherTab.find(omitted)?.token);
      expect(changes.snapshot()).toHaveLength(32);
      expect(journal.storage.length).toBe(32);
      expect(await changes.continue(restored.token, 2)).toBe(false);
      changes.observe(restored.token, observation(3));
      expect(await changes.continue(restored.token, 3)).toBe(true);
      expect(journal.storage.getItem(journal.name(omitted))).toBeNull();
      expect(changes.find(batch(200)[1])).toMatchObject({
        phase: "unknown",
        restored: true,
        observation: null,
      });
      expect(changes.snapshot()).toHaveLength(32);
      expect(journal.storage.length).toBe(31);
    } finally {
      unsubscribe();
    }
  });
});
