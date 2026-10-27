import { describe, expect, it } from "vitest";
import {
  AlertAcknowledgements,
  type AckIntent,
} from "./alert-acknowledgements";
import {
  ReviewJournal,
  JOURNAL_PREFIX,
  type JournalEnvironment,
  type JournalFactory,
} from "./review-journal";
import { createTestLocks, createTestStorage } from "../test/web-locks";

const intent = (episodeId = "1"): AckIntent => ({
  administratorId: "AAECAwQFBgcICQoLDA0ODw",
  nodeId: "EBESExQVFhcYGRobHB0eHw",
  episodeId,
  transitionSequence: String(BigInt(episodeId) + 2n),
});
function harness() {
  const storage = createTestStorage(),
    locks = createTestLocks(),
    listeners = new Set<() => void>();
  const environment: JournalEnvironment = {
    storage: () => storage,
    locks,
    listen: (listener) => {
      listeners.add(listener);
      return () => {
        listeners.delete(listener);
      };
    },
  };
  const factory: JournalFactory = (namespace, codec) =>
    new ReviewJournal(namespace, codec, environment);
  const drained = (value: AckIntent) =>
    locks.request(
      `${JOURNAL_PREFIX}alerts.scope:${value.administratorId}:${value.nodeId}:${value.episodeId}`,
      () => {},
    );
  return {
    storage,
    factory,
    drained,
    changed: () => listeners.forEach((listener) => listener()),
  };
}
describe("original episode acknowledgement review ownership", () => {
  it("writes only original non-secret assertions, restores unknown and never lets late success clear it", async () => {
    const test = harness(),
      first = new AlertAcknowledgements(test.factory),
      value = intent();
    const token = await first.begin(value, () => true);
    expect(token).not.toBeNull();
    const stored = JSON.stringify(test.storage);
    expect(stored).toContain("transitionSequence");
    expect(stored).not.toMatch(/password|csrf|observation|payload|secret/);
    first.unknown(token!);
    expect(first.complete(token!)).toBe(false);
    expect(await first.reviewed(token!, () => true)).toBe(false);
    first.release(token!);
    await test.drained(value);
    const restored = new AlertAcknowledgements(test.factory),
      row = restored.find(value)!;
    expect(row.phase).toBe("unknown");
    expect(row.intent).toEqual(value);
    expect(await restored.begin(value, () => true)).toBeNull();
    expect(await restored.reviewed(row.token, () => false)).toBe(false);
    expect(await restored.reviewed(row.token, () => true)).toBe(true);
    expect(restored.snapshot()).toEqual([]);
  });
  it("holds the cooperative lease until the actual owner releases and fences a superseded pre-dispatch guard", async () => {
    const test = harness(),
      left = new AlertAcknowledgements(test.factory),
      right = new AlertAcknowledgements(test.factory);
    const token = await left.begin(intent(), () => true);
    expect(await right.begin(intent(), () => true)).toBeNull();
    left.unknown(token!);
    expect(await right.begin(intent(), () => true)).toBeNull();
    left.release(token!);
    await test.drained(intent());
    expect(right.find(intent())?.phase).toBe("unknown");
    expect(await right.begin(intent("2"), () => false)).toBeNull();
    expect(right.find(intent("2"))).toBeNull();
  });
  it("bounds retained in-memory unknown notes across external replacement batches without silently dropping old uncertainty", async () => {
    const test = harness(),
      first = new AlertAcknowledgements(test.factory);
    first.subscribe(() => {});
    for (let number = 1; number <= 32; number++) {
      const value = intent(String(number)),
        token = await first.begin(value, () => true);
      first.unknown(token!);
      first.release(token!);
      await test.drained(value);
    }
    test.storage.clear();
    const other = new AlertAcknowledgements(test.factory);
    for (let number = 33; number <= 64; number++) {
      const value = intent(String(number)),
        token = await other.begin(value, () => true);
      other.unknown(token!);
      other.release(token!);
      await test.drained(value);
    }
    test.changed();
    await Promise.resolve();
    expect(first.snapshot()).toHaveLength(32);
    expect(first.find(intent("1"))?.phase).toBe("unknown");
    expect(first.find(intent("33"))).toBeNull();
    expect(await first.begin(intent("65"), () => true)).toBeNull();
    expect(
      await first.reviewed(first.find(intent("1"))!.token, () => true),
    ).toBe(true);
    expect(first.snapshot()).toHaveLength(32);
    expect(first.find(intent("33"))?.phase).toBe("unknown");
  });
});
