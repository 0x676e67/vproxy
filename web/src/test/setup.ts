import { beforeEach } from "vitest";
import { createTestLocks } from "./web-locks";

// Most suites intentionally run in Node. Do not add a browser, storage or
// navigator to that environment just to make browser-only code appear usable.
if (typeof window !== "undefined") {
  if (!window.navigator.locks) {
    Object.defineProperty(window.navigator, "locks", {
      configurable: true,
      value: createTestLocks(),
    });
  }
  beforeEach(() => {
    window.localStorage.clear();
  });
}
