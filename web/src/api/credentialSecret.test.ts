import { describe, expect, it, vi } from "vitest";
import {
  credentialSecret,
  credentialSecretInput,
  targetCredentialSecretInput,
} from "./credentialSecret";
import { ManagementClient } from "./client";
import { jsonResponse } from "./client.fixtures";
import { endpointStatus, type ProxyCredential } from "./proxy";

const credential: ProxyCredential = {
  id: "A".repeat(22),
  user_id: "B".repeat(21) + "A",
  login: "vp2_" + "0".repeat(32),
  syntax_version: 2,
  active: true,
  revoked: false,
  verifier_revision: "1",
};
const input = {
  expected_node_id: "C".repeat(21) + "A",
  controller_epoch: "1",
  verifier_revision: "1",
};
const output = {
  credential_id: credential.id,
  user_id: credential.user_id,
  verifier_revision: "1",
  secret: "D".repeat(42) + "A",
};

describe("current credential secret", () => {
  it("binds remote disclosure to the inspected target, user and registration without fallback", async () => {
    const selected = {
      ...input,
      expected_target_revision: "3",
      user_id: credential.user_id,
    };
    for (const patch of [
      { user_id: "wrong" },
      { expected_target_revision: "01" },
      { extra: "forbidden" },
    ]) {
      expect(() =>
        targetCredentialSecretInput({ ...selected, ...patch }),
      ).toThrow();
    }
    const fetcher = vi
      .fn<typeof fetch>()
      .mockResolvedValue(jsonResponse(output));
    const client = new ManagementClient(fetcher, () => true);
    const signal = new AbortController().signal;
    await expect(
      client.targetCredentialSecret(
        input.expected_node_id,
        credential,
        selected,
        "csrf",
        signal,
      ),
    ).resolves.toEqual(output);
    const path = `/targets/${input.expected_node_id}/proxy/credentials/${credential.id}/secret`;
    expect(fetcher.mock.calls[0]).toMatchObject([
      `/api/v1${path}`,
      {
        method: "POST",
        credentials: "same-origin",
        cache: "no-store",
        signal,
        headers: { "X-CSRF-Token": "csrf" },
        body: JSON.stringify(targetCredentialSecretInput(selected)),
      },
    ]);
    for (const method of ["GET", "PUT"] as const)
      expect(() => endpointStatus(path, method)).toThrow();
    expect(() => endpointStatus(`${path}?secret=forbidden`, "POST")).toThrow();
    for (const changed of [
      { ...selected, user_id: input.expected_node_id },
      { ...selected, expected_node_id: credential.user_id },
      { ...selected, verifier_revision: "2" },
    ]) {
      await expect(
        client.targetCredentialSecret(
          input.expected_node_id,
          credential,
          changed,
          "csrf",
          signal,
        ),
      ).rejects.toThrow();
    }
    expect(fetcher).toHaveBeenCalledTimes(1);
    fetcher.mockResolvedValueOnce(
      jsonResponse({ error: { code: "node_protocol_unsupported" } }, 502),
    );
    await expect(
      client.targetCredentialSecret(
        input.expected_node_id,
        credential,
        selected,
        "csrf",
        signal,
      ),
    ).rejects.toMatchObject({ code: "node_protocol_unsupported" });
    expect(fetcher).toHaveBeenCalledTimes(2);
  });
  it("rejects substituted identities, generations, unknown fields and noncanonical secrets", () => {
    expect(credentialSecret(output, credential)).toEqual(output);
    for (const patch of [
      { credential_id: input.expected_node_id },
      { user_id: input.expected_node_id },
      { verifier_revision: "2" },
      { secret: "wrong" },
      { extra: "forbidden" },
    ])
      expect(() =>
        credentialSecret({ ...output, ...patch }, credential),
      ).toThrow();
    for (const patch of [
      { expected_node_id: "invalid" },
      { controller_epoch: "01" },
      { verifier_revision: "0" },
      { password: "forbidden" },
    ]) {
      expect(() => credentialSecretInput({ ...input, ...patch })).toThrow();
    }
  });
  it("uses an explicit Session/CSRF POST without secrets in its path or request", async () => {
    const fetcher = vi
      .fn<typeof fetch>()
      .mockResolvedValue(jsonResponse(output));
    const client = new ManagementClient(fetcher, () => true);
    await expect(
      client.credentialSecret(
        credential,
        input,
        "csrf",
        new AbortController().signal,
      ),
    ).resolves.toEqual(output);
    expect(fetcher.mock.calls).toHaveLength(1);
    expect(fetcher.mock.calls[0]).toMatchObject([
      `/api/v1/proxy/credentials/${credential.id}/secret`,
      {
        method: "POST",
        credentials: "same-origin",
        cache: "no-store",
        headers: { "X-CSRF-Token": "csrf" },
        body: JSON.stringify(input),
      },
    ]);
    for (const method of ["GET", "PUT"] as const)
      expect(() =>
        endpointStatus(`/proxy/credentials/${credential.id}/secret`, method),
      ).toThrow();
    expect(() =>
      endpointStatus(
        `/proxy/credentials/${credential.id}/secret?secret=forbidden`,
        "POST",
      ),
    ).toThrow();
    await expect(
      client.credentialSecret(
        { ...credential, revoked: true },
        input,
        "csrf",
        new AbortController().signal,
      ),
    ).rejects.toThrow();
    expect(fetcher.mock.calls).toHaveLength(1);
  });
});
