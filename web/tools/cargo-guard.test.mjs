import assert from "node:assert/strict";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { cargoOutput, packageContext, selectGuard } from "./cargo-guard.mjs";

function fixture() {
  const root = path.join(os.tmpdir(), "vproxy-cargo-message-fixture");
  const target = path.join(root, "target");
  const packageId = "opaque-current-vproxy-id";
  const source = path.join(root, "build.rs");
  const build = {
    kind: ["custom-build"],
    crate_types: ["bin"],
    name: "build-script-build",
    src_path: source,
  };
  const metadata = {
    version: 1,
    target_directory: target,
    workspace_members: [packageId],
    packages: [
      {
        id: packageId,
        name: "vproxy",
        source: null,
        manifest_path: path.join(root, "Cargo.toml"),
        targets: [build],
      },
    ],
  };
  const name = `build-script-build${process.platform === "win32" ? ".exe" : ""}`;
  const executable = path.join(
    target,
    "debug/build/vproxy-compile-output",
    name,
  );
  const artifact = {
    reason: "compiler-artifact",
    package_id: packageId,
    manifest_path: path.join(root, "Cargo.toml"),
    target: build,
    features: ["management", "userspace", "web-ui"],
    profile: { test: false },
    fresh: false,
    executable: null,
    filenames: [
      executable,
      path.join(path.dirname(executable), "build_script_build.pdb"),
    ],
  };
  const execution = {
    reason: "build-script-executed",
    package_id: packageId,
    out_dir: path.join(target, "debug/build/vproxy-run-output/out"),
  };
  const finished = { reason: "build-finished", success: true };
  return {
    root,
    metadata,
    executable,
    artifact,
    execution,
    finished,
    messages: [artifact, execution, finished],
    context: packageContext(metadata, root),
  };
}

test("current invocation selects filenames, permits cached records and distinct run directory", () => {
  const value = fixture();
  for (const fresh of [false, true]) {
    value.artifact.fresh = fresh;
    assert.equal(
      selectGuard(value.context, value.messages, 0),
      value.executable,
    );
  }
  const foreign = structuredClone(value.artifact);
  foreign.package_id = "some-other-package";
  foreign.filenames = [path.join(value.root, "unrelated-program")];
  assert.equal(
    selectGuard(value.context, [foreign, ...value.messages], 0),
    value.executable,
  );
});

test("successful build is insufficient when cargo tests fail or control records conflict", () => {
  const value = fixture();
  assert.throws(() => selectGuard(value.context, value.messages, 101));
  assert.throws(() =>
    selectGuard(value.context, value.messages, null, "SIGTERM"),
  );
  for (const messages of [
    [value.artifact, value.execution],
    [
      value.artifact,
      value.execution,
      { reason: "build-finished", success: false },
    ],
    [value.artifact, value.execution, value.finished, value.finished],
    [value.execution, value.finished],
    [value.artifact, value.finished],
    [value.artifact, value.artifact, value.execution, value.finished],
    [value.artifact, value.execution, value.execution, value.finished],
    [value.finished, value.artifact, value.execution],
  ])
    assert.throws(() => selectGuard(value.context, messages, 0));
});

test("artifact identity, Web features and native output paths fail closed", () => {
  const mutations = [
    (v) => {
      v.artifact.package_id = "different-package";
    },
    (v) => {
      v.artifact.manifest_path = path.join(v.root, "other/Cargo.toml");
    },
    (v) => {
      v.artifact.target.src_path = path.join(v.root, "other.rs");
    },
    (v) => {
      v.artifact.target.kind = ["bin"];
    },
    (v) => {
      v.artifact.features = ["management"];
    },
    (v) => {
      v.artifact.features.push("ebpf");
    },
    (v) => {
      v.artifact.features.push("ebpf-program");
    },
    (v) => {
      v.artifact.profile.test = true;
    },
    (v) => {
      v.artifact.filenames = [path.join(v.root, path.basename(v.executable))];
    },
    (v) => {
      v.artifact.filenames = [v.executable, v.executable];
    },
    (v) => {
      v.artifact.filenames = [
        path.join(path.dirname(v.executable), "other.exe"),
      ];
    },
    (v) => {
      v.artifact.executable = path.join(v.root, "other-program");
    },
    (v) => {
      v.execution.out_dir = path.join(
        v.root,
        "target/debug/build/peer-output/out",
      );
    },
    (v) => {
      v.execution.out_dir = path.join(
        v.root,
        "target/release/build/vproxy-run/out",
      );
    },
  ];
  for (const mutate of mutations) {
    const value = fixture();
    mutate(value);
    assert.throws(() => selectGuard(value.context, value.messages, 0));
  }
});

test("metadata must bind exactly this checkout and its sole custom-build target", () => {
  for (const mutate of [
    (v) => {
      v.metadata.version = 2;
    },
    (v) => {
      v.metadata.packages.push(structuredClone(v.metadata.packages[0]));
    },
    (v) => {
      v.metadata.packages[0].source = "registry+remote";
    },
    (v) => {
      v.metadata.packages[0].name = "peer";
    },
    (v) => {
      v.metadata.workspace_members = [];
    },
    (v) => {
      v.metadata.packages[0].targets.push(
        structuredClone(v.metadata.packages[0].targets[0]),
      );
    },
    (v) => {
      v.metadata.packages[0].targets[0].src_path = path.join(
        v.root,
        "peer/build.rs",
      );
    },
  ]) {
    const value = fixture();
    mutate(value);
    assert.throws(() => packageContext(value.metadata, value.root));
  }
});

test("mixed Cargo output stays visible and test stdout cannot supply later artifacts", () => {
  const value = fixture();
  const visible = [];
  const output = cargoOutput(value.context, (line) => visible.push(line));
  output.line("ordinary build output");
  output.line(
    JSON.stringify({
      reason: "compiler-message",
      message: { rendered: "rendered compiler diagnostic\n" },
    }),
  );
  for (const message of value.messages) output.line(JSON.stringify(message));
  output.line("running 42 tests");
  const forged = JSON.stringify({
    ...value.artifact,
    filenames: ["not-an-artifact"],
  });
  output.line(forged);
  assert.equal(selectGuard(value.context, output.records, 0), value.executable);
  assert.deepEqual(visible, [
    "ordinary build output\n",
    "rendered compiler diagnostic\n",
    "running 42 tests\n",
    `${forged}\n`,
  ]);
});
