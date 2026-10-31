import { readFileSync, readdirSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import * as ts from "typescript";
import { describe, expect, it } from "vitest";
import routes from "../config/routes";
import { ApiError } from "./api/error";
import { resourcesHref, usersHref } from "./api/targets";
import { trafficHref } from "./api/traffic";

const root = dirname(fileURLToPath(import.meta.url));
function sources(directory: string): string[] {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    if (entry.name.startsWith(".")) return [];
    const path = join(directory, entry.name);
    if (entry.isDirectory()) return sources(path);
    return /\.tsx?$/.test(path) && !/\.test\.tsx?$/.test(path) ? [path] : [];
  });
}

describe("fixed internal navigation boundary", () => {
  it("does not feed remote patterns or redirects into the route parser", () => {
    expect(routes.map((route) => route.path)).toEqual([
      "/",
      "/nodes",
      "/users",
      "/service",
      "/traffic",
      "/alerts",
      "/resources",
      "*",
    ]);
    for (const route of routes) {
      expect(route).not.toHaveProperty("routes");
      if ("redirect" in route) expect(route.redirect).toBe("/nodes");
      if ("component" in route)
        expect(route.component).toMatch(/^\.\/[A-Za-z]+$/);
    }
  });

  it("keeps all source navigation literal or behind reviewed canonical-ID helpers", () => {
    let links = 0;
    let projectLinks = 0;
    const serviceLinks: string[] = [];
    const production = sources(root);
    const paths = production.map((path) =>
      relative(root, path).replaceAll("\\", "/"),
    );
    expect(paths).toContain("pages/Alerts/index.tsx");
    expect(paths).not.toContain("pages/Alerts/index.dom.test.tsx");
    for (const path of production) {
      const source = ts.createSourceFile(
        path,
        readFileSync(path, "utf8"),
        ts.ScriptTarget.Latest,
        true,
        ts.ScriptKind.TSX,
      );
      const label = relative(root, path);
      const scopeAdapter =
        label.replaceAll("\\", "/") === "routing/ScopeNavigation.tsx";
      const imports = new Map<string, { name: string; module: string }>();
      for (const statement of source.statements) {
        if (
          !ts.isImportDeclaration(statement) ||
          !ts.isStringLiteral(statement.moduleSpecifier)
        )
          continue;
        const bindings = statement.importClause?.namedBindings;
        if (bindings && ts.isNamedImports(bindings))
          for (const binding of bindings.elements) {
            const name = binding.propertyName?.text ?? binding.name.text;
            expect(name, label).not.toBe("redirect");
            if (name === "useNavigate") {
              expect(scopeAdapter, label).toBe(true);
              expect(statement.moduleSpecifier.text, label).toBe("@umijs/max");
            }
            imports.set(binding.name.text, {
              name,
              module: statement.moduleSpecifier.text,
            });
          }
      }
      const visit = (node: ts.Node) => {
        // This is a deliberate source allowlist, not a claim that an old router
        // dependency has no vulnerabilities. New navigation APIs need review.
        if (ts.isCallExpression(node)) {
          const callee = node.expression.getText(source);
          if (/^(?:navigate|useNavigate)$/.test(callee)) {
            expect(scopeAdapter, label).toBe(true);
            if (callee === "navigate")
              expect(
                node.arguments.map((argument) => argument.getText(source)),
                label,
              ).toEqual(["checked"]);
          }
          expect(callee, label).not.toMatch(
            /^(?:(?:window|globalThis)\.)?open$/,
          );
          expect(callee, label).not.toMatch(
            /(?:^|\.)(?:history\.(?:push|replace)|location\.(?:assign|replace))$/,
          );
        }
        if (
          ts.isBinaryExpression(node) &&
          node.operatorToken.kind === ts.SyntaxKind.EqualsToken
        )
          expect(node.left.getText(source), label).not.toMatch(
            /^(?:(?:window|globalThis|document)\.)?location(?:\.href)?$/,
          );
        if (
          ts.isJsxAttribute(node) &&
          ["to", "href"].includes(node.name.getText(source))
        ) {
          links++;
          const value = node.initializer;
          if (value && ts.isStringLiteral(value)) {
            if (value.text === "https://github.com/0x676e67/vproxy") {
              expect(label.replaceAll("\\", "/")).toBe(
                "components/ProjectLink/index.tsx",
              );
              const attributes = node.parent;
              const tag = attributes.parent;
              expect(
                ts.isJsxOpeningElement(tag) && tag.tagName.getText(source),
              ).toBe("a");
              for (const [name, expected] of [
                ["target", "_blank"],
                ["rel", "noopener noreferrer"],
              ]) {
                const attribute = attributes.properties.find(
                  (property) =>
                    ts.isJsxAttribute(property) &&
                    property.name.getText(source) === name,
                );
                expect(
                  attribute &&
                    ts.isJsxAttribute(attribute) &&
                    attribute.initializer &&
                    ts.isStringLiteral(attribute.initializer) &&
                    attribute.initializer.text,
                ).toBe(expected);
              }
              projectLinks++;
              return;
            }
            expect(["/nodes", "/users", "/service"], label).toContain(
              value.text,
            );
            if (value.text === "/service")
              serviceLinks.push(label.replaceAll("\\", "/"));
          } else {
            expect(value && ts.isJsxExpression(value), label).toBe(true);
            const expression =
              value && ts.isJsxExpression(value) ? value.expression : undefined;
            if (scopeAdapter) {
              expect(expression?.getText(source), label).toBe("href");
              return;
            }
            expect(expression && ts.isCallExpression(expression), label).toBe(
              true,
            );
            const name =
              expression &&
              ts.isCallExpression(expression) &&
              ts.isIdentifier(expression.expression)
                ? expression.expression.text
                : "";
            const imported = imports.get(name);
            expect(
              [
                "trafficHref",
                "usersHref",
                "resourcesHref",
                "alertHistoryHref",
                "scopeHref",
              ],
              label,
            ).toContain(name);
            expect(imported?.name, label).toBe(name);
            expect(imported?.module, label).toBe(
              name === "trafficHref"
                ? "../../api/traffic"
                : name === "alertHistoryHref" || name === "scopeHref"
                  ? "../../routing/scope"
                  : "../../api/targets",
            );
          }
        }
        ts.forEachChild(node, visit);
      };
      visit(source);
    }
    // Includes node setup's reviewed continuation, FirstUse's local-user link,
    // HTTPS stays global; egress alerts and Health IDs use exact Resources links.
    // Historical foreign observations expose one reviewed source-node link.
    // A stopped local connection form also offers its fixed service-page link.
    expect(serviceLinks.sort()).toEqual([
      "components/Connections/ConnectionModal.tsx",
      "pages/Nodes/FirstUse.tsx",
      "pages/Nodes/LiveNodes.tsx",
      "pages/Nodes/LiveNodes.tsx",
      "pages/Users/index.tsx",
    ]);
    expect(projectLinks).toBe(1);
    // The inbox adds three reviewed history links and replaces its old bell
    // link with a native dialog button: net two additional canonical links.
    expect(links).toBe(36);
  });

  it("rejects URL and pattern input before canonical identifiers reach navigation", () => {
    const id = "A".repeat(22);
    expect(usersHref(id)).toBe(`/users?target=${id}`);
    expect(resourcesHref()).toBe("/resources");
    expect(resourcesHref(id)).toBe(`/resources?target=${id}`);
    expect(trafficHref({ kind: "node", id: null }, id)).toBe(
      `/traffic?scope=node&target=${id}`,
    );
    for (const invalid of [
      "https://outside.invalid",
      "//outside.invalid",
      "/:id(.*)*",
      "A".repeat(21) + "B",
      "../users",
      "",
      "?redirect=https://outside.invalid",
    ])
      for (const make of [
        usersHref,
        resourcesHref,
        (peer: string) => trafficHref({ kind: "node", id: null }, peer),
      ])
        expect(() => make(invalid)).toThrow(ApiError);
  });
});
