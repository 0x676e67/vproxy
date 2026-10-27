/** Test-only JSON transport fixtures; production entry points do not import this module. */
export const sessionFixture = (username = "operator") => ({
  administrator: { id: "A".repeat(22), username },
  csrf_token: "B".repeat(43),
  expires_at: 1_800_000_000,
});
export const jsonResponse = (value: unknown, status = 200) =>
  new Response(JSON.stringify(value), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8" },
  });
