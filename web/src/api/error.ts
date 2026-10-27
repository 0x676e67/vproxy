export class ApiError extends Error {
  constructor(
    readonly kind: "https" | "network" | "format" | "server",
    readonly code?: string,
    readonly status?: number,
  ) {
    super("Management request failed");
    this.name = "ApiError";
  }
}

export const authenticationRequired = (error: unknown): boolean =>
  error instanceof ApiError &&
  (error.status === 401 || error.status === 403) &&
  error.code === "authentication_required";

/** Never include transport messages, response bodies or one-time secrets. */
export const apiError = (error: unknown): ApiError =>
  error instanceof ApiError ? error : new ApiError("network");
