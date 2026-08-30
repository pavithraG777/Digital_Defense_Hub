/**
 * Only honor in-app return locations captured by the route guard.  This
 * prevents a sign-in flow from being used as an open redirect.
 */
export function safeReturnTo(value: unknown, fallback = "/dashboard"): string {
  if (
    typeof value === "string"
    && value.startsWith("/")
    && !value.startsWith("//")
    && !value.startsWith("/login")
    && !value.startsWith("/mfa")
    && !value.startsWith("/password-recovery")
    && !value.startsWith("/reset-password")
  ) {
    return value;
  }

  return fallback;
}
