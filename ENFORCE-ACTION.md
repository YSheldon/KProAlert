# First Native Action: Switch To Enforcement

The user selected `switch_to_enforce` as the first actual response to implement.
It must use the existing driver's signed SetPolicy path, not a new driver.
**The bound execution channel is candidate-only, not released.** `propose_action` records a request;
`policyMutationAvailable=false` and `aiActionExecutionAvailable=false` remain
truthful until the native flow and its acceptance pass.

## Required Behavior

1. Retrieve a fresh effective-policy snapshot from the authenticated resident
   service. Bind device, service instance, event evidence, policy version/digest
   and a short-lived request ID. An event's decisionMode is event-time data,
   not proof of current policy state.
2. If that verified current policy is already Block, return an explicit no-op.
   Do not replay SetPolicy, reset behavior windows, or report a successful change.
   A reportOnly event in Block can still reflect classification/safety limits;
   repeated mode changes do not remove those limits.
3. Use a server-signed target policy with decisionMode=3. Preserve protected
   objects, operation masks, exceptions and unrelated controls. Do not overwrite
   custom settings with a generic empty-directory maximum template. Any proposed
   risk-block flag increase must be separately shown in the approved change plan.
4. Obtain per-action native user confirmation. AI event text, a recommendation,
   stored request or MCP tool result is not consent.
5. The resident service calls the existing DLL SetPolicy interface and verifies
   the effective result with QueryPolicy and the signed input/snapshot binding.
   A successful function return alone is insufficient.
6. Keep durable effective policy separate from immutable release artifacts.
   Updating package `default-policy.hex` in place would break release hashes.
   Restart, upgrade, failure and rollback must preserve the confirmed policy or
   explicitly report incomplete recovery; never silently return to weaker policy.
7. Return a trusted outcome: changed-and-verified, already-enforced-noop,
   rejected/cancelled, or failed/uncertain. Only the native result may be called
   execution; return AI advice and engine observations separately to operations.

No automatic downgrade to Audit, direct process killing, file deletion,
quarantine or exception creation is authorized by this action.

## Implementation Boundary

The candidate service-local mailbox supports authenticated enforcement and
durable-policy readback. The new request-ID-only native binding still requires
signed end-to-end acceptance before release. See the candidate contract in
[AI-OPERATIONS.md](AI-OPERATIONS.md#candidate-native-action-binding).
No driver/event wire change is required. Do not fabricate a service verb or invoke standalone DLL control
from an untrusted/non-PPL AI process to bypass service authentication.
