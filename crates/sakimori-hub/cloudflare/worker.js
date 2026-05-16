// Cloudflare Worker shim that fronts the sakimori-hub container.
//
// The class extends `Container` from `@cloudflare/containers`, which
// owns the lifecycle (start, sleep, restart, port detection, request
// streaming) so we only have to declare per-class config and a
// dispatcher in `fetch`. See:
//   https://developers.cloudflare.com/containers/
//
// Three responsibilities:
//   1. Tell the runtime what port the container listens on.
//   2. Forward the operator's Worker secrets (notably
//      `SAKIMORI_HUB_INGEST_TOKEN`) into the container process
//      env, since Worker `env` and container process env are
//      otherwise separate worlds.
//   3. Route every incoming Worker request to a singleton
//      instance — sakimori-hub is single-writer by design.

import { Container, getContainer } from "@cloudflare/containers";

export class SakimoriHubContainer extends Container {
  // Container listens on $PORT (defaults to 8080 in the Dockerfile).
  defaultPort = 8080;
  // Idle timeout. Containers cold-start when a request lands after
  // sleep; the background dispatcher loop inside the hub does NOT
  // count as "in use" once the Worker isn't being hit, so a long
  // sleep means notifications stall. Keep short.
  sleepAfter = "5m";

  // Per-instance env. `this.env` is the Worker env (vars + secrets);
  // `this.envVars` is what gets injected into the container process.
  // Filtering explicitly avoids leaking unrelated Worker secrets
  // into the container process — only the ones sakimori-hub knows
  // how to consume should cross the boundary.
  constructor(state, env) {
    super(state, env);
    this.envVars = {
      RUST_LOG: env.RUST_LOG ?? "info",
      SAKIMORI_HUB_INGEST_TOKEN: env.SAKIMORI_HUB_INGEST_TOKEN ?? "",
    };
  }
}

export default {
  async fetch(request, env) {
    // Stable singleton id so every request hits the same container
    // instance. When the hub eventually gains multi-instance
    // support, switch to `getContainer(env.HUB, <tenant-id>)`.
    const container = getContainer(env.HUB, "singleton");
    try {
      return await container.fetch(request);
    } catch (err) {
      return new Response(
        JSON.stringify({ error: "container unavailable", detail: String(err) }),
        { status: 502, headers: { "content-type": "application/json" } },
      );
    }
  },
};
