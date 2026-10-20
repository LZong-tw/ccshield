import { probePrivacyFilter } from "./privacy.mjs";

// Picks the privacy detector the daemon scans with. OPF is used once the asset
// store records it as verified for the policy's privacy version; until then the
// signed policy must name the installed regex worker as its fallback, or the
// daemon refuses to start. While on regex, `refresh()` re-reads the store at
// most once per `recheckMs` and swaps OPF in after it passes a live probe, so
// a finished background download takes effect without a restart. An OPF that
// fails to open or probe, at start or mid-run, leaves regex active and is not
// retried until the store changes.
export async function openPrivacyDetector({
  paths,
  assets,
  policy,
  readAssets,
  createPrivacy,
  probe = probePrivacyFilter,
  clock = Date.now,
  recheckMs = 5_000,
  onOpfFailure = () => {},
} = {}) {
  const expected = policy.detectorVersions.privacy;
  const usableOpf = (privacy) => privacy?.state === "verified" && privacy.version === expected;

  const fallback = policy.detectorFallbacks?.privacy;
  const regexAllowed = Boolean(assets.regex) && fallback !== undefined && fallback === assets.regex.version;

  let opf = null;
  let regex = null;
  let failedState = null;
  if (usableOpf(assets.privacy)) {
    try {
      opf = await openOpf(assets.privacy);
    } catch (error) {
      // A record can outlive the files it names (an upgrade whose self-test
      // failed, a pruned store). With a signed fallback that is a degraded
      // start, not a refusal; the same record is not retried until it changes.
      if (!regexAllowed) throw error;
      failedState = JSON.stringify(assets.privacy);
      try { onOpfFailure(error); } catch {}
    }
  }
  if (!opf) {
    if (!regexAllowed) throw new Error("shield privacy version does not match policy metadata");
    regex = await createPrivacy({ provision: { privacy: assets.regex } });
    if (regex?.version !== fallback) {
      regex?.close?.();
      throw new Error("shield privacy version does not match policy metadata");
    }
  }

  let closed = false;
  let upgrading = null;
  let lastCheck = clock();
  const current = () => opf ?? regex;

  async function openOpf(privacy) {
    const filter = await createPrivacy({ provision: { privacy } });
    if (filter?.version !== expected) {
      filter?.close?.();
      throw new Error("shield privacy version does not match policy metadata");
    }
    return filter;
  }

  const upgrade = async () => {
    const next = await readAssets({ paths });
    if (!usableOpf(next?.privacy)) return;
    const signature = JSON.stringify(next.privacy);
    if (signature === failedState) return;
    let filter = null;
    try {
      filter = await openOpf(next.privacy);
      await probe(filter, { opf: true });
    } catch (error) {
      failedState = signature;
      filter?.close?.();
      throw error;
    }
    if (closed) {
      filter.close?.();
      return;
    }
    // The regex worker stays up: requests keyed to it before the swap still
    // finish on the detector their cache key and audit record name.
    opf = filter;
  };

  return Object.freeze({
    refresh() {
      if (closed || opf || upgrading || clock() - lastCheck < recheckMs) return upgrading ?? undefined;
      lastCheck = clock();
      upgrading = upgrade()
        .catch((error) => { try { onOpfFailure(error); } catch {} })
        .finally(() => { upgrading = null; });
      return upgrading;
    },
    detectorVersions() {
      return { ...policy.detectorVersions, privacy: current().version };
    },
    async scan(body, { signal, version } = {}) {
      const filter = version === undefined ? current()
        : version === opf?.version ? opf
          : version === regex?.version ? regex
            : null;
      if (!filter) throw new Error("shield privacy detector is unavailable");
      return await filter.scan(body, { signal });
    },
    async isReady() {
      return Boolean(await current().isReady?.() ?? true);
    },
    recentScans: () => current().recentScans?.() ?? [],
    scanTotals: () => current().scanTotals?.() ?? null,
    async close() {
      closed = true;
      await Promise.allSettled([opf?.close?.(), regex?.close?.()]);
    },
  });
}
