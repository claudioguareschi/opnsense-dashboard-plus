/*
 * The per-user map options: one set of defaults for the dashboard widget and the map page, and
 * one parser for the values the dashboard stores (strings from the options dialog).
 */
export const DEFAULT_OPTIONS = {
  heavyTop: 5, heavyRate: 1000000, maxArcs: 100, labels: true, hostnames: false, asn: true, blocks: true,
  blockMin: 3, colorMode: 'initiator', follow: false,
};

/** The options dialog's values ("5", "0", "1") as renderer settings, defaults for anything unset. */
export function parseSettings(config = {}) {
  const number = (value, fallback) => {
    const parsed = parseInt(value, 10);
    return Number.isFinite(parsed) ? parsed : fallback;
  };
  return {
    heavyTop: number(config.heavy_top, DEFAULT_OPTIONS.heavyTop),
    heavyRate: number(config.heavy_rate, DEFAULT_OPTIONS.heavyRate),
    maxArcs: number(config.max_arcs, DEFAULT_OPTIONS.maxArcs),
    labels: config.labels !== '0',
    hostnames: config.hostnames === '1',
    asn: config.asn !== '0',
    blocks: config.blocks !== '0',
    blockMin: number(config.block_min, DEFAULT_OPTIONS.blockMin) || DEFAULT_OPTIONS.blockMin,
    follow: config.follow === '1',
  };
}

/** The snapshot request for these settings: the viewer's block threshold and reverse DNS choice. */
export function snapshotQuery(settings) {
  return `?blocks_min=${settings.blockMin ?? DEFAULT_OPTIONS.blockMin}${settings.hostnames ? '&hostnames=1' : ''}`;
}
