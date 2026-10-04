/*
* Copyright (C) 2026 Claudio Guareschi <cguareschimd@gmail.com>
* All rights reserved.
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions are met:
*
* 1. Redistributions of source code must retain the above copyright notice,
*    this list of conditions and the following disclaimer.
*
* 2. Redistributions in binary form must reproduce the above copyright
*    notice, this list of conditions and the following disclaimer in the
*    documentation and/or other materials provided with the distribution.
*
* THIS SOFTWARE IS PROVIDED AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
* INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
* AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
* AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
* OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
* SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
* INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
* CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
* ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
* POSSIBILITY OF SUCH DAMAGE.
*/
(function() {
	//#region src/format.js
	function plain(text) {
		return String(text ?? "").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, "\"").replace(/&#0?39;/g, "'").replace(/&amp;/g, "&");
	}
	function escapeHtml(text) {
		return plain(text).replace(/[&<>"']/g, (char) => `&#${char.charCodeAt(0)};`);
	}
	/** "{count} flows" with values filled in; a missing value leaves its placeholder empty. */
	function fill(template, values = {}) {
		return String(template ?? "").replace(/\{(\w+)\}/g, (_, key) => values[key] ?? "");
	}
	/** The singular or plural form of a text table entry: key_one / key_many (or key / key_many). */
	function plural(text, key, count, values = {}) {
		return fill(count === 1 ? text[`${key}_one`] ?? text[key] : text[`${key}_many`] ?? text[key], {
			count,
			...values
		});
	}
	function formatRate(bytes) {
		const units = [
			"B/s",
			"KB/s",
			"MB/s",
			"GB/s"
		];
		let value = bytes || 0;
		let unit = 0;
		while (value >= 1e3 && unit < units.length - 1) {
			value /= 1e3;
			unit++;
		}
		return `${value >= 100 || unit === 0 ? Math.round(value) : value.toFixed(1)} ${units[unit]}`;
	}
	/** "TCP" for display; empty for an entry without a protocol (an old queue row, a bare Suricata event). */
	function protocolLabel(value) {
		return String(value || "").toUpperCase();
	}
	function formatBytes(bytes) {
		return formatRate(bytes || 0).replace("/s", "");
	}
	/** "FWMAP_Spamhaus_DROP" reads as "Spamhaus DROP". */
	function listLabel(name) {
		return plain(name).replace(/^FWMAP_/, "").replace(/_/g, " ");
	}
	/** A rectangular flag from OPNsense's flag-icon stylesheet, where the page loads it. */
	function flagHtml(code, className = "fwmap-flag") {
		return /^[A-Za-z]{2}$/.test(code || "") && document.querySelector("link[href*=\"flag-icon\"]") ? `<span class="flag-icon flag-icon-${code.toLowerCase()} ${className}"></span>` : "";
	}
	/** [address, port] from "192.0.2.1:443", "[2001:db8::1]:443" or a bare address. */
	function splitHostPort(text) {
		const value = String(text ?? "");
		const bracketed = /^\[([^\]]+)\](?::(\d+))?$/.exec(value);
		if (bracketed) return [bracketed[1], bracketed[2] || ""];
		const match = /^([^:]+):(\d+)$/.exec(value);
		return match ? [match[1], match[2]] : [value, ""];
	}
	/** Combine an address and port without making an IPv6 endpoint ambiguous. */
	function hostPort(address, port) {
		if (!port) return String(address ?? "");
		const value = String(address ?? "");
		return value.includes(":") ? `[${value}]:${port}` : `${value}:${port}`;
	}
	/** Display-only local-address classification for saved targets. */
	function privateAddress(value) {
		const address = String(value ?? "").toLowerCase().split("%")[0];
		if (/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.|127\.|169\.254\.)/.test(address)) return true;
		return address === "::1" || /^(fc|fd|fe[89ab])/.test(address);
	}
	//#endregion
	//#region src/options.js
	var DEFAULT_OPTIONS = {
		heavyTop: 5,
		heavyRate: 1e6,
		maxArcs: 100,
		labels: true,
		hostnames: false,
		asn: true,
		blocks: true,
		blockMin: 3,
		colorMode: "initiator",
		follow: false
	};
	/** The options dialog's values ("5", "0", "1") as renderer settings, defaults for anything unset. */
	function parseSettings(config = {}) {
		const number = (value, fallback) => {
			const parsed = parseInt(value, 10);
			return Number.isFinite(parsed) ? parsed : fallback;
		};
		return {
			heavyTop: number(config.heavy_top, DEFAULT_OPTIONS.heavyTop),
			heavyRate: number(config.heavy_rate, DEFAULT_OPTIONS.heavyRate),
			maxArcs: number(config.max_arcs, DEFAULT_OPTIONS.maxArcs),
			labels: config.labels !== "0",
			hostnames: config.hostnames === "1",
			asn: config.asn !== "0",
			blocks: config.blocks !== "0",
			blockMin: number(config.block_min, DEFAULT_OPTIONS.blockMin) || DEFAULT_OPTIONS.blockMin,
			follow: config.follow === "1"
		};
	}
	/** The same as a query string, for a request that does not build it itself (the page). */
	function summaryQuery(settings) {
		return `?blocks_min=${settings.blockMin ?? DEFAULT_OPTIONS.blockMin}${settings.hostnames ? "&hostnames=1" : ""}`;
	}
	//#endregion
	//#region src/text.js
	var DEFAULT_TEXT = {
		map_started_inside: "Outbound",
		map_started_outside: "Inbound",
		map_started_both: "Both directions",
		map_toward: "Mostly download",
		map_away: "Mostly upload",
		map_blocked: "Blocked",
		map_flagged_blocked: "Flagged · blocked",
		map_flagged_allowed: "Flagged · allowed",
		map_allowed: "Allowed",
		map_ids_alert: "IDS alert",
		map_minutes: "{count} min",
		map_hours: "{count} h",
		map_days: "{count} days",
		map_moments: "moments",
		map_port: "port {port}",
		map_traffic: "traffic",
		map_this_firewall: "this firewall",
		map_this_firewall_title: "This firewall",
		map_other_targets_one: " (and {count} other target)",
		map_other_targets_many: " (and {count} other targets)",
		map_through_forward: " through a port forward",
		map_open_for: ", open for {duration}",
		map_reached: "{other} reached {where} on {service}{more}{forwarded}{open}.",
		map_other_hosts_one: "{host} and {count} other host",
		map_other_hosts_many: "{host} and {count} other hosts",
		map_other_services_one: " and {count} other service",
		map_other_services_many: " and {count} other services",
		map_queried: "{who} queried {service}{more} at {other}",
		map_synced: "{who} synced time with {other} over {service}{more}",
		map_mailed: "{who} delivered mail to {other} over {service}{more}",
		map_pinged: "{who} pinged {other}",
		map_opened: "{who} opened {service}{more} to {other}",
		map_a_connection: "a connection",
		map_other_ports_one: " and {count} other port",
		map_other_ports_many: " and {count} other ports",
		map_and: " and ",
		map_by_rule: " by \"{rule}\"",
		map_on_interface: " on {interface}",
		map_first_seen_ago: ", first seen {duration} ago",
		map_block_sentence: "{source}{place} tried {tried} on this firewall: blocked {hits}× in the last {minutes} min{rule}{where}{since}.",
		map_ids_line: "Suricata: {signature} (severity {severity}{category})",
		map_ids_first: ", {count}× in the last {window}, latest {latest} ago",
		map_ids_count: ", {count}×",
		map_more_alerts_one: "and {count} more alert",
		map_more_alerts_many: "and {count} more alerts",
		map_more_addresses_one: "+{count} more address here",
		map_more_addresses_many: "+{count} more addresses here",
		map_addresses_many: "{count} addresses",
		map_via: "via {egress}",
		map_open_state: "open for {duration}",
		map_closed: "closed",
		map_ips_dropped: "Dropped by IPS",
		map_ips_dropped_flagged: "Dropped by IPS · flagged",
		map_ids_connection: "Suricata alerted on this connection",
		map_ids_connection_dropped: "Suricata alerted on this connection · dropped by IPS",
		map_rule: "rule: {rule}",
		map_seen_by_suricata: "Seen by Suricata",
		map_seen_by_suricata_flagged: "Seen by Suricata · flagged",
		map_no_connection: "No connection is open right now",
		map_last_minute: "{count} in the last minute",
		map_hammering: " · hammering",
		map_active_links_one: "{count} active link",
		map_active_links_many: "{count} active links",
		geo_downloading_title: "Downloading the geolocation database",
		geo_preparing: "Starting the download…",
		geo_progress: "{done} of {total}",
		geo_fills_in: "The map fills in as soon as it is done.",
		geo_failed_title: "The geolocation database could not be downloaded",
		geo_key_title: "A MaxMind license key is needed",
		geo_retry_in: "Trying again in {time}",
		geo_retrying: "Trying again…",
		geo_retry_now: "Retry now",
		geo_partial: "Network names are unavailable",
		geo_fallback: "Using {provider} Lite while the MaxMind download fails",
		geo_stale: "The geolocation database could not be updated",
		geo_err_unauthorized: "MaxMind did not accept the license key. A new key can take a few minutes to start working; if this persists, check the key in the settings and that GeoLite2 downloads are enabled for your MaxMind account.",
		geo_err_forbidden: "{provider} refused the download (HTTP 403): the account may not have access to this database.",
		geo_err_not_found: "{provider} did not have the database at the expected address (HTTP 404). DB-IP publishes a new file each month; early in the month it may not be out yet.",
		geo_err_rate_limited: "{provider} limits how often a database can be downloaded (HTTP 429).",
		geo_err_unreachable: "The firewall could not reach {provider}. Check that it has internet access and working DNS.",
		geo_err_timeout: "The download from {provider} took too long and was stopped. A slow or busy connection is the usual cause.",
		geo_err_invalid: "The downloaded file was not a valid database.",
		geo_err_disk_full: "The database could not be saved: the firewall's disk is full.",
		geo_err_http: "{provider} answered with an error.",
		geo_err_other: "The download failed."
	};
	/** The text table in use: the caller's translations over the English defaults. */
	function textTable(text) {
		return {
			...DEFAULT_TEXT,
			...text || {}
		};
	}
	//#endregion
	//#region page/context.js
	var T = window.FirewallMapPageText || {};
	var TEXT = textTable(T);
	var POLL_MS = 2e3;
	var WATCHLIST = "FWMAP_Watchlist";
	var ABUSEIPDB_BLACKLIST_LIST = "AbuseIPDB blacklist";
	var ABUSEIPDB_LOOKUP_LIST = "AbuseIPDB (looked up)";
	var state = {
		renderer: null,
		data: null,
		live: null,
		mode: "live",
		frozen: null,
		snapshots: [],
		snapshotsKept: {
			keep: 50,
			keep_days: 30
		},
		tabBeforeSnapshots: null,
		settings: null,
		pluginSettings: null,
		filters: {
			traffic: "all",
			service: "",
			iface: "",
			host: "",
			country: "",
			asn: ""
		},
		colorMode: "initiator",
		talkerTab: "hosts",
		talkerRows: [],
		history: /* @__PURE__ */ new Map(),
		isAdmin: false,
		selection: null,
		detailsAddress: null,
		renderedSelection: null,
		renderedAddress: null,
		investigations: /* @__PURE__ */ new Map(),
		revealInvestigation: null,
		revealing: null,
		geoNoteDismissed: null,
		abuseScores: /* @__PURE__ */ new Map(),
		abuseChecking: /* @__PURE__ */ new Set(),
		abuseConfigured: false,
		queueExpanded: /* @__PURE__ */ new Set(),
		follow: false,
		layout: {},
		updatedAt: null
	};
	/** The page's own filters, as the reset button leaves them. */
	function resetFilters() {
		state.filters = {
			traffic: "all",
			service: "",
			iface: "",
			host: "",
			country: "",
			asn: ""
		};
	}
	//#endregion
	//#region page/api.js
	function postJSON(url, payload) {
		return $.ajax({
			url,
			type: "POST",
			dataType: "json",
			contentType: "application/json",
			data: JSON.stringify(payload || {})
		});
	}
	function getJSON(url) {
		return $.getJSON(url);
	}
	/** A failed request or thrown error as one line. */
	function errorText(error) {
		return error?.message || error?.statusText || String(error);
	}
	function notify(message, type) {
		BootstrapDialog.show({
			type: type || BootstrapDialog.TYPE_INFO,
			title: T.firewall_map,
			message: escapeHtml(message),
			buttons: [{
				label: T.close,
				action: (dialog) => dialog.close()
			}]
		});
	}
	function notifyFailure(error) {
		notify(`${T.action_failed}: ${errorText(error)}`, BootstrapDialog.TYPE_DANGER);
	}
	function confirmAction(message, onConfirm) {
		BootstrapDialog.confirm({
			title: T.firewall_map,
			message: escapeHtml(message),
			type: BootstrapDialog.TYPE_WARNING,
			btnOKLabel: T.confirm,
			btnCancelLabel: T.cancel,
			callback: (confirmed) => confirmed && onConfirm()
		});
	}
	//#endregion
	//#region page/actions.js
	async function showStates(address) {
		try {
			const result = await postJSON("/api/diagnostics/firewall/query_states", {
				searchPhrase: address,
				rowCount: 100,
				current: 1
			});
			const count = (result.rows || []).length;
			const rows = (result.rows || []).map((row) => `<tr><td>${escapeHtml(row.interface)}</td><td>${escapeHtml(row.proto)}</td><td>${escapeHtml(hostPort(row.src_addr, row.src_port))}</td><td>${escapeHtml(hostPort(row.dst_addr, row.dst_port))}</td><td>${escapeHtml(row.state)}</td><td>${escapeHtml(row.bytes ?? "")}</td></tr>`).join("");
			BootstrapDialog.show({
				title: escapeHtml(`${T.states_for} ${address}`),
				size: BootstrapDialog.SIZE_WIDE,
				message: rows ? `<table class="table table-condensed table-striped"><thead><tr><th>${escapeHtml(T.interface)}</th><th>${escapeHtml(T.protocol)}</th><th>${escapeHtml(T.source)}</th><th>${escapeHtml(T.destination)}</th><th>${escapeHtml(T.state)}</th><th>${escapeHtml(T.bytes)}</th></tr></thead><tbody>${rows}</tbody></table>${result.total > count ? `<div class="text-muted">${escapeHtml(T.more_states)}</div>` : ""}` : escapeHtml(T.no_states),
				buttons: [{
					label: T.close,
					action: (dialog) => dialog.close()
				}]
			});
		} catch (error) {
			notifyFailure(error);
		}
	}
	function killStates(address) {
		confirmAction(`${T.kill_confirm} ${address}? ${T.kill_scope}`, async () => {
			try {
				const result = await postJSON("/api/diagnostics/firewall/kill_states", { filter: address });
				notify(result.result === "ok" ? `${T.killed} ${result.dropped_states}` : T.action_failed, result.result === "ok" ? BootstrapDialog.TYPE_SUCCESS : BootstrapDialog.TYPE_DANGER);
			} catch (error) {
				notifyFailure(error);
			}
		});
	}
	async function aliasRows(types) {
		return ((await postJSON("/api/firewall/alias/search_item", {
			current: 1,
			rowCount: -1
		})).rows || []).filter((row) => types.includes(String(row.type).toLowerCase().split(" ")[0]) || types.includes(String(row.type).toLowerCase()));
	}
	/** Pick an alias of one of `types`; onChoose(name, uuid). */
	async function chooseAlias(types, title, onChoose) {
		let rows = [];
		try {
			rows = await aliasRows(types);
		} catch (error) {
			notifyFailure(error);
			return;
		}
		if (!rows.length) {
			notify(T.no_aliases);
			return;
		}
		const $select = $("<select class=\"form-control\"></select>").attr("aria-label", T.add_to_alias).html(rows.map((row) => `<option value="${escapeHtml(row.uuid)}" data-name="${escapeHtml(row.name)}">${escapeHtml(row.name)} (${escapeHtml(row.type)})</option>`).join(""));
		BootstrapDialog.show({
			title,
			message: $("<div></div>").append($select),
			buttons: [{
				label: T.cancel,
				action: (dialog) => dialog.close()
			}, {
				label: T.confirm,
				cssClass: "btn-primary",
				action: (dialog) => {
					const $option = $select.find(":selected");
					dialog.close();
					onChoose(plain($option.data("name")), $option.val());
				}
			}]
		});
	}
	/** Add one address to a named alias; throws with the firewall's message when it is refused. */
	async function addAddressToAlias(name, address) {
		const result = await postJSON(`/api/firewall/alias_util/add/${encodeURIComponent(name)}`, { address });
		if (result.status !== "done") throw new Error(result.status_msg || result.status);
	}
	function addToAlias(address) {
		chooseAlias([
			"host",
			"hosts",
			"network",
			"networks"
		], escapeHtml(`${T.add_to_alias}: ${address}`), (name) => {
			confirmAction(`${T.add_confirm} ${address} → ${name}?`, async () => {
				try {
					await addAddressToAlias(name, address);
					notify(`${address} → ${name}`, BootstrapDialog.TYPE_SUCCESS);
				} catch (error) {
					notifyFailure(error);
				}
			});
		});
	}
	function markThreat(address) {
		confirmAction(`${T.mark_confirm} ${address} ${T.mark_scope}`, async () => {
			try {
				if (!((await postJSON("/api/firewall/alias/search_item", {
					current: 1,
					rowCount: -1,
					searchPhrase: "FWMAP_Watchlist"
				})).rows || []).some((row) => plain(row.name) === "FWMAP_Watchlist")) {
					const saved = await postJSON("/api/firewall/alias/add_item", { alias: {
						enabled: "1",
						name: WATCHLIST,
						type: "host",
						content: address,
						description: "Firewall Map+ watchlist: addresses marked as threats (no rules use it unless you add one)"
					} });
					if (saved.result !== "saved") throw new Error(JSON.stringify(saved.validations || saved));
					await postJSON("/api/firewall/alias/reconfigure", {});
				} else await addAddressToAlias(WATCHLIST, address);
				notify(`${address} → ${WATCHLIST}. ${T.marked}`, BootstrapDialog.TYPE_SUCCESS);
			} catch (error) {
				notifyFailure(error);
			}
		});
	}
	function addCountry(code) {
		chooseAlias(["geoip", "geoip (ip in country)"], escapeHtml(`${T.add_country} (${code})`), (name, uuid) => {
			confirmAction(`${T.add_confirm} ${code} → ${name}?`, async () => {
				try {
					const content = (await getJSON(`/api/firewall/alias/get_item/${encodeURIComponent(uuid)}`)).alias?.content || {};
					const codes = Object.entries(content).filter(([, option]) => option.selected).map(([value]) => value);
					if (!codes.includes(code)) codes.push(code);
					const saved = await postJSON(`/api/firewall/alias/set_item/${encodeURIComponent(uuid)}`, { alias: { content: codes.join("\n") } });
					if (saved.result !== "saved") throw new Error(JSON.stringify(saved.validations || saved));
					await postJSON("/api/firewall/alias/reconfigure", {});
					notify(`${code} → ${name}`, BootstrapDialog.TYPE_SUCCESS);
				} catch (error) {
					notify(`${T.action_failed}: ${errorText(error)}`, BootstrapDialog.TYPE_DANGER);
				}
			});
		});
	}
	//#endregion
	//#region src/summaries.js
	function duration(seconds, text = DEFAULT_TEXT) {
		if (!seconds || seconds < 60) return null;
		if (seconds < 5400) return fill(text.map_minutes, { count: Math.round(seconds / 60) });
		if (seconds < 172800) return fill(text.map_hours, { count: Math.round(seconds / 3600) });
		return fill(text.map_days, { count: Math.round(seconds / 86400) });
	}
	/** 'HTTPS (443/tcp)', 'port 9443/tcp' or 'ICMP'. */
	function serviceLabel(name, port, text) {
		const raw = /^(TCP|UDP)\/(\d+)$/.exec(name || "");
		if (raw) return fill(text.map_port, { port: `${raw[2]}/${raw[1].toLowerCase()}` });
		return port ? `${plain(name)} (${port})` : plain(name || text.map_traffic);
	}
	function hostLabel(host) {
		return host.name ? `${plain(host.name)} (${host.ip})` : host.ip;
	}
	function isFirewall(target) {
		return target.firewall || target.name === "firewall";
	}
	function remoteReached(flow, other, open, text) {
		const services = flow.services || [];
		const ports = flow.service_ports || {};
		const targets = flow.targets || [];
		const target = targets[0];
		let where = text.map_this_firewall;
		let service = serviceLabel(services[0], ports[services[0]], text);
		if (target) {
			where = isFirewall(target) ? text.map_this_firewall : hostLabel(target);
			const port = target.port ? `${target.port}/${target.protocol || "tcp"}` : null;
			service = serviceLabel(target.service, port, text);
		}
		return fill(text.map_reached, {
			other,
			where,
			service,
			more: targets.length > 1 ? plural(text, "map_other_targets", targets.length - 1) : "",
			forwarded: target && !isFirewall(target) ? text.map_through_forward : "",
			open: open ? fill(text.map_open_for, { duration: open }) : ""
		});
	}
	function localOpened(flow, other, open, text) {
		const services = flow.services || [];
		const ports = flow.service_ports || {};
		const inside = flow.inside || [];
		const who = inside.length ? inside.length > 1 ? plural(text, "map_other_hosts", inside.length - 1, { host: hostLabel(inside[0]) }) : hostLabel(inside[0]) : text.map_this_firewall_title;
		const name = services[0] || "";
		const values = {
			who,
			other,
			service: serviceLabel(name, ports[name], text),
			more: services.length > 1 ? plural(text, "map_other_services", services.length - 1) : ""
		};
		let sentence;
		if (/^DNS/.test(name)) sentence = fill(text.map_queried, values);
		else if (name === "NTP") sentence = fill(text.map_synced, values);
		else if (/^(SMTP|SMTPS|Submission)$/.test(name)) sentence = fill(text.map_mailed, values);
		else if (name === "ICMP") sentence = fill(text.map_pinged, values);
		else sentence = fill(text.map_opened, values);
		return `${sentence}${open && name !== "ICMP" ? fill(text.map_open_for, { duration: open }) : ""}.`;
	}
	/**
	* One plain-language sentence per direction of a flow, built only from what the collector saw:
	* who opened it, the service and port, the other side's name, network and country, how long.
	* `remote` is {ip, hostname, org, country}; the caller escapes the result.
	*/
	function flowSummary(flow, remote, text = DEFAULT_TEXT) {
		const place = [remote.org, remote.country].filter(Boolean).map(plain).join(", ");
		const other = `${remote.hostname ? plain(remote.hostname) : remote.ip}${place ? ` (${place})` : ""}`;
		const open = duration(flow.age, text);
		const sentences = [];
		if (flow.initiated === "remote" || flow.initiated === "both") sentences.push(remoteReached(flow, other, open, text));
		if (flow.initiated !== "remote") sentences.push(localOpened(flow, other, open, text));
		return sentences;
	}
	/**
	* Suricata's view of an address in one line per signature, worst first:
	* 'Suricata: ET SCAN Potential SSH Scan (severity 2), 3× in the last hour, latest 2 min ago'.
	*/
	function idsSummary(ids, text = DEFAULT_TEXT) {
		if (!ids || !ids.count) return [];
		const latest = duration(ids.last_seconds, text) || text.map_moments;
		const window = ids.minutes >= 60 ? fill(text.map_hours, { count: Math.round(ids.minutes / 60) }) : fill(text.map_minutes, { count: ids.minutes });
		const lines = (ids.signatures || []).map((item, index) => fill(text.map_ids_line, {
			signature: plain(item.signature),
			severity: item.severity,
			category: item.category ? `, ${plain(item.category)}` : ""
		}) + (index === 0 ? fill(text.map_ids_first, {
			count: item.count,
			window,
			latest
		}) : fill(text.map_ids_count, { count: item.count })));
		const shown = (ids.signatures || []).reduce((sum, item) => sum + item.count, 0);
		if (ids.count > shown) lines.push(plural(text, "map_more_alerts", ids.count - shown));
		return lines;
	}
	/**
	* One color legend everywhere (badges, arcs, markers): green allowed and not flagged, gray
	* blocked and not flagged, amber flagged but stopped (firewall or IPS), red flagged and let
	* through. Flagged means a blocklist, an AbuseIPDB report or a Suricata severity 1-2 alert; the
	* collector already folds all three into an address's lists.
	*/
	function outcome({ flagged, stopped }) {
		if (flagged) return stopped ? "contained" : "danger";
		return stopped ? "blocked" : "ok";
	}
	/** Outcome of a connection Suricata alerted on. */
	function idsOutcome(flow) {
		return outcome({
			flagged: flow.severity <= 2 || (flow.lists || []).length > 0,
			stopped: flow.kind === "blocked" || Boolean(flow.ips_dropped)
		});
	}
	//#endregion
	//#region page/icons.js
	var ICON_PATHS = {
		"globe": "<circle cx=\"12\" cy=\"12\" r=\"10\"/><path d=\"M2 12h20\"/><path d=\"M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z\"/>",
		"laptop": "<rect x=\"4\" y=\"4\" width=\"16\" height=\"11\" rx=\"1.5\"/><path d=\"M2 19h20\"/>",
		"server": "<rect x=\"3\" y=\"3\" width=\"18\" height=\"7\" rx=\"1.5\"/><rect x=\"3\" y=\"14\" width=\"18\" height=\"7\" rx=\"1.5\"/><path d=\"M7 6.5h.01M7 17.5h.01M11 6.5h6M11 17.5h6\"/>",
		"shield": "<path d=\"M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z\"/>",
		"shield-check": "<path d=\"M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z\"/><path d=\"m9 12 2 2 4-4\"/>",
		"chart": "<path d=\"M3 3v18h18\"/><path d=\"M8 17v-4M12 17V7M16 17v-7M20 17v-2\"/>",
		"search": "<circle cx=\"11\" cy=\"11\" r=\"7\"/><path d=\"m21 21-5-5\"/>",
		"layers": "<path d=\"m12 2 10 5-10 5L2 7l10-5z\"/><path d=\"m2 17 10 5 10-5\"/><path d=\"m2 12 10 5 10-5\"/>",
		"external": "<path d=\"M15 3h6v6\"/><path d=\"M10 14 21 3\"/><path d=\"M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6\"/>",
		"list": "<path d=\"M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01\"/>",
		"trash": "<path d=\"M3 6h18\"/><path d=\"M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6\"/><path d=\"M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2\"/><path d=\"M10 11v6M14 11v6\"/>",
		"chevron": "<path d=\"m9 18 6-6-6-6\"/>",
		"check": "<path d=\"M20 6 9 17l-5-5\"/>",
		"x": "<path d=\"M18 6 6 18M6 6l12 12\"/>",
		"ban": "<circle cx=\"12\" cy=\"12\" r=\"10\"/><path d=\"m4.9 4.9 14.2 14.2\"/>",
		"flag": "<path d=\"M4 15s1-1 4-1 5 2 8 2 4-1 4-1V3s-1 1-4 1-5-2-8-2-4 1-4 1z\"/><path d=\"M4 22v-7\"/>",
		"alert": "<circle cx=\"12\" cy=\"12\" r=\"10\"/><path d=\"M12 8v4M12 16h.01\"/>",
		"network": "<rect x=\"9\" y=\"2\" width=\"6\" height=\"6\" rx=\"1\"/><rect x=\"16\" y=\"16\" width=\"6\" height=\"6\" rx=\"1\"/><rect x=\"2\" y=\"16\" width=\"6\" height=\"6\" rx=\"1\"/><path d=\"M5 16v-3a1 1 0 0 1 1-1h12a1 1 0 0 1 1 1v3M12 12V8\"/>",
		"plus": "<path d=\"M12 5v14M5 12h14\"/>",
		"minus": "<path d=\"M5 12h14\"/>",
		"calendar": "<rect x=\"3\" y=\"4\" width=\"18\" height=\"18\" rx=\"2\"/><path d=\"M16 2v4M8 2v4M3 10h18\"/>",
		"clock": "<circle cx=\"12\" cy=\"12\" r=\"10\"/><path d=\"M12 6v6l4 2\"/>",
		"swap": "<path d=\"m16 3 4 4-4 4\"/><path d=\"M20 7H4\"/><path d=\"m8 21-4-4 4-4\"/><path d=\"M4 17h16\"/>",
		"eye-off": "<path d=\"M9.9 4.2A10 10 0 0 1 12 4c7 0 10 8 10 8a13 13 0 0 1-1.7 2.7\"/><path d=\"M6.6 6.6A13.5 13.5 0 0 0 2 12s3 8 10 8a9.7 9.7 0 0 0 5.4-1.6\"/><path d=\"M14.1 14.1a3 3 0 1 1-4.2-4.2\"/><path d=\"m2 2 20 20\"/>",
		"undo": "<path d=\"M3 7v6h6\"/><path d=\"M21 17a9 9 0 0 0-9-9 9 9 0 0 0-6 2.3L3 13\"/>",
		"chevron-down": "<path d=\"m6 9 6 6 6-6\"/>",
		"list-box": "<rect x=\"3\" y=\"3\" width=\"18\" height=\"18\" rx=\"2\"/><path d=\"M7 8h10M7 12h10M7 16h6\"/>",
		"expand": "<path d=\"M8 3H5a2 2 0 0 0-2 2v3M21 8V5a2 2 0 0 0-2-2h-3M3 16v3a2 2 0 0 0 2 2h3M16 21h3a2 2 0 0 0 2-2v-3\"/>",
		"camera": "<path d=\"M3 8.5A1.5 1.5 0 0 1 4.5 7h2.6l1.6-2.4h6.6L16.9 7h2.6A1.5 1.5 0 0 1 21 8.5v9A1.5 1.5 0 0 1 19.5 19h-15A1.5 1.5 0 0 1 3 17.5z\"/><circle cx=\"12\" cy=\"12.8\" r=\"3.4\"/>",
		"download": "<path d=\"M12 4v11\"/><path d=\"m7 10 5 5 5-5\"/><path d=\"M5 20h14\"/>",
		"edit": "<path d=\"M4 20h4L19 9l-4-4L4 16z\"/><path d=\"m14 6 4 4\"/>",
		"chevron-left": "<path d=\"m15 18-6-6 6-6\"/>",
		"live": "<circle cx=\"12\" cy=\"12\" r=\"4\"/>"
	};
	var ICON_ALIASES = {
		"fa-globe": "globe",
		"fa-desktop": "laptop",
		"fa-laptop": "laptop",
		"fa-server": "server",
		"fa-shield": "shield",
		"fa-bar-chart": "chart",
		"fa-search": "search",
		"fa-database": "layers",
		"fa-external-link": "external",
		"fa-list": "list",
		"fa-trash-o": "trash",
		"fa-chevron-right": "chevron",
		"fa-check": "check",
		"fa-times": "x",
		"fa-ban": "ban",
		"fa-flag": "flag",
		"fa-flag-o": "flag",
		"fa-exclamation-triangle": "alert",
		"fa-exclamation-circle": "alert",
		"fa-sitemap": "network"
	};
	function ic(name, cls = "") {
		const paths = ICON_PATHS[ICON_ALIASES[name] || name];
		if (!paths) return `<i class="fa ${name} ${cls}"></i>`;
		return `<svg class="fwmap-ic ${cls}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${paths}</svg>`;
	}
	//#endregion
	//#region page/parts.js
	/** A status pill; `big` is the verdict pill at the top of the details panel. */
	function pill(kind, text, icon, big = false) {
		const base = big ? "fwmap-vpill" : "fwmap-pill";
		return `<span class="${base} ${base}-${kind}">${icon ? `${ic(icon)} ` : ""}${escapeHtml(text)}</span>`;
	}
	function bigPill(kind, text, icon) {
		return pill(kind, text, icon, true);
	}
	/** A label/value table; rows with no value are left out. Values are HTML. */
	function rows(items, className = "fwmap-kv") {
		return `<table class="${className}">${items.filter(([, value]) => value !== null && value !== void 0 && value !== "").map(([label, value]) => `<tr><th>${escapeHtml(label)}</th><td>${value}</td></tr>`).join("")}</table>`;
	}
	function place(item) {
		return [item.city, item.country].filter(Boolean).map(plain).join(", ");
	}
	/** One box of the connection diagram: a host on either end. */
	function endBox(icon, name, lines) {
		return `<div class="fwmap-end">${ic(icon)}<div class="fwmap-end-name">${escapeHtml(name)}</div>` + lines.filter(Boolean).map((line) => `<div class="fwmap-end-sub">${escapeHtml(line)}</div>`).join("") + "</div>";
	}
	/** A card of the details panel: icon, title and a chevron that opens the related view. */
	function card(icon, title, body, action) {
		const chevron = action ? `<a href="${action.href || "#"}" class="fwmap-card-go ${action.cls || ""}"${action.href ? " target=\"_blank\" rel=\"noopener\"" : ""}${action.address ? ` data-address="${escapeHtml(action.address)}"` : ""} title="${escapeHtml(action.title)}" aria-label="${escapeHtml(action.title)}">${ic("chevron")}</a>` : "";
		return `<section class="fwmap-card"><div class="fwmap-card-head">${ic(icon, "fwmap-card-ic")}<span>${escapeHtml(title)}</span>${chevron}</div><div class="fwmap-card-body">${body}</div></section>`;
	}
	function serviceParts(name, port) {
		const raw = /^(TCP|UDP)\/(\d+)$/.exec(name || "");
		if (raw) return {
			name: `${T.port_word} ${raw[2]}`,
			port: `${raw[1]}/${raw[2]}`
		};
		const [number, protocol] = String(port || "").split("/");
		return {
			name: plain(name || "—"),
			port: number ? `${(protocol || "").toUpperCase()}/${number}` : ""
		};
	}
	/** Suricata's alerts for an address, worst signature first. */
	function idsLines(ids, text) {
		if (!ids) return "";
		const cls = ids.severity <= 2 ? "fwmap-ids fwmap-ids-high" : "fwmap-ids";
		return idsSummary(ids, text).map((line) => `<div class="${cls}">${ic("flag")} ${escapeHtml(line)}</div>`).join("");
	}
	/** "3 min", "2 h", "5 d" since an epoch time. */
	function ago(seconds) {
		const age = Math.max(0, Date.now() / 1e3 - seconds);
		if (age < 90) return `${Math.round(age)} s`;
		if (age < 5400) return `${Math.round(age / 60)} min`;
		if (age < 129600) return `${Math.round(age / 3600)} h`;
		return `${Math.round(age / 86400)} d`;
	}
	/** 8040 seconds read "2 h 14 min". */
	function spanText(seconds) {
		const minutes = Math.floor(seconds / 60);
		if (minutes < 1) return `${Math.round(seconds)} s`;
		if (minutes < 60) return `${minutes} min`;
		const days = Math.floor(minutes / 1440);
		const hours = Math.floor(minutes % 1440 / 60);
		return days ? `${days} d ${hours} h` : `${hours} h ${minutes % 60} min`;
	}
	//#endregion
	//#region page/details.js
	var REVEAL_MS = 900;
	/** What the map knows about a remote address: hostname, network, country. */
	function remoteOf(address) {
		const location = (state.data?.locations || []).find((item) => item.id === address) || {};
		return {
			ip: address,
			hostname: state.data?.hostnames?.[address],
			org: state.settings.asn ? location.as_org : null,
			country: location.country,
			country_code: location.country_code
		};
	}
	function reputationCard(item) {
		const listed = new Set(item.lists || []);
		const lists = [.../* @__PURE__ */ new Set([...state.data?.threat_lists || [], ...listed])];
		const address = item.address;
		const score = item.abuseipdb ?? state.abuseScores.get(address);
		const blacklisted = listed.has(ABUSEIPDB_BLACKLIST_LIST);
		const known = score !== null && score !== void 0;
		let abuse;
		if (state.abuseChecking.has(address)) abuse = `<span class="fwmap-muted">${escapeHtml(T.checking)}</span>`;
		else if (!known) abuse = state.isAdmin && state.abuseConfigured ? `<a href="#" class="fwmap-abuse-check" data-address="${escapeHtml(address)}">${ic("search")} ${escapeHtml(T.check_now)}</a>` : `<span class="fwmap-muted" title="${escapeHtml(T.abuseipdb_hint)}">${escapeHtml(T.no_key)}</span>`;
		else abuse = score >= 75 ? pill("danger", `${score}%`) : score >= 25 ? pill("warning", `${score}%`) : pill("ok", T.clean, "fa-check");
		const notListed = `<span class="fwmap-not-listed">${ic("check")} ${escapeHtml(T.not_listed_short)}</span>`;
		const left = rows([["AbuseIPDB", blacklisted && !known ? "" : abuse], ...lists.filter((name) => name !== ABUSEIPDB_LOOKUP_LIST).map((name) => [listLabel(name), listed.has(name) ? pill("danger", T.listed, "fa-ban") : notListed])]);
		const right = rows([
			["ASN", item.asn ? escapeHtml(`AS${item.asn}`) : ""],
			[T.organization, escapeHtml(plain(item.as_org || ""))],
			[T.country, item.country ? `${flagHtml(item.country_code)} ${escapeHtml(plain(item.country))}` : ""]
		]);
		return card("fa-database", T.sec_reputation, `<div class="fwmap-two">${left}${right}</div>`, state.isAdmin ? {
			cls: "fwmap-investigate",
			address,
			title: T.investigate
		} : null);
	}
	function idsCard(ids, groups) {
		const signatures = groups ? groups.flatMap((group) => group.signatures) : (ids?.signatures || []).map((item) => ({
			...item,
			last: null
		}));
		if (!signatures.length) return card("fa-search", T.sec_ids_long, `<div class="fwmap-empty-note">${ic("check", "fwmap-ok-ic")}
      <div><div>${escapeHtml(T.no_ids)}</div><div class="fwmap-muted">${escapeHtml(T.no_ids_sub)}</div></div></div>`, {
			href: "/ui/ids#alerts",
			title: T.open_ids
		});
		const scope = groups ? T.ids_on_connection : T.ids_on_address;
		return card("fa-search", T.sec_ids_long, `<div class="fwmap-card-note">${escapeHtml(scope)}</div>` + signatures.map((item) => `<div class="fwmap-sig">
        <div class="${item.severity <= 2 ? "fwmap-ids-high" : "fwmap-ids"}">${ic("flag")} ${escapeHtml(item.signature)}</div>
        <div class="text-muted">${escapeHtml(T.severity)} ${escapeHtml(item.severity)}${item.category ? ` · ${escapeHtml(item.category)}` : ""}${item.sid ? ` · SID ${escapeHtml(item.sid)}` : ""}
          · ${escapeHtml(item.count)}×${item.last ? ` · ${escapeHtml((/* @__PURE__ */ new Date(item.last * 1e3)).toLocaleTimeString())}` : ""}${item.action === "blocked" ? ` · <b>${escapeHtml(T.ips_dropped)}</b>` : ""}</div>
      </div>`).join(""), {
			href: "/ui/ids#alerts",
			title: T.open_ids
		});
	}
	function firewallBox(sub) {
		return endBox("fa-shield", T.this_firewall_title, [sub]);
	}
	function localOrigin() {
		return (state.data?.locations || []).find((entry) => entry.local)?.id || "";
	}
	function rateText(rateIn, rateOut, format = formatRate) {
		return `↓ ${escapeHtml(format(rateIn || 0))} ↑ ${escapeHtml(format(rateOut || 0))}`;
	}
	function flowModel(flow, context) {
		const { remoteBox, item, address } = context;
		const outbound = flow.initiated !== "remote";
		const inside = (flow.inside || [])[0];
		const target = (flow.targets || [])[0];
		const name = (flow.services || [])[0];
		const service = serviceParts(target && !outbound ? target.service : name, target && !outbound && target.port ? `${target.port}/${target.protocol || "tcp"}` : (flow.service_ports || {})[name]);
		const localBox = outbound ? inside ? endBox("laptop", inside.name || inside.ip, [inside.name ? inside.ip : "", inside.interface]) : firewallBox(localOrigin()) : target && !target.firewall ? endBox("laptop", target.name || target.ip, [target.name ? target.ip : "", target.interface]) : firewallBox(localOrigin());
		return {
			verdict: (flow.lists || []).length > 0 ? bigPill("danger", T.allowed_flagged, "fa-exclamation-triangle") : bigPill("ok", T.allowed, "fa-check"),
			sub: outbound ? T.started_inside_long : T.started_outside_long,
			diagram: {
				from: outbound ? localBox : remoteBox,
				service,
				rate: rateText(flow.rate_in, flow.rate_out),
				to: outbound ? remoteBox : localBox,
				blocked: false
			},
			connection: rows([
				[T.protocol, escapeHtml(`${service.name}${service.port ? ` (${service.port.split("/")[0]})` : ""}`)],
				[T.remote_port, outbound && service.port ? escapeHtml(service.port.split("/")[1]) : ""],
				[T.other_services, (flow.services || []).slice(1).map(escapeHtml).join(", ")],
				[T.state, (flow.activity || 0) > 0 ? pill("ok", T.active, "fa-check") : pill("muted", T.idle)],
				[T.started, flow.age ? escapeHtml(`${ago(Date.now() / 1e3 - flow.age)} ${T.ago}`) : ""],
				[T.transferred, flow.transferred ? rateText(flow.transferred[0], flow.transferred[1], formatBytes) : ""],
				[T.current_rate, rateText(flow.rate_in, flow.rate_out)],
				[T.duration, flow.age ? escapeHtml(spanText(flow.age)) : ""],
				[T.connections, escapeHtml(flow.states)]
			]),
			firewall: rows([
				[T.decision, pill("ok", T.allowed, "fa-check")],
				[T.interface, escapeHtml(inside?.interface || target?.interface || flow.egress || "")],
				[T.rule, escapeHtml(flow.rule || "")],
				[T.egress, escapeHtml(flow.egress || "")],
				["NAT", inside && outbound ? escapeHtml(`${T.yes} (${inside.ip} → ${flow.origin})`) : target && !target.firewall ? escapeHtml(`${T.port_forward} (${flow.origin} → ${hostPort(target.ip, target.port)})`) : escapeHtml(T.no)]
			]),
			ids: idsCard(flow.ids, null),
			reputation: reputationCard({
				...item,
				address,
				lists: flow.lists,
				abuseipdb: flow.abuseipdb
			})
		};
	}
	function idsFlowModel(ids, context) {
		const { remoteBox, item, address } = context;
		const inside = ids.inside_host;
		const insideBox = inside ? endBox("laptop", inside.name || inside.ip, [inside.name ? ids.inside : "", inside.interface]) : firewallBox(ids.public);
		const [, port] = splitHostPort(ids.remote);
		const [publicAddress] = splitHostPort(ids.public);
		const [insideAddress] = splitHostPort(ids.inside);
		const service = {
			name: protocolLabel(ids.protocol),
			port: port ? `${protocolLabel(ids.protocol)}/${port}` : ""
		};
		const serious = ids.severity <= 2 || (ids.lists || []).length > 0;
		return {
			verdict: {
				ok: bigPill("ok", T.allowed, "fa-check"),
				danger: bigPill("danger", T.allowed_flagged, "fa-exclamation-triangle"),
				blocked: bigPill("blocked", ids.ips_dropped ? T.ips_dropped_title : T.blocked, "fa-ban"),
				contained: bigPill("contained", ids.ips_dropped ? T.ips_dropped_flagged : T.blocked_flagged, "fa-ban")
			}[idsOutcome(ids)],
			sub: ids.remote_started ? T.started_outside_long : T.started_inside_long,
			diagram: {
				from: ids.remote_started ? remoteBox : insideBox,
				service,
				rate: rateText(ids.bytes_in, ids.bytes_out, formatBytes),
				to: ids.remote_started ? insideBox : remoteBox,
				blocked: false
			},
			connection: rows([
				[T.protocol, escapeHtml(protocolLabel(ids.protocol))],
				[T.inside_side, escapeHtml(ids.inside || T.this_firewall)],
				[T.via, escapeHtml(ids.public)],
				[T.remote_side, escapeHtml(ids.remote)],
				[T.state, ids.active ? pill("ok", T.active, "fa-check") : pill("muted", T.closed)],
				[T.started, ids.age ? escapeHtml(`${ago(Date.now() / 1e3 - ids.age)} ${T.ago}`) : ""],
				[T.transferred, rateText(ids.bytes_in, ids.bytes_out, formatBytes)]
			]),
			firewall: rows([
				[T.decision, pill("ok", T.allowed, "fa-check")],
				[T.interface, escapeHtml(ids.interface || "")],
				[T.rule, escapeHtml(ids.rule || "")],
				["NAT", ids.inside && insideAddress !== publicAddress ? escapeHtml(`${T.yes} (${ids.inside} → ${ids.public})`) : escapeHtml(T.no)],
				["IPS", ids.ips_dropped ? pill(serious ? "contained" : "blocked", T.ips_dropped) : ""]
			]),
			ids: idsCard(null, ids.groups),
			reputation: reputationCard({
				...item,
				address
			})
		};
	}
	function blockModel(block, context) {
		const { remoteBox, item, address } = context;
		const service = serviceParts(block.services?.[0]?.name, block.services?.[0]?.port);
		return {
			verdict: (block.lists || []).length > 0 ? bigPill("contained", T.blocked_flagged, "fa-ban") : bigPill("blocked", T.blocked, "fa-ban"),
			sub: T.blocked_attempts,
			diagram: {
				from: remoteBox,
				service,
				rate: `${escapeHtml(block.hits)}× ${escapeHtml(T.in_minutes.replace("%s", block.window_minutes))}`,
				to: endBox("fa-shield", T.this_firewall_title, [block.target, block.interface]),
				blocked: true
			},
			connection: rows([
				[T.tried, (block.services || []).map((entry) => {
					const parts = serviceParts(entry.name, entry.port);
					return `${escapeHtml(parts.name)} <span class="fwmap-muted">${escapeHtml(parts.port)}</span> ×${escapeHtml(entry.hits)}`;
				}).join("<br>")],
				[T.other_ports, block.port_count > (block.services || []).length ? escapeHtml(block.port_count - block.services.length) : ""],
				[T.attempts, escapeHtml(`${block.hits} · ${block.hits_per_minute}/min`)],
				[T.first_seen, block.seconds ? escapeHtml(`${ago(Date.now() / 1e3 - block.seconds)} ${T.ago}`) : ""]
			]),
			firewall: rows([
				[T.decision, pill("blocked", T.blocked, "fa-ban")],
				[T.interface, escapeHtml(block.interface || "")],
				[T.rule, escapeHtml(block.rule || "")],
				[T.target, escapeHtml(block.target || "")]
			]),
			ids: idsCard(block.ids, null),
			reputation: reputationCard({
				...item,
				address
			})
		};
	}
	function alertModel(alert, context) {
		const { item, address } = context;
		return {
			verdict: alert?.ids?.severity <= 2 || (alert?.lists || []).length ? bigPill("contained", `${T.ids_only} · ${T.flagged}`, "fa-flag") : bigPill("muted", T.ids_only, "fa-flag"),
			sub: T.ids_only_sub,
			diagram: null,
			connection: `<div class="text-muted">${escapeHtml(T.no_connection)}</div>`,
			firewall: `<div class="text-muted">${escapeHtml(T.no_connection)}</div>`,
			ids: idsCard(alert?.ids, null),
			reputation: reputationCard({
				...item,
				address
			})
		};
	}
	/** Everything the panel shows for one remote address of the selection. */
	function detailsModel(selection, address) {
		const flow = selection.kind === "flow" ? (selection.members || []).find((member) => member.dest === address) : null;
		const block = selection.kind === "blocked" ? selection.block : null;
		const alert = selection.kind === "alert" ? selection.alert : null;
		const ids = selection.kind === "idsflow" ? selection.idsFlow : null;
		const location = (state.data?.locations || []).find((entry) => entry.id === address) || {};
		const source = block || alert || ids || {};
		const item = {
			...location,
			...source,
			country_code: source.country_code || location.country_code
		};
		const hostname = state.data?.hostnames?.[address];
		const remote = {
			title: hostname || address,
			hostname,
			place: place(item),
			cc: item.country_code,
			org: state.settings.asn ? plain(item.as_org || "") : ""
		};
		const context = {
			item,
			address,
			remoteBox: endBox("fa-server", remote.title, [hostname ? address : "", remote.place])
		};
		return {
			...flow ? flowModel(flow, context) : ids ? idsFlowModel(ids, context) : block ? blockModel(block, context) : alertModel(alert, context),
			remote
		};
	}
	function actionBar(address, countryCode) {
		const more = [
			`<li><a href="https://bgp.he.net/ip/${encodeURIComponent(address)}" target="_blank" rel="noopener noreferrer"><i class="fa fa-globe"></i> ${escapeHtml(T.whois)}</a></li>`,
			`<li><a href="https://www.abuseipdb.com/check/${encodeURIComponent(address)}" target="_blank" rel="noopener noreferrer"><i class="fa fa-external-link"></i> AbuseIPDB</a></li>`,
			`<li><a href="#" class="fwmap-copy" data-address="${escapeHtml(address)}"><i class="fa fa-clipboard"></i> ${escapeHtml(T.copy)}</a></li>`
		];
		if (state.isAdmin) {
			more.push("<li role=\"separator\" class=\"divider\"></li>", `<li><a href="#" class="fwmap-alias" data-address="${escapeHtml(address)}"><i class="fa fa-list-ul"></i> ${escapeHtml(T.add_to_alias)}</a></li>`, `<li><a href="#" class="fwmap-mark" data-address="${escapeHtml(address)}"><i class="fa fa-flag"></i> ${escapeHtml(T.mark_threat)}</a></li>`);
			if (countryCode) more.push(`<li><a href="#" class="fwmap-country" data-code="${escapeHtml(countryCode)}"><i class="fa fa-map-marker"></i> ${escapeHtml(T.add_country)} (${escapeHtml(countryCode)})</a></li>`);
		}
		return `<div class="fwmap-actions">${(state.isAdmin ? `<button type="button" class="btn btn-primary fwmap-investigate" data-address="${escapeHtml(address)}">${ic("external")} ${escapeHtml(T.investigate)}</button>` : "") + (state.mode === "snapshot" ? `
    <button type="button" class="btn btn-default fwmap-states" data-address="${escapeHtml(address)}">${ic("list")} ${escapeHtml(T.states_at)} ${escapeHtml(capturedTime())}</button>
    ${state.isAdmin ? `<button type="button" class="btn btn-default fwmap-states-now" data-address="${escapeHtml(address)}">${ic("clock")} ${escapeHtml(T.current_states)}</button>` : ""}` : state.isAdmin ? `
    <button type="button" class="btn btn-default fwmap-states" data-address="${escapeHtml(address)}">${ic("list")} ${escapeHtml(T.show_states)}</button>
    <button type="button" class="btn btn-default fwmap-kill" data-address="${escapeHtml(address)}">${ic("trash")} ${escapeHtml(T.kill_states)}</button>` : "")}
    <div class="btn-group dropup"><button type="button" class="btn btn-default dropdown-toggle" data-toggle="dropdown" aria-haspopup="true">${escapeHtml(T.more)} <span class="caret"></span></button>
    <ul class="dropdown-menu dropdown-menu-right">${more.join("")}</ul></div></div>`;
	}
	/** "16:42" of the snapshot on screen. */
	function capturedTime() {
		return (/* @__PURE__ */ new Date((state.frozen?.meta?.taken || 0) * 1e3)).toLocaleTimeString([], {
			hour: "2-digit",
			minute: "2-digit"
		});
	}
	function diagramHtml(diagram) {
		if (!diagram) return "";
		return `<div class="fwmap-diagram">${diagram.from}
    <div class="fwmap-link${diagram.blocked ? " fwmap-link-blocked" : ""}"><div class="fwmap-link-service">${escapeHtml(diagram.service.name)}</div>
      <div class="fwmap-link-port">${escapeHtml(diagram.service.port)}</div>
      <div class="fwmap-link-arrow">${diagram.blocked ? ic("ban") : ""}</div>
      <div class="fwmap-link-rate">${diagram.rate}</div></div>
    ${diagram.to}</div>`;
	}
	function renderDetails() {
		const selection = state.selection;
		const $details = $("#fwmap-details");
		const addresses = selection ? [...new Set(selection.addresses)].filter(Boolean) : [];
		if (!addresses.length) {
			$details.html(`<div class="text-muted fwmap-empty">${escapeHtml(T.click_hint)}</div>`);
			return;
		}
		if (!addresses.includes(state.detailsAddress)) state.detailsAddress = addresses[0];
		const address = state.detailsAddress;
		const model = detailsModel(selection, address);
		const picker = addresses.length > 1 ? `<div class="fwmap-picker"><span class="text-muted">${escapeHtml(addresses.length)} ${escapeHtml(T.remote_addresses_here)}</span>` + addresses.slice(0, 12).map((entry) => `<a href="#" class="fwmap-pick${entry === address ? " active" : ""}" data-address="${escapeHtml(entry)}"${entry === address ? " aria-current=\"true\"" : ""}>${escapeHtml(entry)}</a>`).join("") + "</div>" : "";
		const investigation = state.investigations.get(address);
		const scrollTop = state.renderedSelection === selection && state.renderedAddress === address ? $details.find(".fwmap-d-scroll").scrollTop() || 0 : 0;
		state.renderedSelection = selection;
		state.renderedAddress = address;
		$details.html(`
    <div class="fwmap-d-scroll">
      <div class="fwmap-d-head">
        ${ic("globe", "fwmap-d-icon")}
        <div class="fwmap-d-title">
          <div class="fwmap-d-name">${escapeHtml(model.remote.title)}</div>
          <div class="fwmap-d-line">${model.remote.hostname ? `<b>${escapeHtml(address)}</b>` : ""}
            ${model.remote.place ? `<span>${model.remote.cc ? `${flagHtml(model.remote.cc)} ` : ""}${escapeHtml(model.remote.place)}</span>` : ""}</div>
          ${model.remote.org ? `<div class="fwmap-d-line">${escapeHtml(model.remote.org)}</div>` : ""}
        </div>
        <div class="fwmap-d-verdict">${model.verdict}<div class="fwmap-d-verdict-sub">${escapeHtml(model.sub)}</div></div>
        <a href="#" id="fwmap-details-close" title="${escapeHtml(T.close)}" aria-label="${escapeHtml(T.close)}">${ic("x")}</a>
      </div>
      ${state.mode === "snapshot" ? `<div class="fwmap-snap-notice">${ic("camera")} ${escapeHtml(T.as_captured)} ${escapeHtml(capturedTime())} · ${escapeHtml(T.may_have_closed)}</div>` : ""}
      ${picker}
      ${diagramHtml(model.diagram)}
      <div class="fwmap-cards">
        ${card("fa-bar-chart", T.sec_connection, model.connection, state.isAdmin || state.mode === "snapshot" ? {
			cls: "fwmap-states",
			address,
			title: T.show_states
		} : null)}
        ${card("fa-shield", T.sec_firewall, model.firewall, {
			href: "/ui/diagnostics/firewall/log",
			title: T.open_log
		})}
        ${model.ids}
        ${model.reputation}
      </div>
      ${investigation ? `<div class="fwmap-investigation">${investigation}</div>` : ""}
    </div>
    ${actionBar(address, selection.countryCode)}
  `);
		if (scrollTop) $details.find(".fwmap-d-scroll").scrollTop(scrollTop);
		const scroller = $details.find(".fwmap-d-scroll")[0];
		const lookupCard = $details.find(".fwmap-investigation")[0];
		const now = performance.now();
		if (state.revealInvestigation === address) state.revealing = {
			address,
			until: now + REVEAL_MS
		};
		const revealing = state.revealing?.address === address && now < state.revealing.until;
		if (scroller && lookupCard && state.revealing?.address === address) lookupCard.style.minHeight = `${Math.max(0, scroller.clientHeight - 16)}px`;
		if (scroller && lookupCard && revealing) {
			const top = scroller.scrollTop + lookupCard.getBoundingClientRect().top - scroller.getBoundingClientRect().top - 8;
			$(scroller).stop().animate({ scrollTop: top }, Math.max(0, state.revealing.until - now), "swing");
		}
	}
	//#endregion
	//#region src/palette.js
	var SERVICE_CATEGORIES = [
		["Web", /^(HTTPS?|HTTP alt|HTTPS alt)$/],
		["QUIC", /^QUIC$/],
		["DNS", /^DNS/],
		["NTP", /^NTP$/],
		["VPN", /^(OpenVPN|WireGuard|IKE|IPsec NAT-T)$/],
		["Mail", /^(SMTP|SMTPS|Submission|IMAP|IMAPS|POP3S)$/],
		["Remote access", /^(SSH|RDP)$/],
		["Push / STUN", /(Push|STUN)/]
	];
	function serviceCategory(service) {
		if (!service) return "Other";
		const match = SERVICE_CATEGORIES.find(([, pattern]) => pattern.test(service));
		return match ? match[0] : "Other";
	}
	//#endregion
	//#region page/filters.js
	function locationsById(summary) {
		return new Map((summary.locations || []).map((location) => [location.id, location]));
	}
	function flowService(flow) {
		return serviceCategory((flow.services || [])[0]);
	}
	function flowMatches(flow, locations) {
		const f = state.filters;
		const dest = locations.get(flow.dest) || {};
		if (f.traffic === "blocked") return false;
		if (f.traffic === "threats" && !flow.threat) return false;
		if (f.traffic === "ids" && !flow.ids) return false;
		if (f.traffic === "ids_flows" || f.traffic === "ids_addresses" && !flow.ids) return false;
		if (f.service && flowService(flow) !== f.service) return false;
		if (f.iface && !(flow.inside || []).some((inside) => inside.interface === f.iface)) return false;
		if (f.host && !(flow.inside || []).some((inside) => inside.ip === f.host)) return false;
		if (f.country && dest.country !== f.country) return false;
		if (f.asn && String(dest.asn || "") !== f.asn) return false;
		return true;
	}
	function blockMatches(block) {
		const f = state.filters;
		if (f.traffic === "permitted") return false;
		if (f.traffic === "threats") return false;
		if (f.traffic === "ids" && !block.ids) return false;
		if (f.traffic === "ids_flows" || f.traffic === "ids_addresses" && !block.ids) return false;
		if (f.service || f.iface || f.host) return false;
		if (f.country && block.country !== f.country) return false;
		if (f.asn && String(block.asn || "") !== f.asn) return false;
		return true;
	}
	function idsFlowMatches(flow) {
		const f = state.filters;
		if (f.traffic === "blocked" || f.traffic === "threats" && flow.severity > 2 && !(flow.lists || []).length) return false;
		if (f.host && !(flow.inside || "").startsWith(`${f.host}:`) && flow.inside !== f.host) return false;
		if (f.service || f.iface) return false;
		if (f.country && flow.country !== f.country) return false;
		return !(f.asn && String(flow.asn || "") !== f.asn);
	}
	function alertMatches(alert) {
		const f = state.filters;
		if (f.service || f.iface || f.host) return false;
		if (f.country && alert.country !== f.country) return false;
		return !(f.asn && String(alert.asn || "") !== f.asn);
	}
	function filtered(summary) {
		const locations = locationsById(summary);
		const flows = (summary.flows || []).filter((flow) => flowMatches(flow, locations));
		const blocks = state.settings.blocks ? (summary.blocks || []).filter(blockMatches) : [];
		const alerts = [
			"",
			"all",
			"ids",
			"ids_addresses"
		].includes(state.filters.traffic || "") ? (summary.alerts || []).filter(alertMatches) : [];
		const used = new Set(flows.flatMap((flow) => [flow.origin, flow.dest]));
		return {
			...summary,
			flows,
			blocks,
			alerts,
			ids_flows: (summary.ids_flows || []).filter(idsFlowMatches),
			locations: (summary.locations || []).filter((location) => location.local || used.has(location.id))
		};
	}
	//#endregion
	//#region page/investigate.js
	function scoreBadge(score) {
		return `<span class="fwmap-pill fwmap-pill-${score >= 75 ? "danger" : score >= 25 ? "warning" : score > 0 ? "contained" : "ok"}">${escapeHtml(score)}%</span>`;
	}
	function investigationCard(result) {
		if (result.status !== "ok") return `<div class="text-danger">${escapeHtml(result.error || T.action_failed)}</div>`;
		const section = (title, data, body) => `<div class="fwmap-inv-section"><div class="fwmap-inv-title">${escapeHtml(title)}</div>` + (data?.error ? `<div class="text-muted">${escapeHtml(T.lookup_failed)}: ${escapeHtml(data.error)}</div>` : body) + "</div>";
		const table = (items) => rows(items, "fwmap-inv-table");
		const rdap = result.rdap || {};
		const ripe = result.ripestat || {};
		const abuse = result.abuseipdb;
		let html = section(T.registry, rdap, table([
			[T.owner, escapeHtml(rdap.owner || rdap.name)],
			[T.network, escapeHtml([rdap.name, rdap.handle].filter(Boolean).join(" · "))],
			[T.range, escapeHtml(rdap.range)],
			[T.country, escapeHtml(rdap.country)],
			[T.abuse_contact, rdap.abuse_email ? `<a href="mailto:${escapeHtml(rdap.abuse_email)}">${escapeHtml(rdap.abuse_email)}</a>` : ""],
			[T.registered, escapeHtml([rdap.registered, rdap.updated && `${T.updated} ${rdap.updated}`].filter(Boolean).join(" · "))]
		]));
		html += section(T.routing, ripe, table([
			[T.prefix, escapeHtml(ripe.prefix)],
			[T.origin_as, (ripe.asns || []).map((item) => escapeHtml(`AS${item.asn} ${item.holder || ""}`)).join("<br>")],
			[T.announced, ripe.announced === void 0 ? "" : escapeHtml(ripe.announced ? T.yes : T.no)]
		]));
		if (abuse) html += section("AbuseIPDB", abuse, table([
			[T.confidence, abuse.score === void 0 ? "" : scoreBadge(abuse.score)],
			[T.reports, abuse.reports === void 0 ? "" : escapeHtml(`${abuse.reports} (${abuse.reporters ?? 0} ${T.reporters})`)],
			[T.last_reported, escapeHtml(abuse.last_reported)],
			[T.usage, escapeHtml([abuse.usage, abuse.tor ? "Tor" : null].filter(Boolean).join(" · "))],
			["ISP", escapeHtml([abuse.isp, abuse.domain].filter(Boolean).join(" · "))]
		]));
		else if (!result.abuseipdb_configured) html += `<div class="text-muted fwmap-inv-section">${escapeHtml(T.abuseipdb_hint)}</div>`;
		return html;
	}
	/** Keep a card for the most recent addresses only. */
	function remember(address, html) {
		state.investigations.delete(address);
		state.investigations.set(address, html);
		while (state.investigations.size > 50) state.investigations.delete(state.investigations.keys().next().value);
	}
	function noteScore(result, address) {
		if (result.abuseipdb && typeof result.abuseipdb.score === "number") {
			state.abuseScores.delete(address);
			state.abuseScores.set(address, result.abuseipdb.score);
			while (state.abuseScores.size > 500) state.abuseScores.delete(state.abuseScores.keys().next().value);
		}
	}
	var RETRY_MS = 1500;
	function failureCard(address, text) {
		return `<div class="text-danger">${escapeHtml(T.action_failed)}: ${escapeHtml(text)}</div><button type="button" class="btn btn-default btn-xs fwmap-investigate fwmap-inv-retry" data-address="${escapeHtml(address)}"><i class="fa fa-rotate-right"></i> ${escapeHtml(T.retry)}</button>`;
	}
	async function lookup(address) {
		let failure = null;
		for (let attempt = 0; attempt < 2; attempt++) {
			if (attempt) await new Promise((resolve) => setTimeout(resolve, RETRY_MS));
			try {
				const result = await postJSON(`/api/firewallmap/investigate/address/${encodeURIComponent(address)}`, {});
				if (result.status === "ok") return { result };
				failure = result.error || T.lookup_failed;
			} catch (error) {
				failure = errorText(error);
			}
		}
		return { failure };
	}
	/** The full lookup for an address; `rerender` redraws whatever shows the card, scrolled to it. */
	async function investigate(address, rerender) {
		state.revealInvestigation = address;
		remember(address, `<div class="fwmap-inv-loading"><i class="fa fa-spinner fa-spin"></i> ${escapeHtml(T.looking_up)}</div>`);
		rerender();
		state.revealInvestigation = null;
		const { result, failure } = await lookup(address);
		if (result) {
			remember(address, investigationCard(result));
			noteScore(result, address);
		} else remember(address, failureCard(address, failure));
		rerender();
	}
	/** AbuseIPDB alone, from the Reputation card: the verdict fills in without opening the full investigation. */
	async function checkAbuse(address, rerender) {
		state.abuseChecking.add(address);
		rerender();
		try {
			const result = await postJSON(`/api/firewallmap/investigate/address/${encodeURIComponent(address)}`, { sources: "abuseipdb" });
			noteScore(result, address);
			if (!state.abuseScores.has(address)) notify(`AbuseIPDB: ${result.abuseipdb?.error || result.error || T.lookup_failed}`, BootstrapDialog.TYPE_WARNING);
		} catch (error) {
			notify(`${T.action_failed}: ${errorText(error)}`, BootstrapDialog.TYPE_DANGER);
		}
		state.abuseChecking.delete(address);
		rerender();
	}
	//#endregion
	//#region page/storage.js
	function readStorage(key) {
		try {
			return window.localStorage.getItem(key);
		} catch (_) {
			return null;
		}
	}
	function writeStorage(key, value) {
		try {
			window.localStorage.setItem(key, value);
		} catch (_) {}
	}
	//#endregion
	//#region page/layout.js
	var LAYOUT_KEY = "firewallmap.layout";
	var FOLLOW_KEY = "firewallmap.follow";
	var KEY_STEP_PX = 24;
	var KEY_STEP_SHARE = .05;
	/**
	* Follow traffic: the choice made on this page wins; until one is made, the dashboard widget's
	* "Follow traffic" option decides, so the two never disagree silently.
	*/
	function readFollow() {
		const stored = readStorage(FOLLOW_KEY);
		return stored === null ? Boolean(state.settings?.follow) : stored === "1";
	}
	function setFollow(on, tellRenderer = true) {
		state.follow = Boolean(on);
		$("#fwmap-follow").toggleClass("active", state.follow).attr("aria-pressed", String(state.follow));
		writeStorage(FOLLOW_KEY, state.follow ? "1" : "0");
		if (tellRenderer) state.renderer?.setFollow(state.follow);
	}
	function readLayout() {
		try {
			return JSON.parse(readStorage(LAYOUT_KEY) || "{}") || {};
		} catch (_) {
			return {};
		}
	}
	function applyLayout(layout) {
		const $side = $("#fwmap-side");
		if (layout.side) $side.css({
			width: `${layout.side}px`,
			flex: `0 0 ${layout.side}px`
		});
		else $side.css({
			width: "",
			flex: ""
		});
		const share = layout.talkers || .5;
		$("#fwmap-talkers").css("flex", `${share} 1 0`);
		$("#fwmap-details-box").css("flex", `${1 - share} 1 0`);
		$("#fwmap-split-side").attr("aria-valuenow", Math.round($side.outerWidth() || 0));
		$("#fwmap-split-details").attr("aria-valuenow", Math.round(share * 100));
	}
	function commit() {
		applyLayout(state.layout);
		writeStorage(LAYOUT_KEY, JSON.stringify(state.layout));
		state.renderer?.resize();
	}
	/**
	* A splitter: pointer drag (the map redraws once per frame), arrow keys, double-click or Home
	* to reset. `moveTo(event)` and `step(delta)` change state.layout; `reset()` forgets the size.
	*/
	function splitter($handle, { moveTo, step, reset }) {
		let frame = null;
		const onMove = (event) => {
			moveTo(event);
			applyLayout(state.layout);
			if (frame === null) frame = requestAnimationFrame(() => {
				frame = null;
				state.renderer?.resize();
			});
		};
		const onUp = () => {
			document.removeEventListener("pointermove", onMove);
			document.removeEventListener("pointerup", onUp);
			document.removeEventListener("pointercancel", onUp);
			$handle.removeClass("fwmap-dragging");
			$("body").removeClass("fwmap-resizing");
			commit();
		};
		$handle.attr({
			tabindex: "0",
			role: "separator",
			"aria-label": T.resize_hint || $handle.attr("title")
		}).on("pointerdown", (event) => {
			event.preventDefault();
			document.addEventListener("pointermove", onMove);
			document.addEventListener("pointerup", onUp);
			document.addEventListener("pointercancel", onUp);
			$handle.addClass("fwmap-dragging");
			$("body").addClass("fwmap-resizing");
		}).on("dblclick", () => {
			reset();
			commit();
		}).on("keydown", (event) => {
			const keys = {
				ArrowLeft: -1,
				ArrowUp: -1,
				ArrowRight: 1,
				ArrowDown: 1
			};
			if (event.key in keys) {
				event.preventDefault();
				step(keys[event.key]);
				commit();
			} else if (event.key === "Home") {
				event.preventDefault();
				reset();
				commit();
			}
		});
	}
	function bindSplitters() {
		state.layout = readLayout();
		applyLayout(state.layout);
		const sideBounds = () => $("#fwmap-layout")[0].getBoundingClientRect();
		const clampSide = (width) => Math.max(220, Math.min(width, Math.round(sideBounds().width * .6)));
		splitter($("#fwmap-split-side").attr("aria-orientation", "vertical"), {
			moveTo: (event) => {
				state.layout.side = clampSide(Math.round(sideBounds().right - event.clientX - 6));
			},
			step: (direction) => {
				state.layout.side = clampSide(($("#fwmap-side").outerWidth() || 0) - direction * KEY_STEP_PX);
			},
			reset: () => {
				delete state.layout.side;
			}
		});
		const clampShare = (share) => Math.max(.15, Math.min(share, .85));
		splitter($("#fwmap-split-details").attr("aria-orientation", "horizontal"), {
			moveTo: (event) => {
				const bounds = $("#fwmap-side")[0].getBoundingClientRect();
				state.layout.talkers = clampShare((event.clientY - bounds.top) / bounds.height);
			},
			step: (direction) => {
				state.layout.talkers = clampShare((state.layout.talkers || .5) + direction * KEY_STEP_SHARE);
			},
			reset: () => {
				delete state.layout.talkers;
			}
		});
	}
	/** Drop the least important talker column when the side panel is narrow. */
	function watchSideWidth() {
		const side = document.getElementById("fwmap-side");
		const update = () => side.classList.toggle("fwmap-narrow", side.clientWidth < 470);
		if (window.ResizeObserver) new ResizeObserver(update).observe(side);
		update();
	}
	//#endregion
	//#region page/queue.js
	var VIEWS = [
		"passed",
		"firewall_blocked",
		"ips_dropped",
		"all",
		"reviewed",
		"dismissed"
	];
	var QUEUE_PAGE = 100;
	function insideNames(extra = {}) {
		const names = new Map(Object.entries(extra));
		for (const flow of state.data?.flows || []) for (const host of [...flow.inside || [], ...flow.targets || []]) if (host.name && host.ip) names.set(host.ip, host.name);
		return names;
	}
	function queueItem(row, names) {
		const insideAddresses = new Set(row.inside || []);
		const ports = row.service_ports || {};
		const serviceFor = (protocol, port) => Object.keys(ports).find((name) => ports[name] === `${port}/${protocol}`) || (port ? `${protocolLabel(protocol)}/${port}` : "ICMP");
		const disposition = [
			"passed",
			"firewall_blocked",
			"ips_dropped"
		].includes(row.disposition) ? row.disposition : "passed";
		const wanted = {
			passed: "pass",
			firewall_blocked: "block"
		}[disposition];
		const conns = [...row.connections || []].sort((a, b) => (b.decision === wanted) - (a.decision === wanted));
		const lead = conns[0];
		const leadTarget = lead && lead.remote_started ? (() => {
			const [ip, port] = splitHostPort(lead.inside || lead.public || "");
			return `${lead.protocol}|${ip}|${port}`;
		})() : null;
		const targets = [...row.targets || []].sort((a, b) => (b === leadTarget) - (a === leadTarget)).map((target) => {
			const [protocol, ip, port] = String(target).split("|");
			const firewall = !privateAddress(ip) && !insideAddresses.has(ip);
			return {
				ip,
				port,
				protocol,
				name: firewall ? "firewall" : names.get(ip),
				firewall,
				service: (row.target_services || {})[target] || serviceFor(protocol, port)
			};
		});
		const pseudo = {
			initiated: row.inbound && row.outbound ? "both" : row.inbound ? "remote" : "local",
			targets,
			inside: (row.inside || []).map((ip) => ({
				ip,
				name: names.get(ip)
			})),
			services: row.services || [],
			service_ports: ports
		};
		const live = remoteOf(row.address);
		const saved = row.remote || {};
		const remote = {
			ip: row.address,
			hostname: saved.hostname || live.hostname,
			org: state.settings.asn ? saved.org || live.org : null,
			country: saved.country || live.country
		};
		const lines = flowSummary(pseudo, remote, TEXT).map(escapeHtml);
		const address = escapeHtml(row.address);
		const status = [
			"new",
			"reviewed",
			"blocked",
			"dismissed"
		].includes(row.status) ? row.status : "new";
		const inbound = pseudo.initiated !== "local";
		const target = targets[0];
		const inside = pseudo.inside[0];
		let localIcon = "shield";
		let localName = T.this_firewall_title;
		let localLines = [];
		let otherTargets = "";
		let service = row.services?.[0] ? `${row.services[0]}${ports[row.services[0]] ? ` · ${ports[row.services[0]].split("/").reverse().join("/").toUpperCase()}` : ""}` : "";
		if (inbound && target) {
			service = `${target.service}${target.port ? ` · ${protocolLabel(target.protocol)}/${target.port}` : ""}`;
			if (!target.firewall) {
				localIcon = "server";
				localName = target.name || target.ip;
				localLines = [target.name ? target.ip : "", T.port_forward];
			} else {
				const via = (row.connections || []).find((item) => item.interface && splitHostPort(item.public || "")[0] === target.ip);
				localLines = [via ? `${target.ip} · ${via.interface}` : target.ip];
			}
			if (targets.length > 1) otherTargets = `+ ${targets.length - 1} ${targets.length > 2 ? T.other_targets : T.other_target}`;
		} else if (!inbound && inside) {
			localIcon = "laptop";
			localName = inside.name || inside.ip;
			localLines = [inside.name ? inside.ip : ""];
			if (pseudo.inside.length > 1) localLines.push(`+ ${pseudo.inside.length - 1} ${T.other_hosts}`);
		}
		const cc = saved.country_code || live.country_code || countryCodeOf(remote.country);
		if (lead && lead.inside && !inbound) {
			const [leadIp] = splitHostPort(lead.inside);
			localIcon = "laptop";
			localName = lead.inside_name || names.get(leadIp) || leadIp;
			localLines = [lead.inside, conns.length > 1 ? `+ ${conns.length - 1} ${conns.length > 2 ? T.more_connections : T.more_connection}` : ""];
		}
		const rule = lead ? lead.rule || conns.find((item) => item.decision === lead.decision && item.rule)?.rule : null;
		const decision = (item) => [item.decision === "pass" ? pill("ok", T.fw_passed) : item.decision === "block" ? pill("blocked", T.fw_blocked) : `<span class="fwmap-q-muted">${escapeHtml(T.fw_not_seen)}</span>`, item.ips_dropped ? pill("contained", T.ips_dropped_short) : ""].filter(Boolean).join(" ");
		const connTable = conns.length ? `<table class="fwmap-q-conns"><thead><tr><th>${escapeHtml(T.connection_col)}</th><th>${escapeHtml(T.decision)}</th><th>${escapeHtml(T.rule)}</th><th>${escapeHtml(T.interface)}</th><th>${escapeHtml(T.transferred)}</th><th>${escapeHtml(T.started)}</th><th>IDS</th></tr></thead><tbody>` + conns.map((item) => {
			const insideText = `${item.inside_name ? `${item.inside_name} ` : ""}${item.inside || T.this_firewall}`;
			const path = item.remote_started ? `${item.remote} → ${insideText}` : `${insideText} → ${item.remote}`;
			const ids = (item.ids || []).map((sig) => `<div class="${sig.severity <= 2 ? "fwmap-ids-high" : "fwmap-ids"}">${ic("flag")} ${escapeHtml(sig.signature)} ×${escapeHtml(sig.count)}</div>` + (sig.query ? `<div class="fwmap-q-muted">${escapeHtml(T.query)}: ${escapeHtml(sig.query)}</div>` : "")).join("");
			return `<tr><td><div>${escapeHtml(path)} <span class="fwmap-q-muted">${escapeHtml(protocolLabel(item.protocol))}</span></div><div class="fwmap-q-muted">${escapeHtml(T.via)} ${escapeHtml(item.public || "")}${item.open ? "" : ` · ${escapeHtml(T.closed)}`}</div></td><td>${decision(item)}</td><td>${escapeHtml(item.rule || "—")}</td><td>${escapeHtml(item.interface || "—")}</td><td>↓ ${escapeHtml(formatBytes(item.bytes_in || 0))} ↑ ${escapeHtml(formatBytes(item.bytes_out || 0))}</td><td>${item.started ? escapeHtml(`${ago(item.started)} ${T.ago}`) : "—"}</td><td>${ids || "<span class=\"fwmap-q-muted\">—</span>"}</td></tr>`;
		}).join("") + "</tbody></table>" : "";
		const org = saved.org || live.org;
		const chips = (row.lists || []).map((name) => `<span class="fwmap-q-chip">${escapeHtml(listLabel(name))}</span>`).join("");
		const expanded = state.queueExpanded.has(row.address);
		const card = state.investigations.get(row.address);
		const btn = (cls, icon, label, extra = "") => `<button type="button" class="btn btn-default ${cls}" ${extra}>${ic(icon)}<span>${escapeHtml(label)}</span></button>`;
		const link = (href, icon, label) => `<a class="btn btn-default" href="${href}" target="_blank" rel="noopener noreferrer">${ic(icon)}<span>${escapeHtml(label)}</span></a>`;
		const review = status === "new" ? btn("fwmap-q-status", "check", T.mark_reviewed, "data-status=\"reviewed\"") : btn("fwmap-q-status", "undo", T.reopen, "data-status=\"new\"");
		return `<div class="fwmap-q-item fwmap-q-${status}${expanded ? " fwmap-q-open" : ""}" data-address="${address}" data-status="${status}">
    <div class="fwmap-q-top">
      <div class="fwmap-q-who">
        <div class="fwmap-q-ipline"><span class="fwmap-q-ip">${address}</span>
          <span class="fwmap-q-badge fwmap-q-disposition-${disposition}">${escapeHtml(T[`disposition_${disposition}`])}</span>
          ${status !== "new" ? `<span class="fwmap-q-workflow">${escapeHtml(T[`status_${status}`])}</span>` : ""}</div>
        ${remote.hostname ? `<div class="fwmap-q-hostname" title="${escapeHtml(remote.hostname)}">${escapeHtml(remote.hostname)}</div>` : ""}
        ${org ? `<div class="fwmap-q-org">${escapeHtml(org)}</div>` : ""}
        ${remote.country ? `<div class="fwmap-q-country">${flagHtml(cc)}${escapeHtml(remote.country)}</div>` : ""}
        ${chips ? `<div class="fwmap-q-chips">${chips}</div>` : ""}
      </div>
      <div class="fwmap-q-flow">
        <div class="fwmap-q-diagram">
          ${ic("globe", "fwmap-q-end")}
          <div class="fwmap-q-link">
            <div class="fwmap-q-svc">${escapeHtml(service)}</div>
            <div class="fwmap-q-arrow ${inbound ? "fwmap-q-arrow-in" : "fwmap-q-arrow-out"}"></div>
            <span class="fwmap-q-dirpill">${escapeHtml(inbound ? `↘ ${T.inbound}` : `↖ ${T.outbound}`)}</span>
          </div>
          ${ic(localIcon, "fwmap-q-end")}
          <div class="fwmap-q-local"><div class="fwmap-q-local-name">${escapeHtml(localName)}</div>
            ${localLines.filter(Boolean).map((line, index) => `<div class="${index ? "fwmap-q-muted" : ""}">${escapeHtml(line)}</div>`).join("")}
            ${otherTargets ? `<a href="#" class="fwmap-q-expand fwmap-q-muted" aria-expanded="${expanded}">${escapeHtml(otherTargets)}</a>` : ""}</div>
        </div>
        <div class="fwmap-q-meta">
          <span>${ic("calendar")} ${escapeHtml(T.first_seen)} ${escapeHtml(ago(row.first_seen))} ${escapeHtml(T.ago)}</span>
          <span>${ic("chart")} ${escapeHtml(row.samples)} ${escapeHtml(row.samples === 1 ? T.sample : T.samples)}</span>
          <span>${ic("swap")} ${escapeHtml(T.peak)} ${escapeHtml(formatBytes(row.peak_bytes || 0))}</span>
          ${rule ? `<span title="${escapeHtml(T.rule)}">${ic("shield")} ${escapeHtml(rule)}</span>` : ""}
        </div>
        ${idsLines(row.ids, TEXT)}
      </div>
      <div class="fwmap-q-when">
        <span title="${escapeHtml((/* @__PURE__ */ new Date(row.last_seen * 1e3)).toLocaleString())}">${ic("clock")} ${escapeHtml(ago(row.last_seen))} ${escapeHtml(T.ago)}</span>
        <a href="#" class="fwmap-q-expand" title="${escapeHtml(T.more_details)}" aria-label="${escapeHtml(T.more_details)}" aria-expanded="${expanded}">${ic(expanded ? "chevron-down" : "chevron")}</a>
      </div>
    </div>
    ${row.seen_after_block ? `<div class="fwmap-q-warning">${ic("alert")} ${escapeHtml(T.seen_after_block)}</div>` : ""}
    ${expanded ? `<div class="fwmap-q-more">${lines.map((line) => `<div>${line}</div>`).join("")}
      ${targets.length > 1 ? `<div class="fwmap-q-muted">${escapeHtml(T.targets_seen)}: ${targets.map((item) => escapeHtml(`${item.firewall ? T.this_firewall : item.name || item.ip} (${hostPort(item.ip, item.port)}${item.service ? `, ${item.service}` : ""})`)).join(" · ")}</div>` : ""}
      ${(row.services || []).length ? `<div class="fwmap-q-muted">${escapeHtml(T.services_seen)}: ${(row.services || []).map(escapeHtml).join(", ")}</div>` : ""}
      ${connTable || `<div class="fwmap-q-muted">${escapeHtml(T.no_snapshot)}</div>`}</div>` : ""}
    ${row.note ? `<div class="fwmap-q-note">${escapeHtml(row.note)}</div>` : ""}
    ${card ? `<div class="fwmap-investigation">${card}</div>` : ""}
    <div class="fwmap-q-bar">
      <div class="fwmap-q-left">
        <button type="button" class="btn btn-primary fwmap-q-investigate">${ic("search")}<span>${escapeHtml(T.investigate)}</span></button>
        ${btn("fwmap-q-states", "list", T.show_states)}
        ${link(`https://bgp.he.net/ip/${encodeURIComponent(row.address)}`, "globe", T.whois)}
        ${link(`https://www.abuseipdb.com/check/${encodeURIComponent(row.address)}`, "external", "AbuseIPDB")}
      </div>
      <div class="fwmap-q-right">
        ${review}
        ${status !== "dismissed" ? btn("fwmap-q-status", "eye-off", T.dismiss, "data-status=\"dismissed\"") : ""}
        <button type="button" class="btn btn-danger fwmap-q-block">${ic("ban")}<span>${escapeHtml(T.block)}</span></button>
        <div class="btn-group">
          <button type="button" class="btn btn-default dropdown-toggle fwmap-q-menu" data-toggle="dropdown" aria-haspopup="true" aria-label="${escapeHtml(T.more)}">${ic("chevron-down")}</button>
          <ul class="dropdown-menu dropdown-menu-right">
            <li><a href="#" class="fwmap-q-edit-note">${escapeHtml(T.edit_note)}</a></li>
            <li><a href="#" class="fwmap-q-kill">${escapeHtml(T.kill_states)}</a></li>
          </ul>
        </div>
      </div>
    </div>
  </div>`;
	}
	/** Country name to code from the live map (older queue entries only stored the name). */
	function countryCodeOf(name) {
		const match = (state.data?.locations || []).find((location) => location.country === name && location.country_code);
		return match ? match.country_code : "";
	}
	async function refreshQueueCount() {
		if (document.hidden) return;
		try {
			const result = await getJSON("/api/firewallmap/threats/list/counts");
			$("#fwmap-review-count").text(result.counts?.passed || "");
		} catch (_) {
			$("#fwmap-review-count").text("");
		}
	}
	async function setThreat(address, status, note) {
		const payload = {
			address,
			status
		};
		if (note !== void 0) payload.note = note;
		const result = await postJSON("/api/firewallmap/threats/set", payload);
		if (result.result !== "saved") throw new Error(result.error || T.action_failed);
	}
	function blacklistStatus(settings) {
		const status = settings.abuseipdb_blacklist || {};
		let text = T.blacklist_no_key;
		if (settings.abuseipdb_configured) {
			text = status.updated ? `${Number(status.count).toLocaleString()} ${T.blacklist_addresses}, ${T.updated} ${(/* @__PURE__ */ new Date(status.updated * 1e3)).toLocaleString([], {
				dateStyle: "medium",
				timeStyle: "short"
			})}` : T.blacklist_pending;
			if (status.error) text += ` (${T.blacklist_error}: ${plain(status.error)})`;
		}
		return $("<div class=\"fwmap-q-source\"></div>").attr("title", T.blacklist).append(`${ic("layers")} `).append($("<span></span>").text(`${T.blacklist_short}: ${text}`));
	}
	/** The Threats dialog. The server pages and searches it: history can hold thousands of entries. */
	async function showQueue() {
		const view = {
			status: "passed",
			rows: [],
			total: 0,
			counts: {},
			names: {},
			query: "",
			seq: 0
		};
		const $body = $("<div></div>");
		const settings = state.pluginSettings || {};
		const $record = $(`<label class="fwmap-q-record" title="${escapeHtml(T.record_threats_hint)}"><input type="checkbox"> ${escapeHtml(T.record_threats)}</label>`);
		$record.find("input").prop("checked", settings.record_threats !== "0").on("change", async function() {
			try {
				await postJSON("/api/firewallmap/settings/set", { record_threats: this.checked ? "1" : "0" });
				if (state.pluginSettings) state.pluginSettings.record_threats = this.checked ? "1" : "0";
			} catch (error) {
				notifyFailure(error);
			}
		});
		const $tabs = $(`<ul class="nav nav-pills fwmap-q-tabs" role="tablist" aria-label="${escapeHtml(T.review_queue)}"></ul>`);
		const $bulk = $("<div class=\"fwmap-q-bulkbar\"></div>");
		const $search = $(`<input type="search" class="form-control input-sm fwmap-q-search" placeholder="${escapeHtml(T.queue_search)}" aria-label="${escapeHtml(T.queue_search)}">`);
		const $list = $("<div class=\"fwmap-q-list\" aria-live=\"polite\"></div>");
		const $searchBox = $(`<div class="fwmap-q-searchbox">${ic("search")}</div>`).append($search);
		$body.append($("<div class=\"fwmap-q-toolbar\"></div>").append($tabs, $bulk, $searchBox), $list);
		const emptyText = () => view.query ? T.queue_no_match : T[`queue_empty_${view.status}`] || T.queue_empty;
		const render = () => {
			$tabs.html(VIEWS.map((status) => `<li class="${status === view.status ? "active" : ""}" role="presentation"><a href="#" role="tab" aria-selected="${status === view.status}" data-status="${status}">${escapeHtml(T[`status_${status}`])}${view.counts[status] ? ` <span class="badge">${escapeHtml(view.counts[status])}</span>` : ""}</a></li>`).join(""));
			const names = insideNames(view.names);
			$list.html(view.rows.length ? view.rows.map((row) => queueItem(row, names)).join("") + (view.total > view.rows.length ? `<div class="fwmap-q-moreitems"><button type="button" class="btn btn-default fwmap-q-showmore">${escapeHtml(T.show_more.replace("%s", Math.min(QUEUE_PAGE, view.total - view.rows.length)))}</button> <span class="fwmap-q-muted">${escapeHtml(T.showing.replace("%s", view.rows.length).replace("%t", view.total))}</span></div>` : "") : `<div class="text-muted fwmap-empty fwmap-q-empty">${ic("check")} ${escapeHtml(emptyText())}</div>`);
			const count = view.query ? view.total : view.counts[view.status] || 0;
			const bulk = [];
			if ([
				"passed",
				"firewall_blocked",
				"ips_dropped"
			].includes(view.status) && count) {
				const label = view.query ? T.dismiss_shown : T.dismiss_all;
				bulk.push(`<button type="button" class="btn btn-default fwmap-q-bulk" data-to="dismissed">${ic("eye-off")}<span>${escapeHtml(label.replace("%s", count))}</span></button>`);
			}
			if ((view.status === "dismissed" || view.status === "reviewed") && count) {
				const label = view.query ? T.delete_shown : T.delete_all;
				bulk.push(`<button type="button" class="btn btn-default fwmap-q-purge">${ic("trash")}<span>${escapeHtml(label.replace("%s", count))}</span></button>`);
			}
			$bulk.html(bulk.join(""));
		};
		const url = (offset, limit) => `/api/firewallmap/threats/list/${view.status}?offset=${offset}&limit=${limit}` + (view.query ? `&q=${encodeURIComponent(view.query)}` : "");
		/** First page of the current tab and search; `more` appends the next page instead. */
		const load = async (more = false) => {
			const seq = ++view.seq;
			try {
				const result = await getJSON(more ? url(view.rows.length, QUEUE_PAGE) : url(0, Math.max(QUEUE_PAGE, view.rows.length)));
				if (seq !== view.seq) return;
				view.rows = more ? view.rows.concat(result.rows || []) : result.rows || [];
				view.total = result.total ?? view.rows.length;
				view.counts = result.counts || {};
				view.names = result.names || {};
				$(".fwmap-q-newcount b").text(view.counts.passed || 0);
				$("#fwmap-review-count").text(view.counts.passed || "");
			} catch (error) {
				if (seq === view.seq) notifyFailure(error);
			}
			if (seq === view.seq) render();
		};
		const act = async (work) => {
			try {
				await work();
			} catch (error) {
				notifyFailure(error);
			}
			load();
		};
		const addressOf = (element) => String($(element).closest(".fwmap-q-item").data("address"));
		const rowOf = (address) => view.rows.find((row) => row.address === address) || {};
		let typing = null;
		$search.on("input", () => {
			clearTimeout(typing);
			typing = setTimeout(() => {
				view.query = String($search.val() || "").trim();
				view.rows = [];
				load();
			}, 250);
		});
		$bulk.on("click", ".fwmap-q-bulk", function() {
			const to = String($(this).data("to"));
			const count = view.query ? view.total : view.counts[view.status] || 0;
			confirmAction((view.query ? T.dismiss_shown_confirm : T.dismiss_all_confirm).replace("%s", count), () => act(async () => {
				const result = await postJSON("/api/firewallmap/threats/bulk", {
					from: view.status,
					to,
					query: view.query
				});
				if (result.result !== "saved") throw new Error(result.error || T.action_failed);
			}));
		}).on("click", ".fwmap-q-purge", function() {
			const count = view.query ? view.total : view.counts[view.status] || 0;
			confirmAction(T.delete_all_confirm.replace("%s", count).replace("%status", T[`status_${view.status}`]), () => act(async () => {
				const result = await postJSON("/api/firewallmap/threats/purge", {
					status: view.status,
					query: view.query
				});
				if (result.result !== "deleted") throw new Error(result.error || T.action_failed);
			}));
		});
		$tabs.on("click", "a", function(event) {
			event.preventDefault();
			view.status = String($(this).data("status"));
			view.rows = [];
			load();
		});
		$list.on("click", ".fwmap-q-status", function() {
			const address = addressOf(this);
			act(() => setThreat(address, String($(this).data("status"))));
		}).on("click", ".fwmap-q-showmore", () => load(true)).on("click", ".fwmap-q-expand", function(event) {
			event.preventDefault();
			const address = addressOf(this);
			if (state.queueExpanded.has(address)) state.queueExpanded.delete(address);
			else state.queueExpanded.add(address);
			render();
		}).on("click", ".fwmap-q-edit-note", function(event) {
			event.preventDefault();
			const address = addressOf(this);
			const $text = $("<textarea class=\"form-control\" rows=\"4\" maxlength=\"800\"></textarea>").attr("aria-label", `${T.note_title} ${address}`).val(plain(rowOf(address).note || ""));
			BootstrapDialog.show({
				title: escapeHtml(`${T.note_title} ${address}`),
				message: $text,
				buttons: [{
					label: T.cancel,
					action: (dialog) => dialog.close()
				}, {
					label: T.save,
					cssClass: "btn-primary",
					action: (dialog) => {
						dialog.close();
						act(() => setThreat(address, rowOf(address).status || "new", String($text.val())));
					}
				}]
			});
		}).on("click", ".fwmap-q-block", function() {
			const address = addressOf(this);
			chooseAlias([
				"host",
				"hosts",
				"network",
				"networks"
			], escapeHtml(`${T.block_title}: ${address}`), (name) => {
				confirmAction(`${T.add_confirm} ${address} → ${name}? ${T.block_hint}`, () => act(async () => {
					await addAddressToAlias(name, address);
					const note = [plain(rowOf(address).note || ""), `→ ${name} (${(/* @__PURE__ */ new Date()).toLocaleString()})`].filter(Boolean).join("\n");
					await setThreat(address, "blocked", note);
				}));
			});
		}).on("click", ".fwmap-q-investigate, .fwmap-inv-retry", (event) => {
			event.preventDefault();
			investigate(addressOf(event.currentTarget), render);
		}).on("click", ".fwmap-q-states", function(event) {
			event.preventDefault();
			showStates(addressOf(this));
		}).on("click", ".fwmap-q-kill", function(event) {
			event.preventDefault();
			killStates(addressOf(this));
		});
		const $footer = $("<div class=\"fwmap-q-footer\"></div>").append($record).append(blacklistStatus(settings));
		BootstrapDialog.show({
			title: `<div class="fwmap-q-titlebar">${ic("list-box", "fwmap-q-title-ic")}<div><div class="fwmap-q-title">${escapeHtml(T.review_queue)}</div><div class="fwmap-q-subtitle">${escapeHtml(T.review_intro)}</div></div><span class="fwmap-q-newcount"><b></b> ${escapeHtml(T.passed_attention)}</span></div>`,
			size: BootstrapDialog.SIZE_WIDE,
			message: $body,
			cssClass: "fwmap-q-dialog",
			buttons: [{
				label: T.close,
				action: (dialog) => dialog.close()
			}],
			onshown: (dialog) => {
				dialog.getModalFooter().prepend($footer);
				$(".fwmap-q-newcount b").text(view.counts.passed ?? "");
			},
			onhidden: () => refreshQueueCount()
		});
		load();
	}
	//#endregion
	//#region page/snapshots.js
	var TIMELINE_KEY = "firewallmap.timeline";
	var hooks = {
		refresh: () => {},
		renderTabs: () => {},
		renderDetails: () => {},
		setTab: () => {},
		setFollow: () => {}
	};
	var timelineOpen = readStorage(TIMELINE_KEY) === "1";
	/** "Fri 3 Oct, 16:42:10" in the browser's language. */
	function takenText(meta, withDate = true) {
		const date = /* @__PURE__ */ new Date((meta?.taken || 0) * 1e3);
		const time = date.toLocaleTimeString([], {
			hour: "2-digit",
			minute: "2-digit",
			second: "2-digit"
		});
		if (!withDate) return time;
		return `${(/* @__PURE__ */ new Date()).toDateString() === date.toDateString() ? T.today : date.toLocaleDateString([], {
			weekday: "short",
			day: "numeric",
			month: "short"
		})}, ${time}`;
	}
	function countsText(meta) {
		const parts = [plural(T, "snapshot_flows", meta.flows || 0)];
		if (meta.flagged) parts.push(`<span class="fwmap-snap-flagged">${escapeHtml(plural(T, "snapshot_flagged", meta.flagged))}</span>`);
		return parts.map((part, index) => index ? part : escapeHtml(part)).join(" · ");
	}
	async function loadSnapshots() {
		try {
			const result = await getJSON("/api/firewallmap/snapshots/list");
			state.snapshots = result.snapshots || [];
			state.snapshotsKept = {
				keep: result.keep || 50,
				keep_days: result.keep_days || 30
			};
		} catch (error) {
			console.error("Firewall Map+: snapshot list unavailable", error);
			state.snapshots = [];
		}
		if (state.frozen && !state.snapshots.some((meta) => meta.id === state.frozen.meta.id)) state.snapshots = [state.frozen.meta, ...state.snapshots];
		renderChrome();
	}
	/** The camera: a flash, a saved snapshot, a note that offers to open it. Nothing to fill in. */
	async function takeSnapshot() {
		const frame = document.getElementById("fwmap-map");
		window.FirewallMapRenderer.host.flash(frame);
		const $button = $("#fwmap-camera").prop("disabled", true);
		try {
			const result = await postJSON("/api/firewallmap/snapshots/save", {});
			if (result.result !== "saved") throw new Error(result.error || result.result);
			const meta = result.snapshot;
			const note = window.FirewallMapRenderer.host.toast(frame, `${ic("check", "fwmap-toast-ok")}<span><b>${escapeHtml(T.snapshot_saved)}</b> <span class="fwmap-muted">· ${escapeHtml(takenText(meta, false))} · ${countsText(meta)}</span></span><button type="button" class="btn btn-primary btn-xs fwmap-toast-open">${escapeHtml(T.snapshot_open)}</button>`);
			$(note).find(".fwmap-toast-open").on("click", () => {
				note.remove();
				openSnapshot(meta.id);
			});
			await loadSnapshots();
		} catch (error) {
			if (error?.message === "too_soon") window.FirewallMapRenderer.host.toast(frame, `<span>${escapeHtml(T.snapshot_too_soon)}</span>`);
			else notifyFailure(error);
		} finally {
			$button.prop("disabled", false);
		}
	}
	async function openSnapshot(id) {
		try {
			const result = await getJSON(`/api/firewallmap/snapshots/get/${encodeURIComponent(id)}?blocks_min=${state.settings?.blockMin ?? 3}`);
			if (result.result !== "ok") throw new Error(result.error || result.result);
			enterSnapshotMode(result.snapshot, result.data);
		} catch (error) {
			notifyFailure(error);
		}
	}
	function enterSnapshotMode(meta, data) {
		timelineDay = dayKey(meta);
		if (state.mode !== "snapshot") state.tabBeforeSnapshots = state.talkerTab;
		state.mode = "snapshot";
		state.frozen = {
			meta,
			data
		};
		state.data = data;
		state.selection = null;
		state.renderer.setFrozen(true);
		state.renderer.setFollow(false);
		hooks.setTab("snapshots");
		hooks.refresh();
		hooks.renderDetails();
		renderChrome();
	}
	function backToLive() {
		if (state.mode === "live") return;
		state.mode = "live";
		state.frozen = null;
		state.selection = null;
		state.renderer.setFrozen(false);
		state.data = state.live;
		hooks.setTab(state.tabBeforeSnapshots && state.tabBeforeSnapshots !== "snapshots" ? state.tabBeforeSnapshots : "hosts");
		state.tabBeforeSnapshots = null;
		hooks.setFollow(state.follow);
		if (state.data) hooks.refresh();
		hooks.renderDetails();
		renderChrome();
	}
	/** The header switch: Snapshots opens the newest one (or the one already on screen). */
	function chooseMode(mode) {
		if (mode === "live") backToLive();
		else if (state.mode !== "snapshot" && state.snapshots.length) openSnapshot(state.snapshots[0].id);
	}
	function editNote() {
		const meta = state.frozen?.meta;
		if (!meta) return;
		const $input = $("<textarea class=\"form-control\" rows=\"3\" maxlength=\"500\"></textarea>").val(meta.note || "").attr("aria-label", T.snapshot_note);
		BootstrapDialog.show({
			title: escapeHtml(`${T.snapshot_note} · ${takenText(meta)}`),
			message: $("<div></div>").append($input),
			onshown: () => $input.trigger("focus"),
			buttons: [{
				label: T.cancel,
				action: (dialog) => dialog.close()
			}, {
				label: T.save,
				cssClass: "btn-primary",
				action: async (dialog) => {
					dialog.close();
					try {
						const result = await postJSON(`/api/firewallmap/snapshots/note/${encodeURIComponent(meta.id)}`, { note: String($input.val() || "") });
						if (result.result !== "saved") throw new Error(result.error || result.result);
						state.frozen.meta = result.snapshot;
						await loadSnapshots();
					} catch (error) {
						notifyFailure(error);
					}
				}
			}]
		});
	}
	function download() {
		const frozen = state.frozen;
		if (!frozen) return;
		const blob = new Blob([JSON.stringify({
			snapshot: frozen.meta,
			data: frozen.data
		}, null, 1)], { type: "application/json" });
		const link = document.createElement("a");
		link.href = URL.createObjectURL(blob);
		link.download = `firewall-map-${frozen.meta.id}.json`;
		document.body.appendChild(link);
		link.click();
		link.remove();
		setTimeout(() => URL.revokeObjectURL(link.href), 1e3);
	}
	function remove() {
		const meta = state.frozen?.meta;
		if (!meta) return;
		confirmAction(`${T.snapshot_delete_confirm} ${takenText(meta)}?`, async () => {
			try {
				const result = await postJSON(`/api/firewallmap/snapshot_admin/delete/${encodeURIComponent(meta.id)}`, {});
				if (result.result !== "deleted") throw new Error(result.error || result.result);
				const index = state.snapshots.findIndex((item) => item.id === meta.id);
				state.frozen = null;
				await loadSnapshots();
				const next = state.snapshots[Math.min(Math.max(index, 0), state.snapshots.length - 1)];
				if (next) openSnapshot(next.id);
				else backToLive();
			} catch (error) {
				notifyFailure(error);
			}
		});
	}
	/** Step to the next older (+1) or newer (-1) snapshot. */
	function step(direction) {
		const index = state.snapshots.findIndex((meta) => meta.id === state.frozen?.meta.id);
		const next = state.snapshots[index + direction];
		if (next) openSnapshot(next.id);
	}
	function renderBanner() {
		const $banner = $("#fwmap-banner");
		const frozen = state.frozen;
		if (state.mode !== "snapshot" || !frozen) {
			$banner.hide().empty();
			return;
		}
		const meta = frozen.meta;
		const note = meta.note ? ` · <span class="fwmap-snap-note">“${escapeHtml(meta.note)}”</span>` : "";
		const partial = meta.partial ? ` · <span class="fwmap-muted" title="${escapeHtml(T.snapshot_partial_hint)}">${escapeHtml(T.snapshot_partial)}</span>` : "";
		$banner.html(`
    ${ic("camera", "fwmap-banner-ic")}
    <span class="fwmap-banner-text"><b>${escapeHtml(T.snapshot)} · ${escapeHtml(takenText(meta))}</b>${meta.user ? ` <span class="fwmap-banner-counts">· ${escapeHtml(T.snapshot_by)} ${escapeHtml(meta.user)}</span>` : ""}${note}
      <span class="fwmap-banner-counts">· ${countsText(meta)}${partial}</span></span>
    <span class="fwmap-banner-actions">
      <button type="button" class="btn btn-default btn-sm fwmap-snap-note-btn">${ic("edit")} ${escapeHtml(meta.note ? T.snapshot_edit_note : T.snapshot_add_note)}</button>
      <button type="button" class="btn btn-default btn-sm fwmap-snap-download" title="${escapeHtml(T.snapshot_download)}" aria-label="${escapeHtml(T.snapshot_download)}">${ic("download")}</button>
      ${state.isAdmin ? `<button type="button" class="btn btn-default btn-sm fwmap-snap-delete" title="${escapeHtml(T.snapshot_delete)}" aria-label="${escapeHtml(T.snapshot_delete)}">${ic("trash")}</button>` : ""}
    </span>`).show();
	}
	var CLUSTER_PX = 18;
	var STRIP_GAP_PX = 34;
	var timelineDay = null;
	function dayKey(meta) {
		return (/* @__PURE__ */ new Date((meta?.taken || 0) * 1e3)).toDateString();
	}
	function dayLabel(key) {
		const date = new Date(key);
		return (/* @__PURE__ */ new Date()).toDateString() === key ? T.today : date.toLocaleDateString([], {
			weekday: "short",
			day: "numeric",
			month: "short"
		});
	}
	/** The badge over a dot: when and by whom, what it holds, the note. */
	function tipHtml(meta) {
		return `<span class="fwmap-tl-tip" role="tooltip"><b>${escapeHtml(takenText(meta))}</b>
    ${meta.user ? `<span class="fwmap-muted">${escapeHtml(T.snapshot_by)} ${escapeHtml(meta.user)}</span>` : ""}
    <span>${countsText(meta)}</span>
    ${meta.note ? `<span class="fwmap-snap-note">“${escapeHtml(meta.note)}”</span>` : ""}</span>`;
	}
	/** A tick every 5 min … 6 h, whichever gives four to seven labels over `span` seconds. */
	function tickStep(span) {
		return [
			300,
			600,
			900,
			1800,
			3600,
			7200,
			10800,
			21600
		].find((stepSeconds) => span / stepSeconds <= 7) || 21600;
	}
	function timeLabel(seconds) {
		return (/* @__PURE__ */ new Date(seconds * 1e3)).toLocaleTimeString([], {
			hour: "2-digit",
			minute: "2-digit"
		});
	}
	/** Lay out one day's snapshots on the track: numbered dots for close ones, a zoomed strip on hover. */
	function layoutTrack($track, day) {
		const width = $track.width() || 300;
		const metas = day.slice().sort((a, b) => a.taken - b.taken);
		const first = metas[0].taken;
		const last = metas[metas.length - 1].taken;
		const span = Math.max(last - first, 1200);
		const middle = (first + last) / 2;
		const start = middle - span * .56;
		const end = middle + span * .56;
		const x = (taken) => (taken - start) / (end - start) * width;
		const step = tickStep(end - start);
		let ticks = "";
		for (let tick = Math.ceil(start / step) * step; tick <= end; tick += step) ticks += `<span class="fwmap-tl-tick" style="left:${x(tick).toFixed(1)}px">${escapeHtml(timeLabel(tick))}</span>`;
		const groups = [];
		for (const meta of metas) {
			const position = x(meta.taken);
			const group = groups[groups.length - 1];
			if (group && position - group.x0 < CLUSTER_PX) {
				group.items.push(meta);
				group.x1 = position;
			} else groups.push({
				x0: position,
				x1: position,
				items: [meta]
			});
		}
		const currentId = state.frozen?.meta.id;
		const dots = groups.map((group) => {
			const center = (group.x0 + group.x1) / 2;
			const current = group.items.some((meta) => meta.id === currentId);
			if (group.items.length === 1) {
				const meta = group.items[0];
				return `<button type="button" class="fwmap-tl-dot${current ? " active" : ""}${meta.flagged ? " flagged" : ""}" data-id="${escapeHtml(meta.id)}"
        style="left:${center.toFixed(1)}px" aria-label="${escapeHtml(takenText(meta))}"${current ? " aria-current=\"true\"" : ""}>${tipHtml(meta)}</button>`;
			}
			const a = group.items[0].taken;
			const b = group.items[group.items.length - 1].taken;
			const stripWidth = Math.max(180, (group.items.length - 1) * STRIP_GAP_PX + 60);
			let previous = -Infinity;
			const mini = group.items.map((meta, index) => {
				let position = 30 + (b > a ? (meta.taken - a) / (b - a) * (stripWidth - 60) : index * STRIP_GAP_PX);
				position = Math.max(position, previous + STRIP_GAP_PX);
				previous = position;
				const active = meta.id === currentId;
				return `<button type="button" class="fwmap-tl-mini${active ? " active" : ""}${meta.flagged ? " flagged" : ""}" data-id="${escapeHtml(meta.id)}"
        style="left:${position.toFixed(1)}px" aria-label="${escapeHtml(takenText(meta))}"${active ? " aria-current=\"true\"" : ""}>
        <span class="fwmap-tl-mini-time">${escapeHtml(takenText(meta, false))}</span>${tipHtml(meta)}</button>`;
			}).join("");
			const finalWidth = Math.max(stripWidth, previous + 30);
			return `<div class="fwmap-tl-group${current ? " active" : ""}" tabindex="0" style="left:${center.toFixed(1)}px"
        aria-label="${escapeHtml(plural(T, "snapshots_here", group.items.length))}">
      <span class="fwmap-tl-count">${escapeHtml(group.items.length)}</span>
      <span class="fwmap-tl-pop"><span class="fwmap-tl-strip" style="width:${finalWidth.toFixed(0)}px">${mini}</span></span></div>`;
		}).join("");
		$track.html(`<span class="fwmap-tl-line"></span>${ticks}${dots}`);
	}
	function renderTimeline() {
		const $timeline = $("#fwmap-timeline");
		if (state.mode !== "snapshot" || !state.frozen) {
			$timeline.hide().empty();
			return;
		}
		const list = state.snapshots;
		const index = list.findIndex((meta) => meta.id === state.frozen.meta.id);
		const older = `<button type="button" class="fwmap-tl-step" data-step="1" title="${escapeHtml(T.snapshot_older)}" aria-label="${escapeHtml(T.snapshot_older)}"${index >= list.length - 1 ? " disabled" : ""}>${ic("chevron-left")}</button>`;
		const newer = `<button type="button" class="fwmap-tl-step" data-step="-1" title="${escapeHtml(T.snapshot_newer)}" aria-label="${escapeHtml(T.snapshot_newer)}"${index <= 0 ? " disabled" : ""}>${ic("chevron")}</button>`;
		const where = `<span class="fwmap-tl-where">${escapeHtml(takenText(state.frozen.meta, false))} <span class="fwmap-muted">· ${escapeHtml(list.length - index)}/${escapeHtml(list.length)}</span></span>`;
		if (!timelineOpen) {
			$timeline.removeClass("open").html(`
      <button type="button" class="fwmap-tl-toggle" aria-expanded="false" title="${escapeHtml(T.timeline_expand)}">${ic("clock")} ${escapeHtml(T.timeline)}</button>
      ${older}${where}${newer}`).show();
			return;
		}
		const days = [...new Set(list.map(dayKey))].sort((a, b) => new Date(a) - new Date(b));
		if (!timelineDay || !days.includes(timelineDay)) timelineDay = dayKey(state.frozen.meta);
		const dayIndex = days.indexOf(timelineDay);
		const dayButton = (stepValue, icon, label, disabled) => `<button type="button" class="fwmap-tl-day-step" data-day-step="${stepValue}"
    title="${escapeHtml(label)}" aria-label="${escapeHtml(label)}"${disabled ? " disabled" : ""}>${ic(icon)}</button>`;
		$timeline.addClass("open").html(`
    <button type="button" class="fwmap-tl-toggle" aria-expanded="true" title="${escapeHtml(T.timeline_collapse)}" aria-label="${escapeHtml(T.timeline_collapse)}">${ic("clock")}</button>
    <span class="fwmap-tl-day">${dayButton(-1, "chevron-left", T.timeline_previous_day, dayIndex <= 0)}
      <span class="fwmap-tl-day-label">${escapeHtml(dayLabel(timelineDay))}</span>
      ${dayButton(1, "chevron", T.timeline_next_day, dayIndex >= days.length - 1)}</span>
    <span class="fwmap-tl-track"></span>
    ${older}${where}${newer}`).show();
		layoutTrack($timeline.find(".fwmap-tl-track"), list.filter((meta) => dayKey(meta) === timelineDay));
	}
	/** The Snapshots tab of the side panel. */
	function renderSnapshotList() {
		const $list = $("#fwmap-talkers-list");
		const needle = String($("#fwmap-talker-search").val() || "").trim().toLowerCase();
		let rows = state.snapshots;
		if (needle) rows = rows.filter((meta) => [
			meta.note,
			meta.user,
			takenText(meta)
		].filter(Boolean).some((text) => String(text).toLowerCase().includes(needle)));
		if (!rows.length) {
			$list.html(`<div class="text-muted fwmap-empty">${escapeHtml(needle ? T.queue_no_match : T.no_snapshots)}</div>`);
			return;
		}
		const kept = `<div class="fwmap-snap-kept fwmap-muted">${escapeHtml(T.snapshots_kept.replace("%s", state.snapshotsKept.keep).replace("%d", state.snapshotsKept.keep_days))}</div>`;
		$list.html(kept + rows.map((meta) => {
			const current = meta.id === state.frozen?.meta.id;
			return `<div class="fwmap-talker fwmap-snap-row${current ? " active" : ""}" role="button" tabindex="0" data-id="${escapeHtml(meta.id)}"
        aria-pressed="${current}" title="${escapeHtml(T.snapshot_show)}">
      <span class="fwmap-talker-icon">${ic("camera")}</span>
      <span class="fwmap-talker-text"><span class="fwmap-talker-label">${escapeHtml(takenText(meta))}${meta.user ? ` <span class="fwmap-snap-by">· ${escapeHtml(T.snapshot_by)} ${escapeHtml(meta.user)}</span>` : ""}</span>
        <span class="fwmap-talker-sub">${countsText(meta)}</span>
        ${meta.note ? `<span class="fwmap-talker-sub fwmap-snap-note">“${escapeHtml(meta.note)}”</span>` : ""}</span>
      <span class="fwmap-snap-size">${escapeHtml(formatBytes(meta.size || 0))}</span>
    </div>`;
		}).join(""));
	}
	/** The header switch, the camera, the frame, banner and timeline, and the tab if it is open. */
	function renderChrome() {
		const snapshot = state.mode === "snapshot";
		$("#fwmap-map").toggleClass("fwmap-frozen", snapshot);
		$("#fwmap-mode-live").toggleClass("active", !snapshot).attr("aria-pressed", String(!snapshot));
		$("#fwmap-mode-snapshots").toggleClass("active", snapshot).attr("aria-pressed", String(snapshot)).prop("disabled", !snapshot && !state.snapshots.length).attr("title", state.snapshots.length ? T.snapshots : T.no_snapshots);
		$("#fwmap-snapshot-count").text(state.snapshots.length || "");
		$("#fwmap-camera, #fwmap-follow").toggle(!snapshot);
		renderBanner();
		renderTimeline();
		if (state.talkerTab === "snapshots") renderSnapshotList();
	}
	/** The States dialog for a saved snapshot: the PF states as they were when it was taken. */
	function showSavedStates(address) {
		const body = (state.frozen?.data?.states?.[address] || []).map((row) => `<tr><td>${escapeHtml(row.interface || "")}</td><td>${escapeHtml(row.proto || "")}</td><td>${escapeHtml(hostPort(row.src_addr, row.src_port))}</td><td>${escapeHtml(hostPort(row.dst_addr, row.dst_port))}</td><td>${escapeHtml(row.nat || "")}</td><td>${escapeHtml(row.state || "")}</td><td>${escapeHtml(formatBytes(row.bytes || 0))}</td></tr>`).join("");
		BootstrapDialog.show({
			title: escapeHtml(`${T.states_for} ${address} · ${takenText(state.frozen?.meta)}`),
			size: BootstrapDialog.SIZE_WIDE,
			message: body ? `<table class="table table-condensed table-striped"><thead><tr><th>${escapeHtml(T.interface)}</th><th>${escapeHtml(T.protocol)}</th><th>${escapeHtml(T.source)}</th><th>${escapeHtml(T.destination)}</th><th>NAT</th><th>${escapeHtml(T.state)}</th><th>${escapeHtml(T.bytes)}</th></tr></thead><tbody>${body}</tbody></table>` : escapeHtml(state.frozen?.data?.full ? T.no_states : T.snapshot_no_states),
			buttons: [{
				label: T.close,
				action: (dialog) => dialog.close()
			}]
		});
	}
	function bindSnapshots(pageHooks) {
		hooks = {
			...hooks,
			...pageHooks
		};
		$("#fwmap-camera").on("click", () => takeSnapshot());
		$("#fwmap-mode").on("click", "button", function() {
			chooseMode($(this).data("mode"));
		});
		$("#fwmap-banner").on("click", ".fwmap-snap-note-btn", () => editNote()).on("click", ".fwmap-snap-download", () => download()).on("click", ".fwmap-snap-delete", () => remove());
		$("#fwmap-timeline").on("click", ".fwmap-tl-toggle", () => {
			timelineOpen = !timelineOpen;
			writeStorage(TIMELINE_KEY, timelineOpen ? "1" : "0");
			renderTimeline();
		}).on("click", ".fwmap-tl-step", function() {
			step(Number($(this).data("step")));
		}).on("click", ".fwmap-tl-dot, .fwmap-tl-mini", function() {
			openSnapshot(String($(this).data("id")));
		}).on("click", ".fwmap-tl-day-step", function() {
			const days = [...new Set(state.snapshots.map(dayKey))].sort((a, b) => new Date(a) - new Date(b));
			timelineDay = days[days.indexOf(timelineDay) + Number($(this).data("day-step"))] || timelineDay;
			renderTimeline();
		});
		$("#fwmap-talkers-list").on("mousedown", ".fwmap-snap-row", function(event) {
			event.preventDefault();
			openSnapshot(String($(this).data("id")));
		}).on("keydown", ".fwmap-snap-row", function(event) {
			if (event.key === "Enter" || event.key === " ") {
				event.preventDefault();
				openSnapshot(String($(this).data("id")));
			}
		});
		if (window.ResizeObserver) {
			let frame = null;
			new ResizeObserver(() => {
				if (timelineOpen && state.mode === "snapshot" && frame === null) frame = requestAnimationFrame(() => {
					frame = null;
					renderTimeline();
				});
			}).observe(document.getElementById("fwmap-map"));
		}
		const match = /(?:^#|&)snapshot=(\d{8}T\d{6}Z-[0-9a-f]{4})/.exec(window.location.hash);
		loadSnapshots().then(() => {
			if (match) {
				openSnapshot(match[1]);
				history.replaceState(null, "", window.location.pathname + window.location.search);
			}
		});
	}
	//#endregion
	//#region page/talkers.js
	var HISTORY_POINTS = 60;
	var TALKER_ROWS = 20;
	/** "VLAN10_MGMT" reads as "MGMT (VLAN10)"; the configured name stays in the tooltip. */
	function shortInterface(name) {
		const match = /^VLAN(\d+)[_ -]+(.+)$/i.exec(plain(name || ""));
		return match ? `${match[2]} (VLAN${match[1]})` : plain(name || "");
	}
	/** Top talkers by host, country and network, plus the addresses Suricata alerted on. */
	function groupTalkers(summary) {
		const locations = locationsById(summary);
		const groups = {
			hosts: /* @__PURE__ */ new Map(),
			countries: /* @__PURE__ */ new Map(),
			networks: /* @__PURE__ */ new Map(),
			ids: /* @__PURE__ */ new Map()
		};
		const add = (group, key, fields, rate) => {
			const entry = groups[group].get(key) || {
				key,
				rate: 0,
				flows: 0,
				...fields
			};
			entry.rate += rate;
			entry.flows += 1;
			groups[group].set(key, entry);
		};
		for (const flow of summary.flows || []) {
			const rate = flow.rate || 0;
			const dest = locations.get(flow.dest) || {};
			for (const inside of (flow.inside || []).slice(0, 1)) add("hosts", inside.ip, {
				label: inside.name || inside.ip,
				ip: inside.ip,
				iface: inside.interface,
				icon: "laptop",
				filter: { host: inside.ip }
			}, rate);
			if (dest.country) add("countries", dest.country, {
				label: plain(dest.country),
				flag: flagHtml(dest.country_code),
				icon: "fa-flag-o",
				filter: { country: dest.country }
			}, rate);
			if (dest.asn) add("networks", String(dest.asn), {
				label: plain(dest.as_org || `AS${dest.asn}`),
				sub: `AS${dest.asn}`,
				icon: "network",
				filter: { asn: String(dest.asn) }
			}, rate);
		}
		const idsEntry = (address, ids, count, severity, select, connection) => {
			const current = groups.ids.get(address);
			if (current && (current.connection || !connection)) return;
			const top = ids?.signatures?.[0] || ids?.groups?.[0]?.signatures?.[0];
			groups.ids.set(address, {
				key: address,
				label: address,
				sub: top ? plain(top.signature) : "",
				severity,
				count,
				connection,
				icon: connection ? "fa-exclamation-circle" : "fa-flag",
				rate: 0,
				select
			});
		};
		for (const flow of summary.ids_flows || []) if (flow.kind !== "blocked") idsEntry(flow.dest, flow, flow.count, flow.severity, {
			kind: "idsflow",
			addresses: [flow.dest],
			idsFlow: flow,
			country: flow.country,
			countryCode: flow.country_code,
			title: flow.city || flow.country
		}, true);
		for (const flow of summary.flows || []) if (flow.ids) {
			const dest = locations.get(flow.dest) || {};
			idsEntry(flow.dest, flow.ids, flow.ids.count, flow.ids.severity, {
				kind: "flow",
				addresses: [flow.dest],
				members: [flow],
				country: dest.country,
				countryCode: dest.country_code,
				title: dest.city || dest.country
			}, false);
		}
		for (const block of summary.blocks || []) if (block.ids) idsEntry(block.source, block.ids, block.ids.count, block.ids.severity, {
			kind: "blocked",
			addresses: [block.source],
			block,
			country: block.country,
			countryCode: block.country_code,
			title: block.city || block.country
		}, false);
		for (const alert of summary.alerts || []) idsEntry(alert.source, alert.ids, alert.ids?.count || 0, alert.ids?.severity || 3, {
			kind: "alert",
			addresses: [alert.source],
			alert,
			country: alert.country,
			countryCode: alert.country_code,
			title: alert.city || alert.country
		}, false);
		const result = {};
		for (const [group, entries] of Object.entries(groups)) result[group] = [...entries.values()].sort(group === "ids" ? (a, b) => b.connection - a.connection || a.severity - b.severity || b.count - a.count : (a, b) => b.rate - a.rate);
		return result;
	}
	function talkers(summary) {
		const result = groupTalkers(summary);
		for (const [group, entries] of Object.entries(result)) {
			if (group === "ids") continue;
			for (const entry of entries) {
				const key = `${group}:${entry.key}`;
				const series = state.history.get(key) || [];
				series.push(entry.rate);
				if (series.length > HISTORY_POINTS) series.shift();
				state.history.set(key, series);
				entry.series = series;
			}
		}
		for (const [key, series] of state.history) {
			const [group, id] = key.split(/:(.*)/s);
			if (!(result[group] || []).some((entry) => entry.key === id)) {
				series.push(0);
				if (series.length > HISTORY_POINTS) series.shift();
				if (series.every((value) => value === 0)) state.history.delete(key);
			}
		}
		return result;
	}
	/** A small filled area chart; the newest point sits at the right edge. */
	function sparkline(canvas, series) {
		const ratio = window.devicePixelRatio || 1;
		const width = canvas.clientWidth || 64;
		const height = canvas.clientHeight || 22;
		canvas.width = Math.round(width * ratio);
		canvas.height = Math.round(height * ratio);
		const context = canvas.getContext("2d");
		const color = getComputedStyle(canvas).getPropertyValue("--fwmap-accent").trim() || "rgb(192, 62, 20)";
		context.setTransform(ratio, 0, 0, ratio, 0, 0);
		context.clearRect(0, 0, width, height);
		if (!series || series.length < 2) return;
		const max = Math.max(...series, 1);
		const points = series.map((value, index) => [index / (series.length - 1) * width, height - 1 - value / max * (height - 3)]);
		context.beginPath();
		points.forEach(([x, y], index) => index ? context.lineTo(x, y) : context.moveTo(x, y));
		context.lineTo(points[points.length - 1][0], height);
		context.lineTo(points[0][0], height);
		context.closePath();
		context.fillStyle = color;
		context.globalAlpha = .18;
		context.fill();
		context.globalAlpha = 1;
		context.beginPath();
		points.forEach(([x, y], index) => index ? context.lineTo(x, y) : context.moveTo(x, y));
		context.strokeStyle = color;
		context.lineWidth = 1.2;
		context.stroke();
	}
	function talkerActive(row) {
		return row.filter && Object.entries(row.filter).every(([key, value]) => state.filters[key] === value);
	}
	function renderTalkers(groups) {
		const ids = state.talkerTab === "ids";
		$("#fwmap-talker-sort").toggle(!ids);
		const needle = String($("#fwmap-talker-search").val() || "").trim().toLowerCase();
		const sort = $("#fwmap-talker-sort").val() || "rate";
		let rows = (groups[state.talkerTab] || []).slice();
		if (needle) rows = rows.filter((row) => [
			row.label,
			row.ip,
			row.iface,
			row.sub,
			row.key
		].filter(Boolean).some((text) => String(text).toLowerCase().includes(needle)));
		if (!ids && sort === "flows") rows.sort((a, b) => b.flows - a.flows || b.rate - a.rate);
		else if (sort === "name") rows.sort((a, b) => String(a.label).localeCompare(String(b.label)));
		rows = rows.slice(0, TALKER_ROWS);
		const $list = $("#fwmap-talkers-list");
		if (!rows.length) {
			$list.html(`<div class="text-muted fwmap-empty">${escapeHtml(ids ? T.no_ids_talkers : T.no_talkers)}</div>`);
			state.talkerRows = [];
			return;
		}
		$list.html(rows.map((row, index) => {
			const sub = row.ip ? `${escapeHtml(row.ip)}${row.iface ? ` · <span title="${escapeHtml(row.iface)}">${escapeHtml(shortInterface(row.iface))}</span>` : ""}` : escapeHtml(row.sub || "");
			const chart = ids ? "<span></span>" : "<canvas></canvas>";
			const value = ids ? `<span class="fwmap-talker-count ${row.severity <= 2 ? "fwmap-ids-high" : "fwmap-ids"}">${escapeHtml(row.count)} ${escapeHtml(T.alerts_short)}</span>` : `<span class="fwmap-talker-rate">${escapeHtml(formatRate(row.rate))}</span>`;
			const extra = ids ? `<span class="fwmap-talker-flows">${escapeHtml(T.severity)} ${escapeHtml(row.severity)}</span>` : `<span class="fwmap-talker-flows">${escapeHtml(row.flows)} ${escapeHtml(row.flows === 1 ? T.flow_one : T.flow_many)}</span>`;
			const active = talkerActive(row);
			return `<div class="fwmap-talker${active ? " active" : ""}" data-index="${index}" role="button" tabindex="0"
        ${ids ? "" : `aria-pressed="${active}"`} title="${escapeHtml(ids ? T.select_hint : T.filter_hint)}">
      <span class="fwmap-talker-icon">${row.flag || `${ic(row.icon)}`}</span>
      <span class="fwmap-talker-text"><span class="fwmap-talker-label">${escapeHtml(row.label)}</span>
        <span class="fwmap-talker-sub">${sub}</span></span>
      ${chart}${value}${extra}
    </div>`;
		}).join(""));
		state.talkerRows = rows;
		$list.find(".fwmap-talker canvas").each(function() {
			sparkline(this, rows[$(this).closest(".fwmap-talker").data("index")].series);
		});
	}
	function talkersFromLast() {
		const groups = groupTalkers(state.data);
		for (const [group, entries] of Object.entries(groups)) for (const entry of entries) entry.series = state.mode === "snapshot" ? null : state.history.get(`${group}:${entry.key}`);
		return groups;
	}
	//#endregion
	//#region page/toolbar.js
	/** Rebuild a filter's options (bootstrap-select), never while its list is open. */
	function fillSelect($select, values, current, allLabel) {
		const options = [`<option value="">${escapeHtml(allLabel)}</option>`].concat([...values].sort((a, b) => String(a.label).localeCompare(String(b.label))).map((item) => `<option value="${escapeHtml(item.value)}">${escapeHtml(item.label)}</option>`));
		if (current && ![...values].some((item) => String(item.value) === current)) options.push(`<option value="${escapeHtml(current)}">${escapeHtml(current)}</option>`);
		const html = options.join("");
		if ($select.data("html") !== html && !$select.parent().hasClass("open")) {
			$select.html(html).data("html", html);
			withIcons($select);
			$select.selectpicker("refresh");
		}
		$select.val(current);
	}
	/** The filter's icon on every option, so bootstrap-select shows it on the button. */
	function withIcons($select) {
		const icon = $select.closest(".fwmap-filter").data("icon");
		if (icon) $select.find("option").attr("data-icon", icon);
	}
	function updateToolbar(summary) {
		const locations = locationsById(summary);
		const services = /* @__PURE__ */ new Map();
		const ifaces = /* @__PURE__ */ new Map();
		const hosts = /* @__PURE__ */ new Map();
		const countries = /* @__PURE__ */ new Map();
		for (const flow of summary.flows || []) {
			const service = flowService(flow);
			services.set(service, {
				value: service,
				label: service
			});
			for (const inside of flow.inside || []) {
				if (inside.interface) ifaces.set(inside.interface, {
					value: inside.interface,
					label: inside.interface
				});
				hosts.set(inside.ip, {
					value: inside.ip,
					label: inside.name ? `${inside.name} (${inside.ip})` : inside.ip
				});
			}
			const country = locations.get(flow.dest)?.country;
			if (country) countries.set(country, {
				value: country,
				label: plain(country)
			});
		}
		for (const name of summary.interfaces || []) ifaces.set(name, {
			value: name,
			label: name
		});
		for (const block of summary.blocks || []) if (block.country) countries.set(block.country, {
			value: block.country,
			label: plain(block.country)
		});
		fillSelect($("#fwmap-filter-service"), services.values(), state.filters.service, T.all_services);
		fillSelect($("#fwmap-filter-iface"), ifaces.values(), state.filters.iface, T.all_interfaces);
		fillSelect($("#fwmap-filter-host"), hosts.values(), state.filters.host, T.all_hosts);
		fillSelect($("#fwmap-filter-country"), countries.values(), state.filters.country, T.all_countries);
		const asnActive = state.filters.asn !== "";
		$("#fwmap-filter-asn").toggleClass("shown", asnActive).find(".fwmap-asn-label > span").text(asnActive ? `AS${state.filters.asn}` : "");
		syncChips();
	}
	/** A chosen filter turns primary and shows its clear button; reset appears once two are set. */
	function syncChips() {
		let active = state.filters.asn ? 1 : 0;
		$(".fwmap-filter").each(function() {
			const $select = $(this).find("select.selectpicker");
			const on = !["", "all"].includes($select.val() || "");
			if ($(this).hasClass("active") !== on || !$(this).data("styled")) {
				$(this).toggleClass("active", on).data("styled", true);
				$select.selectpicker("setStyle", on ? "btn-primary btn-sm" : "btn-default btn-sm");
			}
			const shown = `${$select.val()}|${$select.data("html") || ""}`;
			if ($select.data("rendered") !== shown) $select.data("rendered", shown).selectpicker("render");
			active += on ? 1 : 0;
		});
		$("#fwmap-reset").toggle(active >= 2);
		const layout = `${document.getElementById("fwmap-chips")?.clientWidth}|${$(".fwmap-filter select.selectpicker").map((_, select) => $(select).data("rendered")).get().join("|")}|${active}`;
		if (layout !== lastLayout) {
			lastLayout = layout;
			foldChips();
		}
	}
	var lastLayout = null;
	/** Filters that do not fit on the row move, from the right, into the "Filters" menu. */
	function foldChips() {
		const row = document.getElementById("fwmap-chips");
		const wrap = document.getElementById("fwmap-more-wrap");
		const menu = document.getElementById("fwmap-more-menu");
		if (!row || row.offsetParent === null || $(".fwmap-filter .bootstrap-select.open").length) return;
		const groups = [...document.querySelectorAll(".fwmap-filter")];
		for (const group of groups) row.insertBefore(group, document.getElementById("fwmap-filter-asn"));
		wrap.style.display = "none";
		if (row.scrollWidth > row.clientWidth + 1) {
			wrap.style.display = "";
			for (let index = groups.length - 1; index > 0 && row.scrollWidth > row.clientWidth + 1; index--) menu.insertBefore(groups[index], menu.firstChild);
		} else closeMore();
		const folded = groups.filter((group) => group.parentNode === menu && group.classList.contains("active")).length;
		$("#fwmap-more-count").text(folded || "");
	}
	function closeMore() {
		$("#fwmap-more-wrap").removeClass("open");
		$("#fwmap-more").attr("aria-expanded", "false");
	}
	/** bootstrap-select on the filters and the legend's color scheme, clear buttons, the "Filters" menu. */
	function bindChips() {
		$(".fwmap-filter select.selectpicker").each(function() {
			withIcons($(this));
		});
		$("#fwmap-toolbar .selectpicker, #fwmap-color").selectpicker().selectpicker("refresh");
		$("#fwmap-chips").on("click", ".fwmap-filter .fwmap-filter-clear", function(event) {
			event.preventDefault();
			const group = $(this).closest(".fwmap-filter");
			group.find("select").val(group.data("filter") === "traffic" ? "all" : "").trigger("change");
		});
		$("#fwmap-more").on("click", (event) => {
			event.stopPropagation();
			const open = !$("#fwmap-more-wrap").hasClass("open");
			$("#fwmap-more-wrap").toggleClass("open", open);
			$("#fwmap-more").attr("aria-expanded", String(open));
		});
		$(document).on("mousedown", (event) => {
			if (!$(event.target).closest("#fwmap-more-wrap").length) closeMore();
		});
		$("#fwmap-toolbar").on("change", "select", () => syncChips());
		if (window.ResizeObserver) new ResizeObserver(() => foldChips()).observe(document.getElementById("fwmap-toolbar"));
		syncChips();
	}
	function updateLegend() {
		const items = state.renderer.legend();
		$("#fwmap-legend-items").html(items.map((item) => `<span class="fwmap-legend-item"><i style="background:rgb(${item.color.slice(0, 3).join(",")})"></i>${escapeHtml(item.label)}</span>`).join("") + `<span class="fwmap-legend-item"><i class="fwmap-legend-ring"></i>${escapeHtml(T.ids_alert)}</span>`);
	}
	//#endregion
	//#region page/main.js
	var host = () => window.FirewallMapRenderer.host;
	/** Suricata counts in the status line, each a one-click filter; connections and address history apart. */
	function idsLinks(summary) {
		const idsFlows = (summary.ids_flows || []).filter((flow) => flow.kind !== "blocked").length;
		const idsAddresses = (/* @__PURE__ */ new Set([
			...(summary.alerts || []).map((alert) => alert.source),
			...(summary.flows || []).filter((flow) => flow.ids).map((flow) => flow.dest),
			...(summary.blocks || []).filter((block) => block.ids).map((block) => block.source)
		])).size;
		const link = (filter, text) => `<a href="#" class="fwmap-status-ids${state.filters.traffic === filter ? " active" : ""}" data-filter="${filter}" aria-pressed="${state.filters.traffic === filter}">${escapeHtml(text)}</a>`;
		const links = [];
		if (idsFlows) links.push(link("ids_flows", `${idsFlows} ${idsFlows === 1 ? T.ids_flow : T.ids_flows}`));
		if (idsAddresses) links.push(link("ids_addresses", `${idsAddresses} ${idsAddresses === 1 ? T.ids_address : T.ids_addresses}`));
		return links;
	}
	function statusLine(summary, shown) {
		const parts = host().statusParts(summary, shown, state.settings, T);
		const carp = summary.carp === "backup" ? parts.pop() : null;
		$("#fwmap-status").html([
			...parts,
			...idsLinks(summary),
			carp
		].filter(Boolean).join(" · "));
		if (state.mode === "live") state.updatedAt = Date.now();
		updatedLine();
	}
	function updatedLine() {
		if (state.mode === "snapshot" && state.frozen) {
			$("#fwmap-updated").html(`${escapeHtml(T.captured)} ${escapeHtml(takenText(state.frozen.meta))} <i class="fwmap-live frozen"></i>`);
			return;
		}
		if (!state.updatedAt) return;
		const seconds = Math.max(0, Math.round((Date.now() - state.updatedAt) / 1e3));
		$("#fwmap-updated").html(`${escapeHtml(T.last_updated)} ${escapeHtml(seconds)} s ${escapeHtml(T.ago)} <i class="fwmap-live${seconds > 10 ? " stale" : ""}"></i>`);
	}
	function refresh() {
		const summary = state.data;
		if (!summary || summary.status !== "ok") return;
		const shown = filtered(summary);
		state.renderer.render(shown);
		updateToolbar(summary);
		updateLegend();
		statusLine(summary, shown);
		$("#fwmap-credit").html(host().creditHtml(summary.provider));
	}
	/**
	* The geolocation card over an empty map (downloading, failed, key missing), or the small note when
	* only network names are missing; re-rendered only when it changes, so Retry stays pressed.
	*/
	function showGeo(summary) {
		const html = summary ? host().geoCardHtml(summary, T, { admin: state.isAdmin }) || host().geoNoteHtml(summary, T, state.geoNoteDismissed) : "";
		const $slot = $("#fwmap-geo");
		if ($slot.data("html") !== html) {
			$slot.html(html).data("html", html);
			host().tickCountdowns();
		}
	}
	/** One request at a time, never stacked on a slow firewall; nothing while the page is hidden. */
	function poll(query) {
		let timer = null;
		const tick = async () => {
			timer = null;
			if (document.hidden) return;
			try {
				const summary = await getJSON(`/api/firewallmap/flow/summary${query}`);
				const problem = host().problemText(summary, T);
				showGeo(state.mode === "live" ? summary : null);
				if (problem && state.mode === "live") {
					if (summary.status === "no_database" || summary.status === "too_many_states") state.renderer.render({
						flows: [],
						locations: []
					});
					$("#fwmap-status").text(summary.status === "no_database" ? "" : problem);
				} else {
					state.live = summary;
					const groups = talkers(summary);
					if (state.mode === "live") {
						state.data = summary;
						renderTabs(groups);
						refresh();
					}
				}
			} catch (error) {
				console.error("Firewall Map+: flow update failed", error);
				if (state.mode === "live") $("#fwmap-status").text(T.unavailable);
			}
			if (!document.hidden) timer = setTimeout(tick, POLL_MS);
		};
		document.addEventListener("visibilitychange", () => {
			if (!document.hidden && timer === null) {
				tick();
				refreshQueueCount();
			}
		});
		tick();
	}
	/** The side panel's current tab: top talkers from `groups`, or the saved snapshots. */
	function renderTabs(groups) {
		const snapshots = state.talkerTab === "snapshots";
		$("#fwmap-talker-sort").toggle(!snapshots && state.talkerTab !== "ids");
		if (snapshots) renderSnapshotList();
		else if (groups) renderTalkers(groups);
	}
	/** Switch the side panel to `tab` (as a click on it would). */
	function setTab(tab) {
		state.talkerTab = tab;
		$("#fwmap-talkers .nav li").removeClass("active").find("a").attr("aria-selected", "false");
		$(`#fwmap-talkers .nav a[data-tab="${tab}"]`).attr("aria-selected", "true").parent().addClass("active");
		renderTabs(state.data ? talkersFromLast() : null);
	}
	function selectTalker(row) {
		if (row?.select) {
			state.selection = row.select;
			state.detailsAddress = row.key;
			renderDetails();
		} else if (row?.filter) {
			const active = talkerActive(row);
			for (const [key, value] of Object.entries(row.filter)) state.filters[key] = active ? "" : value;
			refresh();
		}
	}
	function bindFilters() {
		const bind = (selector, key) => $(selector).on("change", function() {
			state.filters[key] = $(this).val();
			refresh();
			state.renderer.refit();
		});
		bind("#fwmap-filter-traffic", "traffic");
		bind("#fwmap-filter-service", "service");
		bind("#fwmap-filter-iface", "iface");
		bind("#fwmap-filter-host", "host");
		bind("#fwmap-filter-country", "country");
		bindChips();
		$("#fwmap-filter-asn a").on("click", (event) => {
			event.preventDefault();
			state.filters.asn = "";
			refresh();
			syncChips();
		});
		$("#fwmap-color").on("change", function() {
			state.colorMode = $(this).val();
			state.renderer.setSettings({
				...state.settings,
				colorMode: state.colorMode,
				follow: state.follow
			});
			refresh();
		});
		$("#fwmap-reset").on("click", () => {
			resetFilters();
			$("#fwmap-filter-traffic").val("all");
			refresh();
			syncChips();
		});
		$("#fwmap-status").on("click", ".fwmap-status-ids", function(event) {
			event.preventDefault();
			const filter = String($(this).data("filter"));
			$("#fwmap-filter-traffic").val(state.filters.traffic === filter ? "all" : filter).trigger("change");
		});
	}
	function bindTalkers() {
		const rowOf = (element) => (state.talkerRows || [])[$(element).closest(".fwmap-talker").data("index")];
		$("#fwmap-talkers-list").on("mousedown", ".fwmap-talker:not(.fwmap-snap-row)", function(event) {
			event.preventDefault();
			selectTalker(rowOf(this));
		}).on("keydown", ".fwmap-talker:not(.fwmap-snap-row)", function(event) {
			if (event.key === "Enter" || event.key === " ") {
				event.preventDefault();
				const index = $(this).data("index");
				selectTalker(rowOf(this));
				$(`#fwmap-talkers-list .fwmap-talker[data-index="${index}"]`).trigger("focus");
			}
		});
		$("#fwmap-talker-search, #fwmap-talker-sort").on("input change", () => {
			renderTabs(state.data ? talkersFromLast() : null);
		});
		$("#fwmap-talkers .nav a").on("click", function(event) {
			event.preventDefault();
			setTab($(this).data("tab"));
		});
	}
	function bindDetails() {
		const on = (selector, handler) => $("#fwmap-details").on("click", selector, function(event) {
			event.preventDefault();
			handler($(this));
		});
		const address = ($element) => String($element.data("address"));
		on("#fwmap-details-close", () => {
			state.selection = null;
			renderDetails();
		});
		on(".fwmap-copy", ($element) => navigator.clipboard?.writeText(address($element)));
		on(".fwmap-states", ($element) => state.mode === "snapshot" ? showSavedStates(address($element)) : showStates(address($element)));
		on(".fwmap-states-now", ($element) => showStates(address($element)));
		on(".fwmap-kill", ($element) => killStates(address($element)));
		on(".fwmap-alias", ($element) => addToAlias(address($element)));
		on(".fwmap-mark", ($element) => markThreat(address($element)));
		on(".fwmap-country", ($element) => addCountry(String($element.data("code"))));
		on(".fwmap-abuse-check", ($element) => checkAbuse(address($element), renderDetails));
		on(".fwmap-investigate", ($element) => investigate(address($element), renderDetails));
		on(".fwmap-pick", ($element) => {
			state.detailsAddress = address($element);
			renderDetails();
		});
	}
	function bindControls() {
		bindFilters();
		bindTalkers();
		bindDetails();
		$("#fwmap-review").on("click", () => showQueue());
		setInterval(updatedLine, 1e3);
		$("#fwmap-zoom").on("click", "button", function() {
			const step = $(this).data("zoom");
			if (step === "follow") setFollow(!state.follow);
			else if (step === "fit") state.renderer.fit();
			else state.renderer.zoom(Number(step));
		});
	}
	/** This user's map options, as the dashboard widget stores them. */
	async function loadSettings() {
		let config = {};
		try {
			config = ((await getJSON("/api/core/dashboard/getDashboard")).dashboard?.widgets || []).find((widget) => widget.id === "firewallmap")?.widget || {};
		} catch (error) {
			console.error("Firewall Map+: dashboard settings unavailable", error);
		}
		state.settings = {
			...parseSettings(config),
			colorMode: state.colorMode
		};
		try {
			state.pluginSettings = await getJSON("/api/firewallmap/settings/get");
			state.isAdmin = Boolean(state.pluginSettings.provider);
			state.abuseConfigured = Boolean(state.pluginSettings.abuseipdb_configured);
		} catch (_) {
			state.pluginSettings = null;
			state.isAdmin = false;
		}
	}
	function createRenderer() {
		const $map = $("#fwmap-map");
		const theme = window.FirewallMapRenderer.readTheme($map[0]);
		host().applyTheme($map[0], theme, {
			grid: document.getElementById("fwmap-grid"),
			overlays: [document.getElementById("fwmap-status"), document.getElementById("fwmap-legend")],
			root: document.body
		});
		state.follow = readFollow();
		const container = document.getElementById("fwmap-canvas");
		state.renderer = window.FirewallMapRenderer.create(container, {
			theme,
			settings: {
				...state.settings,
				follow: state.follow
			},
			text: T,
			onSelect: (selection) => {
				state.selection = selection;
				renderDetails();
			},
			onFollowChange: (on) => setFollow(on, false),
			onContextLost: () => recoverRenderer()
		});
		setFollow(state.follow);
		$(container).children("canvas").css({
			left: 0,
			top: 0
		});
	}
	var MAX_RESETS = 3;
	var RESET_WINDOW_MS = 12e4;
	var REBUILD_MS = 2e3;
	var resets = [];
	var rebuilding = null;
	/** The WebGL context was lost: say so, then build a new renderer (a new canvas, a new context). */
	function recoverRenderer() {
		state.contextLosses = (state.contextLosses || 0) + 1;
		const now = Date.now();
		resets = resets.filter((time) => now - time < RESET_WINDOW_MS).concat(now);
		if (rebuilding) return;
		if (resets.length > MAX_RESETS) {
			$("#fwmap-status").text(T.webgl_failed);
			return;
		}
		$("#fwmap-status").text(T.webgl_lost);
		rebuilding = setTimeout(() => {
			rebuilding = null;
			try {
				state.renderer.destroy();
			} catch (_) {}
			$("#fwmap-canvas").empty();
			createRenderer();
			if (state.mode === "snapshot") {
				state.renderer.setFrozen(true);
				state.renderer.setFollow(false);
			}
			refresh();
		}, REBUILD_MS);
	}
	$(async () => {
		if (!window.FirewallMapRenderer?.host.hasWebGL()) {
			$("#fwmap-status").text(T.webgl);
			return;
		}
		await loadSettings();
		try {
			createRenderer();
		} catch (error) {
			console.error("Firewall Map+: renderer initialization failed", error);
			$("#fwmap-status").text(`${T.renderer_failed}: ${error?.message || error}`);
			return;
		}
		bindControls();
		bindSplitters();
		watchSideWidth();
		$("#fwmap-review").toggle(state.isAdmin);
		if (state.isAdmin) {
			refreshQueueCount();
			setInterval(refreshQueueCount, 6e4);
		}
		renderDetails();
		bindSnapshots({
			refresh,
			renderDetails,
			setTab,
			setFollow: (on) => setFollow(on)
		});
		$("#fwmap-geo").on("click", ".fwmap-geo-note-close", () => {
			state.geoNoteDismissed = host().geoNoteKey(state.live);
			showGeo(state.mode === "live" ? state.live : null);
		});
		$(window).on("resize", () => state.renderer.resize());
		$(document).on("keydown", (event) => {
			if (event.key === "Escape" && state.mode === "snapshot" && !$(".modal.in").length) backToLive();
		});
		poll(summaryQuery(state.settings));
		if (new URLSearchParams(window.location.search).get("debug") === "1" && window.FirewallMapDiagnostics) window.FirewallMapDiagnostics.start({
			renderer: () => state.renderer,
			mode: () => state.mode,
			contextLosses: () => state.contextLosses
		});
	});
	//#endregion
})();
