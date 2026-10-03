{#
 # Copyright (C) 2026 Claudio Guareschi <cguareschimd@gmail.com>
 # All rights reserved.
 #
 # Redistribution and use in source and binary forms, with or without
 # modification, are permitted provided that the following conditions are met:
 #
 # 1. Redistributions of source code must retain the above copyright notice,
 #    this list of conditions and the following disclaimer.
 #
 # 2. Redistributions in binary form must reproduce the above copyright
 #    notice, this list of conditions and the following disclaimer in the
 #    documentation and/or other materials provided with the distribution.
 #
 # THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 # INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 # AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 # AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 # OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 # SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 # INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 # CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 # ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 # POSSIBILITY OF SUCH DAMAGE.
 #}

<style>
    /*
     * Colours come from the theme through CSS variables set by the renderer's host.applyTheme():
     * --fwmap-accent, --fwmap-text, --fwmap-panel and the status colours --fwmap-ok, -danger,
     * -contained, -blocked (each with an --fwmap-on-* text colour). Sizes are in em of the
     * surrounding text, so the page scales with the theme's font size.
     */
    /* one row: the mode switch, the filter chips (in the order a connection runs: interface, inside
       host, service, country) and the threats list at the end. Chips that do not fit fold into a
       "Filters" menu instead of wrapping onto a second row. */
    #fwmap-toolbar { display: flex; flex-wrap: nowrap; gap: 8px; align-items: center; margin-bottom: 12px; min-width: 0; }
    .fwmap-tool-sep { flex: none; width: 1px; height: 1.8em; background: rgba(128, 128, 128, .3); }
    #fwmap-chips { flex: 1 1 auto; min-width: 0; display: flex; flex-wrap: nowrap; gap: 6px; align-items: center; }
    .fwmap-chip { position: relative; flex: none; display: inline-flex; align-items: center; gap: 5px; height: 2.3em; padding: 0 8px;
        border: 1px solid rgba(128, 128, 128, .3); border-radius: 8px; background: var(--fwmap-panel, #fff); color: var(--fwmap-text, inherit);
        white-space: nowrap; box-shadow: 0 1px 2px rgba(0, 0, 0, .04); }
    .fwmap-chip:hover { border-color: rgba(128, 128, 128, .55); }
    .fwmap-chip:focus-within { box-shadow: 0 0 0 2px var(--fwmap-accent); }
    .fwmap-chip > .fwmap-ic { width: 1.05em; height: 1.05em; flex: none; opacity: .75; pointer-events: none; }
    .fwmap-chip select { -webkit-appearance: none; appearance: none; border: 0; outline: 0; background: transparent; color: inherit;
        font: inherit; height: 100%; padding: 0 1.3em 0 0; margin: 0; cursor: pointer; max-width: 13em; text-overflow: ellipsis; }
    .fwmap-chip select option { color: initial; }
    /* the theme forces its caret image onto every select (!important); the chips draw their own */
    .fwmap-chip select, .fwmap-legend-mode select { background-image: none !important; background-color: transparent !important; }
    #fwmap-toolbar button, .fwmap-chip { -webkit-user-select: none; user-select: none; }
    .fwmap-chip .fwmap-chip-caret { position: absolute; right: 7px; width: .9em; height: .9em; opacity: .6; pointer-events: none; }
    .fwmap-chip-clear { display: none; flex: none; align-items: center; justify-content: center; width: 1.3em; height: 1.3em; padding: 0;
        margin-right: -4px; border: 0; border-radius: 50%; background: transparent; color: inherit; opacity: .85; line-height: 1; }
    .fwmap-chip-clear:hover, .fwmap-chip-clear:focus { background: rgba(0, 0, 0, .15); opacity: 1; color: inherit; text-decoration: none; }
    .fwmap-chip-clear .fwmap-ic { width: .8em; height: .8em; }
    /* a chosen filter fills with the accent colour and trades its caret for a clear button */
    .fwmap-chip.active { background: var(--fwmap-accent); border-color: var(--fwmap-accent); color: var(--fwmap-on-accent, #fff); }
    .fwmap-chip.active > .fwmap-ic { opacity: 1; }
    .fwmap-chip.active .fwmap-chip-caret { display: none; }
    .fwmap-chip.active select { padding-right: 2px; }
    .fwmap-chip.active .fwmap-chip-clear { display: inline-flex; }
    #fwmap-filter-asn { display: none; font-weight: 600; }
    #fwmap-filter-asn.shown { display: inline-flex; }
    #fwmap-more-wrap { position: relative; flex: none; }
    #fwmap-more { cursor: pointer; padding-right: 2em; }
    #fwmap-more .badge { background: var(--fwmap-accent); color: var(--fwmap-on-accent, #fff); }
    #fwmap-more .badge:empty { display: none; }
    #fwmap-more-menu { display: none; position: absolute; top: calc(100% + 6px); left: 0; z-index: 20; min-width: 15em; padding: 8px;
        flex-direction: column; align-items: stretch; gap: 6px; border: 1px solid rgba(128, 128, 128, .3); border-radius: 8px;
        background: var(--fwmap-panel, #fff); box-shadow: 0 6px 18px rgba(0, 0, 0, .15); }
    #fwmap-more-wrap.open #fwmap-more-menu { display: flex; }
    #fwmap-more-menu .fwmap-chip select { max-width: none; flex: 1; }
    #fwmap-reset { flex: none; width: 2.3em; height: 2.3em; display: inline-flex; align-items: center; justify-content: center; padding: 0;
        border: 0; border-radius: 8px; background: transparent; color: inherit; opacity: .75; }
    #fwmap-reset:hover { background: rgba(128, 128, 128, .14); opacity: 1; }
    #fwmap-reset .fwmap-ic { width: 1.1em; height: 1.1em; }
    #fwmap-toolbar .fwmap-tool-btn { flex: none; height: 2.3em; display: inline-flex; align-items: center; gap: 6px; padding: 0 10px; border-radius: 8px; }
    #fwmap-toolbar .fwmap-tool-btn .fwmap-ic { width: 1.15em; height: 1.15em; }
    #fwmap-toolbar #fwmap-review { margin-left: auto; }
    /* the colour scheme explains the legend, so it is chosen there */
    .fwmap-legend-mode { position: relative; pointer-events: auto; display: inline-flex; align-items: center; gap: 6px; margin: -3px 4px 0 0;
        height: 1.9em; padding: 0 8px; border: 1px solid rgba(128, 128, 128, .3); border-radius: 6px; font-weight: normal;
        background: var(--fwmap-panel, #fff); color: var(--fwmap-text, inherit); }
    .fwmap-legend-mode > span { opacity: .7; }
    .fwmap-legend-mode select { -webkit-appearance: none; appearance: none; border: 0; outline: 0; background: transparent; color: inherit;
        font: inherit; font-weight: 600; padding: 0 1.2em 0 0; cursor: pointer; }
    .fwmap-legend-mode select option { color: initial; font-weight: normal; }
    .fwmap-legend-mode .fwmap-chip-caret { position: absolute; right: 7px; width: .85em; height: .85em; opacity: .6; pointer-events: none; }
    .fwmap-legend-mode:focus-within { box-shadow: 0 0 0 2px var(--fwmap-accent); }
    #fwmap-legend-items { display: contents; }
    #fwmap-layout { display: flex; height: calc(100vh - 222px); min-height: 540px; }
    #fwmap-main { flex: 1; min-width: 0; display: flex; flex-direction: column; border: 1px solid rgba(128, 128, 128, .18);
        border-radius: 6px; padding: 12px 12px 0; }
    /* the legend takes the top left, the zoom buttons the top right: they never overlap */
    #fwmap-zoom { position: absolute; right: 12px; top: 10px; z-index: 3; display: flex; flex-direction: column;
        border: 1px solid rgba(128, 128, 128, .3); border-radius: 4px; overflow: hidden; background: var(--fwmap-panel, #fff);
        color: var(--fwmap-text, inherit); box-shadow: 0 1px 3px rgba(0, 0, 0, .08); }
    #fwmap-zoom button { width: 30px; height: 30px; border: 0; background: transparent; color: inherit; }
    #fwmap-zoom button + button { border-top: 1px solid rgba(128, 128, 128, .25); }
    #fwmap-zoom button:hover { background: rgba(128, 128, 128, .12); }
    #fwmap-zoom button.active { background: rgba(128, 128, 128, .22); color: var(--fwmap-accent); }
    #fwmap-zoom .fwmap-ic { width: 16px; height: 16px; vertical-align: middle; }
    #fwmap-statusbar { display: flex; align-items: center; gap: 12px; padding: 12px 6px; font-size: .92em;
        border-top: 1px solid rgba(128, 128, 128, .15); margin-top: 8px; }
    #fwmap-statusbar #fwmap-status { flex: 1; min-width: 0; }
    #fwmap-map {
        position: relative; flex: 1; min-width: 0; min-height: 0; overflow: hidden; border-radius: 6px;
        /* the map's own layers (canvas, legend, zoom buttons) stack inside it, never above OPNsense's menus */
        isolation: isolate;
    }
    #fwmap-grid { pointer-events: none; position: absolute; inset: 0; z-index: 0; background-size: 48px 48px; }
    #fwmap-canvas { position: absolute; inset: 0; z-index: 1; text-align: left; }
    #fwmap-credit { position: absolute; right: 12px; bottom: 10px; z-index: 2; font-size: .8em; opacity: .7; }
    #fwmap-legend {
        position: absolute; left: 12px; top: 10px; right: 60px; z-index: 2; font-size: .85em; pointer-events: none;
        display: flex; flex-wrap: wrap; align-items: center; gap: 4px 12px;
    }
    .fwmap-legend-item { white-space: nowrap; }
    .fwmap-legend-item i { display: inline-block; width: 22px; height: 3px; margin-right: 6px; vertical-align: middle; border-radius: 2px; }
    .fwmap-legend-item i.fwmap-legend-ring { width: 11px; height: 11px; border-radius: 50%; border: 2px solid currentColor; opacity: .7; background: transparent; }
    .fwmap-status-ids { color: var(--fwmap-danger); }
    .fwmap-status-ids.active { font-weight: 600; text-decoration: underline; }
    #fwmap-updated { white-space: nowrap; opacity: .8; }
    .fwmap-live { display: inline-block; width: 8px; height: 8px; border-radius: 50%; background: var(--fwmap-ok); margin-left: 4px; }
    .fwmap-live.stale { background: var(--fwmap-contained); }
    /* the map gets the larger share by default; the splitter gives the side panel more when wanted */
    #fwmap-side { width: clamp(360px, 30vw, 600px); flex: 0 0 clamp(360px, 30vw, 600px); display: flex; flex-direction: column;
        height: 100%; min-height: 0; }
    #fwmap-talkers, #fwmap-details-box { border: 1px solid rgba(128, 128, 128, .22); border-radius: 6px;
        background: var(--fwmap-panel, transparent); box-shadow: 0 1px 3px rgba(0, 0, 0, .06); }
    #fwmap-talkers { flex: 1 1 60%; min-height: 0; display: flex; flex-direction: column; padding: 10px 12px 6px; }
    #fwmap-talkers-list { flex: 1; min-height: 0; overflow-y: auto; margin: 0 -4px; padding: 0 4px; }
    #fwmap-details-box { flex: 1 1 40%; min-height: 0; overflow: hidden; display: flex; flex-direction: column; }
    #fwmap-details { flex: 1; min-height: 0; display: flex; flex-direction: column; }
    #fwmap-details > .fwmap-empty { padding: 14px 16px; }
    /* drag handles: between map and side panel, and between the two side boxes; double-click resets */
    .fwmap-splitter { flex: 0 0 12px; position: relative; touch-action: none; user-select: none; }
    .fwmap-splitter::after { content: ""; position: absolute; border-radius: 2px; background: rgba(128, 128, 128, .35);
        transition: background .15s; }
    .fwmap-splitter:hover::after, .fwmap-splitter:focus-visible::after, .fwmap-splitter.fwmap-dragging::after { background: rgba(128, 128, 128, .75); }
    .fwmap-splitter:focus-visible { outline: 2px solid var(--fwmap-accent); outline-offset: -2px; }
    .fwmap-splitter-v { cursor: col-resize; }
    .fwmap-splitter-v::after { left: 5px; top: 50%; width: 3px; height: 40px; margin-top: -20px; }
    .fwmap-splitter-h { cursor: row-resize; }
    .fwmap-splitter-h::after { top: 5px; left: 50%; height: 3px; width: 40px; margin-left: -20px; }
    body.fwmap-resizing, body.fwmap-resizing * { user-select: none !important; }
    /* top talkers: tabs that shrink instead of running off the panel, search and sort, rows */
    #fwmap-talkers .nav-tabs { border-bottom: 1px solid rgba(128, 128, 128, .25); margin-bottom: 8px; display: flex; gap: 4px; }
    #fwmap-talkers .nav-tabs > li { float: none; margin-bottom: -1px; flex: 0 1 auto; min-width: 0; }
    #fwmap-talkers .nav-tabs > li > a { padding: 7px 14px; margin: 0; border: 1px solid rgba(128, 128, 128, .22); border-bottom-color: transparent;
        border-radius: 5px 5px 0 0; background: rgba(128, 128, 128, .05); font-weight: 500;
        white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
    #fwmap-talkers .nav-tabs > li.active > a { background: var(--fwmap-panel, #fff); color: inherit; border-color: rgba(128, 128, 128, .3);
        border-bottom-color: var(--fwmap-panel, #fff); box-shadow: inset 0 3px 0 var(--fwmap-accent); font-weight: 600; }
    .fwmap-talker-tools { display: flex; gap: 8px; margin-bottom: 6px; }
    .fwmap-talker-search { position: relative; flex: 1; }
    .fwmap-talker-search .fwmap-ic { position: absolute; left: 10px; top: 9px; width: 15px; height: 15px; opacity: .5; }
    .fwmap-talker-search input { width: 100%; height: 2.3em; padding: 4px 8px 4px 30px; }
    .fwmap-talker-tools select { width: auto; min-width: 9.5em; height: 2.3em; padding: 2px 1.8em 2px 8px; }
    .fwmap-talker { display: grid; grid-template-columns: 30px minmax(0, 1fr) 64px 80px 62px; column-gap: 10px;
        align-items: center; padding: 7px 6px; cursor: pointer; border-radius: 5px; }
    .fwmap-talker + .fwmap-talker { border-top: 1px solid rgba(128, 128, 128, .08); }
    .fwmap-talker:hover, .fwmap-talker:focus-visible { background: rgba(128, 128, 128, .08); outline: none; }
    .fwmap-talker:focus-visible { box-shadow: inset 0 0 0 2px var(--fwmap-accent); }
    .fwmap-talker.active { background: rgba(128, 128, 128, .12); box-shadow: inset 3px 0 0 var(--fwmap-accent); }
    .fwmap-talker-icon { text-align: center; opacity: .8; }
    .fwmap-talker-icon .fwmap-ic { width: 22px; height: 22px; stroke-width: 1.6; }
    .fwmap-talker-icon .fwmap-flag.flag-icon { width: 24px; height: 17px; margin: 0; }
    .fwmap-talker-text { display: block; min-width: 0; line-height: 1.3; }
    .fwmap-talker-label, .fwmap-talker-sub { display: block; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
    .fwmap-talker-label { font-size: 1.02em; font-weight: 500; }
    .fwmap-talker-sub { font-size: .82em; opacity: .65; }
    .fwmap-talker canvas { width: 64px; height: 22px; }
    .fwmap-talker-rate, .fwmap-talker-count { text-align: right; font-variant-numeric: tabular-nums; white-space: nowrap; font-weight: 500; }
    .fwmap-talker-flows { font-size: .85em; opacity: .6; white-space: nowrap; text-align: right; }
    #fwmap-side.fwmap-narrow .fwmap-talker { grid-template-columns: 26px minmax(0, 1fr) 56px 72px; }
    #fwmap-side.fwmap-narrow .fwmap-talker-flows { display: none; }
    .fwmap-ids { margin-top: 2px; opacity: .85; }
    .fwmap-ids-high { font-weight: 600; opacity: 1; color: var(--fwmap-danger); }
    .fwmap-empty { padding: 6px 2px; }
    .fwmap-investigation { margin: 4px 0 8px; padding: 6px 8px; border-left: 3px solid rgba(128, 128, 128, .35); }
    .fwmap-inv-section { margin-bottom: 6px; }
    .fwmap-inv-title { font-weight: 600; font-size: .9em; text-transform: uppercase; letter-spacing: .03em; opacity: .75; }
    .fwmap-inv-table { width: 100%; font-size: .9em; }
    .fwmap-inv-table th { font-weight: normal; opacity: .7; padding-right: 8px; vertical-align: top; white-space: nowrap; width: 1%; }
    .fwmap-inv-table td { word-break: break-word; }
    #fwmap-review-count:empty { display: none; }
    #fwmap-review-count { background: var(--fwmap-danger); color: var(--fwmap-on-danger); }

    /* threat history */
    .bootstrap-dialog.fwmap-q-dialog .modal-dialog { width: min(1320px, 94vw); max-width: none; }
    .bootstrap-dialog.fwmap-q-dialog .modal-header { background: var(--fwmap-panel, #fff) !important; color: var(--fwmap-text, #222);
        border-bottom: 2px solid var(--fwmap-accent); padding: 14px 20px; border-radius: 6px 6px 0 0; }
    .bootstrap-dialog.fwmap-q-dialog .bootstrap-dialog-title, .fwmap-q-dialog .modal-title { color: inherit; width: 100%; }
    .fwmap-q-dialog .modal-header .close, .fwmap-q-dialog .modal-header .bootstrap-dialog-close-button button { color: inherit; opacity: .8; font-size: 1.85em; }
    .fwmap-q-titlebar { display: flex; align-items: center; gap: 14px; }
    .fwmap-q-titlebar > div { flex: 1; }
    .fwmap-q-titlebar .fwmap-q-title-ic { width: 32px; height: 32px; color: var(--fwmap-accent); }
    .fwmap-q-title { font-size: 1.55em; font-weight: 600; line-height: 1.2; }
    .fwmap-q-subtitle { font-size: 1em; opacity: .65; font-weight: normal; }
    .fwmap-q-newcount { font-size: 1.07em; color: var(--fwmap-accent); font-weight: 600; margin-right: 18px; white-space: nowrap; }
    .fwmap-q-newcount b { display: inline-block; background: var(--fwmap-danger); color: var(--fwmap-on-danger); border-radius: 12px; padding: 1px 10px; }
    .fwmap-q-toolbar { display: flex; flex-wrap: wrap; align-items: center; gap: 10px; margin-bottom: 10px; }
    .fwmap-q-tabs { flex: 1 1 auto; margin: 0; }
    .fwmap-q-tabs > li > a { padding: 7px 18px; font-size: 1.07em; }
    .fwmap-q-tabs .badge { margin-left: 6px; }
    .fwmap-q-bulkbar { display: flex; gap: 8px; }
    .fwmap-q-bulkbar .btn { height: 2.7em; display: inline-flex; align-items: center; gap: 7px; font-size: 1em; }
    .fwmap-q-bulkbar .btn .fwmap-ic { width: 1.15em; height: 1.15em; }
    .fwmap-q-conns { width: 100%; margin-top: 8px; font-size: .93em; border-collapse: collapse; }
    .fwmap-q-conns th { font-weight: 600; opacity: .7; padding: 4px 8px 4px 0; border-bottom: 1px solid rgba(128, 128, 128, .25); white-space: nowrap; }
    .fwmap-q-conns td { padding: 5px 8px 5px 0; vertical-align: top; border-bottom: 1px solid rgba(128, 128, 128, .1); }
    .fwmap-q-moreitems { text-align: center; padding: 10px 0 4px; }
    .fwmap-q-searchbox { position: relative; width: 38%; min-width: 240px; }
    .fwmap-q-searchbox .fwmap-ic { position: absolute; left: 12px; top: 10px; width: 17px; height: 17px; opacity: .6; }
    .fwmap-q-searchbox input { width: 100%; height: 2.7em; padding-left: 38px; font-size: 1em; }
    /* the list keeps its height when a tab is empty, so the dialog does not jump */
    .fwmap-q-list { min-height: 40vh; max-height: 64vh; overflow-y: auto; margin: 0 -6px; padding: 0 6px; }
    .fwmap-q-empty { padding: 3em 0; text-align: center; font-size: 1.07em; }
    .fwmap-q-item { padding: 12px 14px 10px; margin: 10px 0; border: 1px solid rgba(128, 128, 128, .22); border-radius: 6px;
        box-shadow: 0 1px 2px rgba(0, 0, 0, .04); font-size: 1em; }
    .fwmap-q-item.fwmap-q-dismissed { opacity: .8; }
    .fwmap-q-top { display: grid; grid-template-columns: minmax(200px, 30%) minmax(0, 1fr) auto; gap: 14px; }
    .fwmap-q-who { border-right: 1px solid rgba(128, 128, 128, .15); padding-right: 12px; min-width: 0; }
    .fwmap-q-ipline { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
    .fwmap-q-ip { font-size: 1.5em; font-weight: 600; letter-spacing: -.01em; }
    .fwmap-q-badge { font-size: .8em; font-weight: 700; letter-spacing: .04em; text-transform: uppercase; padding: 1px 9px; border-radius: 10px;
        background: rgba(128, 128, 128, .2); }
    .fwmap-q-disposition-passed { background: var(--fwmap-danger); color: var(--fwmap-on-danger); }
    .fwmap-q-disposition-firewall_blocked { background: var(--fwmap-blocked); color: var(--fwmap-on-blocked); }
    .fwmap-q-disposition-ips_dropped { background: var(--fwmap-contained); color: var(--fwmap-on-contained); }
    .fwmap-q-workflow { font-size: .8em; opacity: .65; text-transform: uppercase; }
    .fwmap-q-hostname { font-size: .93em; opacity: .7; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; margin-top: 1px; }
    .fwmap-q-org { margin-top: 3px; font-size: 1.07em; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .fwmap-q-country { font-size: 1.07em; margin-top: 2px; }
    .fwmap-q-country .fwmap-flag.flag-icon { width: 20px; height: 15px; margin-right: 8px; vertical-align: -2px; }
    .fwmap-q-chips { margin-top: 8px; display: flex; flex-wrap: wrap; gap: 6px; }
    .fwmap-q-chip { font-size: .9em; font-weight: 600; padding: 2px 10px; border-radius: 4px; color: var(--fwmap-danger);
        border: 1px solid var(--fwmap-danger); }
    .fwmap-q-blocked .fwmap-q-chip, .fwmap-q-dropped .fwmap-q-chip { color: inherit; border-color: var(--fwmap-contained); }
    .fwmap-q-reviewed .fwmap-q-chip, .fwmap-q-dismissed .fwmap-q-chip { color: inherit; border-color: rgba(128, 128, 128, .4); }
    .fwmap-q-flow { min-width: 0; }
    .fwmap-q-diagram { display: flex; align-items: flex-start; gap: 12px; }
    .fwmap-q-diagram .fwmap-q-end { width: 34px; height: 34px; flex: none; margin-top: 6px; opacity: .8; stroke-width: 1.5; }
    .fwmap-q-link { flex: 1; min-width: 90px; text-align: center; }
    .fwmap-q-svc { font-size: .96em; opacity: .8; }
    .fwmap-q-arrow { position: relative; height: 12px; margin: 2px 0 4px; }
    .fwmap-q-arrow::before { content: ""; position: absolute; left: 0; right: 0; top: 6px; border-top: 1.5px solid currentColor; opacity: .55; }
    .fwmap-q-arrow::after { content: ""; position: absolute; top: 2px; border: 5px solid transparent; opacity: .55; }
    .fwmap-q-arrow-in::after { right: -2px; border-left: 8px solid currentColor; }
    .fwmap-q-arrow-out::after { left: -2px; border-right: 8px solid currentColor; }
    .fwmap-q-dirpill { display: inline-block; font-size: .93em; padding: 1px 12px; border-radius: 12px; background: rgba(128, 128, 128, .13); }
    .fwmap-q-local { min-width: 120px; font-size: 1em; line-height: 1.45; }
    .fwmap-q-local-name { font-weight: 600; font-size: 1.14em; }
    .fwmap-q-muted { opacity: .65; }
    .fwmap-q-meta { display: flex; flex-wrap: wrap; gap: 4px 22px; margin-top: 10px; font-size: .96em; opacity: .75; }
    .fwmap-q-meta .fwmap-ic { width: 16px; height: 16px; margin-right: 4px; vertical-align: -3px; }
    .fwmap-q-flow .fwmap-ids { margin-top: 6px; font-size: .93em; }
    .fwmap-q-when { display: flex; align-items: flex-start; gap: 10px; white-space: nowrap; font-size: 1em; opacity: .8; }
    .fwmap-q-when .fwmap-ic { width: 16px; height: 16px; vertical-align: -3px; }
    .fwmap-q-expand { color: inherit; }
    .fwmap-q-when .fwmap-q-expand .fwmap-ic { width: 20px; height: 20px; }
    .fwmap-q-warning { margin-top: 8px; color: var(--fwmap-danger); font-weight: 600; }
    .fwmap-q-more { margin-top: 8px; padding: 8px 10px; border-radius: 4px; background: rgba(128, 128, 128, .06); font-size: .96em; }
    .fwmap-q-note { white-space: pre-wrap; margin-top: 8px; padding: 6px 10px; border-left: 3px solid rgba(128, 128, 128, .35);
        background: rgba(128, 128, 128, .06); font-size: .96em; }
    .fwmap-q-bar { display: flex; flex-wrap: wrap; justify-content: space-between; align-items: center; gap: 8px; margin-top: 12px; }
    .fwmap-q-left, .fwmap-q-right { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; }
    .fwmap-q-bar .btn { height: 2.7em; display: inline-flex; align-items: center; gap: 7px; padding: 6px 14px; font-size: 1em; margin: 0; }
    .fwmap-q-bar .btn .fwmap-ic { width: 17px; height: 17px; }
    .fwmap-q-bar .btn-primary, .fwmap-actions .btn-primary { background: var(--fwmap-accent); border-color: var(--fwmap-accent); color: #fff; }
    .fwmap-q-bar .btn-primary:hover, .fwmap-actions .btn-primary:hover { filter: brightness(.92); }
    .fwmap-q-bar .btn-danger { background: var(--fwmap-danger); border-color: var(--fwmap-danger); color: var(--fwmap-on-danger); }
    .fwmap-q-bar .fwmap-q-menu { padding: 6px 10px; }
    .fwmap-q-footer { float: left; display: flex; flex-wrap: wrap; align-items: center; gap: 4px 28px; text-align: left;
        font-size: 1em; padding-top: 8px; }
    .fwmap-q-record { display: inline-flex; align-items: center; font-weight: normal; margin: 0; }
    .fwmap-q-record input { width: 18px; height: 18px; margin: 0 8px 0 0; flex: none; }
    .fwmap-q-source { opacity: .75; }

    /* details panel: header, verdict pill, diagram, cards, action bar. Base size 13/14 of the page text */
    .fwmap-d-scroll { flex: 1; min-height: 0; overflow-y: auto; overflow-x: hidden; padding: 12px 14px 4px; font-size: .93em; }
    .fwmap-d-head { display: flex; align-items: flex-start; gap: 12px; }
    .fwmap-d-icon { width: 30px; height: 30px; opacity: .7; margin-top: 2px; }
    .fwmap-d-title { flex: 1; min-width: 0; }
    .fwmap-d-name { font-size: 1.38em; font-weight: 600; line-height: 1.2; overflow-wrap: anywhere; }
    .fwmap-d-line { font-size: .96em; margin-top: 2px; display: flex; flex-wrap: wrap; gap: 2px 10px; opacity: .8; }
    .fwmap-d-line b { font-weight: 500; }
    .fwmap-d-verdict { text-align: center; margin-top: 8px; }
    .fwmap-d-verdict-sub { font-size: .88em; opacity: .65; margin-top: 5px; }
    #fwmap-details-close { line-height: 1; margin-left: 2px; color: var(--fwmap-accent); }
    #fwmap-details-close .fwmap-ic { width: 20px; height: 20px; stroke-width: 2.2; }
    .fwmap-vpill, .fwmap-pill { display: inline-block; font-weight: 600; white-space: nowrap; }
    .fwmap-vpill { font-size: .96em; padding: 2px 12px; border-radius: 14px; }
    .fwmap-pill { font-size: .92em; font-weight: 500; padding: 0 8px; border-radius: 9px; }
    .fwmap-vpill .fwmap-ic, .fwmap-pill .fwmap-ic { stroke-width: 2.6; width: .95em; height: .95em; }
    .fwmap-vpill-ok, .fwmap-pill-ok { background: var(--fwmap-ok); color: var(--fwmap-on-ok); }
    .fwmap-vpill-danger, .fwmap-pill-danger { background: var(--fwmap-danger); color: var(--fwmap-on-danger); }
    .fwmap-vpill-blocked, .fwmap-pill-blocked { background: var(--fwmap-blocked); color: var(--fwmap-on-blocked); }
    .fwmap-vpill-contained, .fwmap-pill-contained { background: var(--fwmap-contained); color: var(--fwmap-on-contained); }
    .fwmap-vpill-muted, .fwmap-pill-muted { background: rgba(128, 128, 128, .2); }
    .fwmap-pill-warning { background: var(--fwmap-contained); color: var(--fwmap-on-contained); }
    .fwmap-vpill-ok { box-shadow: 0 0 0 4px rgba(128, 128, 128, .12); }
    .fwmap-picker { margin: 6px 0 0; font-size: .88em; display: flex; flex-wrap: wrap; gap: 4px 8px; align-items: center; }
    .fwmap-pick { padding: 0 6px; border-radius: 8px; }
    .fwmap-pick.active { background: rgba(128, 128, 128, .2); font-weight: 600; }
    .fwmap-diagram { display: flex; align-items: stretch; gap: 8px; margin: 10px 0 8px; }
    .fwmap-end { flex: 1 1 0; min-width: 0; text-align: center; padding: 7px 6px; border-radius: 5px; background: rgba(128, 128, 128, .06);
        border: 1px solid rgba(128, 128, 128, .12); font-size: .96em; }
    .fwmap-end .fwmap-ic { display: block; width: 24px; height: 24px; margin: 0 auto 3px; color: var(--fwmap-accent); }
    .fwmap-end-name { font-weight: 600; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .fwmap-end-sub { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .fwmap-end-sub + .fwmap-end-sub { font-size: .9em; opacity: .7; }
    .fwmap-link { flex: 0 0 30%; display: flex; flex-direction: column; justify-content: center; text-align: center; font-size: .92em; }
    .fwmap-link-service { font-weight: 600; }
    .fwmap-link-port { opacity: .75; }
    .fwmap-link-arrow { position: relative; height: 14px; margin: 4px 2px 6px; }
    .fwmap-link-arrow::before { content: ""; position: absolute; left: 0; right: 7px; top: 6px; border-top: 1.5px solid currentColor; opacity: .6; }
    .fwmap-link-arrow::after { content: ""; position: absolute; right: 0; top: 2px; border: 5px solid transparent; border-left: 8px solid currentColor; opacity: .6; }
    .fwmap-link-blocked .fwmap-link-arrow .fwmap-ic { position: relative; z-index: 1; color: var(--fwmap-danger); }
    .fwmap-link-rate { opacity: .7; }
    .fwmap-cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 7px; }
    .fwmap-card { border: 1px solid rgba(128, 128, 128, .22); border-radius: 5px; min-width: 0; }
    .fwmap-card-head { display: flex; align-items: center; gap: 8px; font-weight: 600; font-size: 1em; padding: 5px 9px;
        border-bottom: 1px solid rgba(128, 128, 128, .15); }
    .fwmap-card-head span { flex: 1; }
    .fwmap-card-ic { width: 18px; height: 18px; color: var(--fwmap-accent); }
    .fwmap-card-go { color: inherit; opacity: .5; }
    .fwmap-card-go:hover, .fwmap-card-go:focus-visible { opacity: 1; }
    .fwmap-card-go .fwmap-ic { width: 14px; height: 14px; }
    .fwmap-card-body { padding: 4px 9px 6px; }
    .fwmap-kv { width: 100%; font-size: .92em; border-collapse: collapse; }
    .fwmap-kv th { font-weight: normal; opacity: .7; padding: 0 8px 0 0; vertical-align: top; white-space: nowrap; width: 40%; }
    .fwmap-kv td { padding: 0; overflow-wrap: anywhere; }
    .fwmap-two { display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 2px 14px; }
    .fwmap-two .fwmap-kv { table-layout: auto; }
    .fwmap-two .fwmap-kv th { width: 1%; }
    .fwmap-card-note { font-size: .84em; opacity: .7; margin-bottom: 3px; }
    .fwmap-empty-note { display: flex; gap: 10px; align-items: center; font-size: .88em; padding: 6px 9px; border-radius: 4px;
        background: rgba(128, 128, 128, .07); }
    .fwmap-ok-ic { width: 22px; height: 22px; color: var(--fwmap-ok); stroke-width: 2.4; }
    .fwmap-muted { opacity: .65; }
    .fwmap-sig { margin-bottom: 5px; font-size: .95em; }
    .fwmap-actions { display: flex; flex-wrap: wrap; gap: 8px; padding: 9px 14px; border-top: 1px solid rgba(128, 128, 128, .18); }
    .fwmap-actions .btn { padding: 6px 14px; font-size: .96em; }
    .fwmap-actions .btn .fwmap-ic { width: 17px; height: 17px; margin-right: 5px; vertical-align: -3px; }
    .fwmap-actions .btn-group { margin-left: auto; }
    /* outline icons and flag images */
    .fwmap-ic { width: 1.05em; height: 1.05em; vertical-align: -.17em; flex: none; }
    .fwmap-flag.flag-icon { width: 19px; height: 14px; line-height: 14px; background-size: cover; border-radius: 2px;
        box-shadow: 0 0 0 1px rgba(0, 0, 0, .1); vertical-align: -3px; margin-right: 6px; }
    .fwmap-not-listed { color: var(--fwmap-ok); }
    .fwmap-not-listed .fwmap-ic { stroke-width: 2.4; width: .95em; height: .95em; }
    .fwmap-abuse-check { white-space: nowrap; font-weight: 500; }

    /* snapshots: the Live | Snapshots switch, the camera, and snapshot mode (frame, banner, timeline).
       --fwmap-frozen is the theme's warning colour, made to stand out on the map background. */
    .fwmap-mode { display: inline-flex; gap: 3px; padding: 3px; border: 1px solid rgba(128, 128, 128, .3); border-radius: 8px; flex: none; }
    .fwmap-mode button { height: 2em; display: inline-flex; align-items: center; gap: 6px; padding: 0 12px; border: 0; border-radius: 5px;
        background: transparent; color: inherit; opacity: .75; white-space: nowrap; }
    .fwmap-mode button:hover:not(:disabled) { background: rgba(128, 128, 128, .12); opacity: 1; }
    .fwmap-mode button:disabled { opacity: .4; cursor: default; }
    .fwmap-mode button.active { opacity: 1; font-weight: 600; background: rgba(128, 128, 128, .14); }
    .fwmap-mode #fwmap-mode-snapshots.active { background: var(--fwmap-frozen-soft); box-shadow: inset 0 0 0 1px var(--fwmap-frozen); }
    .fwmap-mode .fwmap-live { margin: 0; }
    #fwmap-snapshot-count:empty { display: none; }
    #fwmap-snapshot-count { background: rgba(128, 128, 128, .35); color: inherit; }
    #fwmap-camera { position: absolute; right: 12px; top: 146px; z-index: 3; width: 32px; height: 32px; padding: 0;
        display: flex; align-items: center; justify-content: center; border: 1px solid var(--fwmap-accent); border-radius: 8px;
        background: var(--fwmap-panel, #fff); color: var(--fwmap-accent); box-shadow: 0 1px 3px rgba(0, 0, 0, .08); }
    #fwmap-camera:hover { background: var(--fwmap-accent); color: #fff; }
    #fwmap-camera:disabled { opacity: .6; }
    #fwmap-camera .fwmap-ic { width: 18px; height: 18px; }
    #fwmap-map.fwmap-frozen::after { content: ""; position: absolute; inset: 0; z-index: 4; pointer-events: none;
        border: 2px solid var(--fwmap-frozen); border-radius: 6px; }
    #fwmap-map.fwmap-frozen #fwmap-legend, #fwmap-map.fwmap-frozen #fwmap-zoom { top: 58px; }
    #fwmap-map.fwmap-frozen #fwmap-credit { display: none; }
    #fwmap-banner { position: absolute; left: 0; right: 0; top: 0; z-index: 4; display: flex; flex-wrap: wrap; align-items: center; gap: 6px 10px;
        padding: 8px 12px; font-size: .92em; color: var(--fwmap-text, inherit);
        background: linear-gradient(var(--fwmap-frozen-soft), var(--fwmap-frozen-soft)), var(--fwmap-panel, #fff);
        border-bottom: 1px solid var(--fwmap-frozen); }
    .fwmap-banner-ic { width: 18px; height: 18px; color: var(--fwmap-frozen); }
    .fwmap-banner-text { flex: 1 1 260px; min-width: 0; }
    .fwmap-banner-counts { opacity: .8; }
    .fwmap-banner-actions { display: flex; flex-wrap: wrap; gap: 6px; }
    .fwmap-banner-actions .btn { display: inline-flex; align-items: center; gap: 5px; }
    .fwmap-banner-actions .btn .fwmap-ic { width: 15px; height: 15px; }
    .fwmap-snap-live { background: var(--fwmap-ok); color: var(--fwmap-on-ok); border: 0; font-weight: 600; }
    .fwmap-snap-live:hover { filter: brightness(.94); color: var(--fwmap-on-ok); }
    .fwmap-snap-live .fwmap-live { background: currentColor; margin: 0 2px 0 0; }
    .fwmap-snap-note { font-style: italic; }
    .fwmap-snap-flagged { color: var(--fwmap-danger); font-weight: 600; }
    .fwmap-live.frozen { background: var(--fwmap-frozen); }
    /* the timeline: a pill bottom left that grows sideways only (same height), a scrubber when open */
    #fwmap-timeline { position: absolute; left: 12px; bottom: 12px; z-index: 4; height: 40px; box-sizing: border-box;
        display: flex; align-items: center; gap: 2px; max-width: calc(100% - 24px); padding: 0 4px; border-radius: 20px; font-size: .9em;
        background: var(--fwmap-panel, #fff); color: var(--fwmap-text, inherit); border: 1px solid var(--fwmap-frozen);
        box-shadow: 0 4px 14px rgba(0, 0, 0, .18); }
    #fwmap-timeline.open { right: 12px; }
    #fwmap-timeline button { border: 0; background: transparent; color: inherit; }
    .fwmap-tl-toggle, .fwmap-tl-step, .fwmap-tl-day-step { height: 30px; border-radius: 15px; flex: none; }
    #fwmap-timeline .fwmap-tl-toggle:hover, #fwmap-timeline .fwmap-tl-step:hover:not(:disabled),
    #fwmap-timeline .fwmap-tl-day-step:hover:not(:disabled) { background: var(--fwmap-frozen-soft); }
    #fwmap-timeline button:disabled { opacity: .3; }
    .fwmap-tl-toggle { display: inline-flex; align-items: center; gap: 6px; padding: 0 10px; font-weight: 600; }
    #fwmap-timeline.open .fwmap-tl-toggle { width: 30px; padding: 0; justify-content: center; color: var(--fwmap-frozen); }
    .fwmap-tl-step, .fwmap-tl-day-step { width: 28px; padding: 0; }
    .fwmap-tl-where { padding: 0 6px; white-space: nowrap; font-variant-numeric: tabular-nums; flex: none; }
    .fwmap-tl-day { display: inline-flex; align-items: center; flex: none; padding: 0 4px 0 2px; margin-right: 6px;
        border-right: 1px solid rgba(128, 128, 128, .25); }
    .fwmap-tl-day-label { font-weight: 600; white-space: nowrap; min-width: 4.5em; text-align: center; }
    .fwmap-tl-track { position: relative; flex: 1; min-width: 120px; height: 100%; margin: 0 14px; }
    .fwmap-tl-line { position: absolute; left: -6px; right: -6px; top: 15px; height: 2px; border-radius: 1px; background: rgba(128, 128, 128, .35); }
    .fwmap-tl-tick { position: absolute; bottom: 2px; transform: translateX(-50%); font-size: .7em; opacity: .55; white-space: nowrap;
        font-variant-numeric: tabular-nums; pointer-events: none; }
    .fwmap-tl-tick::before { content: ""; position: absolute; left: 50%; top: -9px; width: 1px; height: 5px; background: currentColor; }
    .fwmap-tl-dot, .fwmap-tl-group, .fwmap-tl-mini { position: absolute; transform: translate(-50%, -50%); }
    #fwmap-timeline .fwmap-tl-dot { top: 16px; width: 12px; height: 12px; padding: 0; border-radius: 50%;
        background: var(--fwmap-text, #888); opacity: .75; box-shadow: 0 0 0 2px var(--fwmap-panel, #fff); }
    #fwmap-timeline .fwmap-tl-dot:hover, #fwmap-timeline .fwmap-tl-dot:focus-visible { opacity: 1; width: 15px; height: 15px; }
    #fwmap-timeline .fwmap-tl-dot.flagged { background: var(--fwmap-danger); opacity: .9; }
    #fwmap-timeline .fwmap-tl-dot.active { background: var(--fwmap-frozen); opacity: 1;
        box-shadow: 0 0 0 2px var(--fwmap-panel, #fff), 0 0 0 4px var(--fwmap-frozen); }
    .fwmap-tl-group { top: 16px; width: 20px; height: 20px; border-radius: 50%; display: flex; align-items: center; justify-content: center;
        cursor: pointer; background: var(--fwmap-frozen-soft); border: 1.5px solid var(--fwmap-frozen); outline: none;
        box-shadow: 0 0 0 2px var(--fwmap-panel, #fff); }
    .fwmap-tl-group.active { background: var(--fwmap-frozen); color: var(--fwmap-on-frozen); }
    .fwmap-tl-group:focus-visible { box-shadow: 0 0 0 2px var(--fwmap-panel, #fff), 0 0 0 4px var(--fwmap-accent); }
    .fwmap-tl-count { font-size: .72em; font-weight: 700; line-height: 1; }
    /* a numbered dot opens a zoomed strip above the pill (the pill keeps its height) */
    .fwmap-tl-pop { display: none; position: absolute; left: 50%; bottom: 100%; transform: translateX(-50%); padding-bottom: 12px; cursor: default; }
    .fwmap-tl-group:hover .fwmap-tl-pop, .fwmap-tl-group:focus-within .fwmap-tl-pop { display: block; }
    .fwmap-tl-strip { position: relative; display: block; height: 52px; border-radius: 12px; background: var(--fwmap-panel, #fff);
        border: 1px solid var(--fwmap-frozen); box-shadow: 0 6px 18px rgba(0, 0, 0, .22); }
    .fwmap-tl-strip::before { content: ""; position: absolute; left: 14px; right: 14px; top: 18px; height: 2px; background: rgba(128, 128, 128, .3); }
    #fwmap-timeline .fwmap-tl-mini { top: 19px; width: 12px; height: 12px; padding: 0; border-radius: 50%; background: var(--fwmap-text, #888); opacity: .8; }
    #fwmap-timeline .fwmap-tl-mini.flagged { background: var(--fwmap-danger); }
    #fwmap-timeline .fwmap-tl-mini.active { background: var(--fwmap-frozen); opacity: 1; box-shadow: 0 0 0 2px var(--fwmap-panel, #fff), 0 0 0 4px var(--fwmap-frozen); }
    #fwmap-timeline .fwmap-tl-mini:hover, #fwmap-timeline .fwmap-tl-mini:focus-visible { opacity: 1; width: 15px; height: 15px; }
    .fwmap-tl-mini-time { position: absolute; top: 15px; left: 50%; transform: translateX(-50%) scale(.8); font-size: .78em; white-space: nowrap;
        opacity: .75; pointer-events: none; color: var(--fwmap-text, inherit); }
    /* the badge over a dot: date, time, counts, note, who took it */
    .fwmap-tl-tip { display: none; position: absolute; left: 50%; bottom: calc(100% + 12px); transform: translateX(-50%); z-index: 2;
        flex-direction: column; gap: 2px; min-width: 150px; max-width: 280px; padding: 7px 10px; border-radius: 8px; text-align: left;
        white-space: normal; font-size: .88rem; line-height: 1.35; pointer-events: none;
        background: var(--fwmap-panel, #fff); color: var(--fwmap-text, inherit); border: 1px solid rgba(128, 128, 128, .35);
        box-shadow: 0 6px 18px rgba(0, 0, 0, .25); }
    .fwmap-tl-dot:hover > .fwmap-tl-tip, .fwmap-tl-dot:focus-visible > .fwmap-tl-tip,
    .fwmap-tl-mini:hover > .fwmap-tl-tip, .fwmap-tl-mini:focus-visible > .fwmap-tl-tip { display: flex; }
    .fwmap-tl-tip b { white-space: nowrap; }
    .fwmap-snap-row { grid-template-columns: 30px minmax(0, 1fr) auto; }
    #fwmap-side.fwmap-narrow .fwmap-snap-row { grid-template-columns: 26px minmax(0, 1fr) auto; }
    .fwmap-snap-row.active { background: var(--fwmap-frozen-soft); box-shadow: inset 3px 0 0 var(--fwmap-frozen); }
    .fwmap-snap-row .fwmap-talker-icon { color: var(--fwmap-frozen); opacity: 1; }
    .fwmap-snap-size { font-size: .85em; opacity: .6; white-space: nowrap; }
    .fwmap-snap-kept { font-size: .85em; padding: 0 6px 6px; }
    .fwmap-snap-notice { display: flex; align-items: center; gap: 8px; margin: 8px 0 2px; padding: 6px 10px; border-radius: 4px; font-size: .92em;
        background: var(--fwmap-frozen-soft); border-left: 3px solid var(--fwmap-frozen); }
    .fwmap-snap-notice .fwmap-ic { color: var(--fwmap-frozen); }
    .fwmap-toast-ok { color: var(--fwmap-ok); stroke-width: 2.6; }
    @media (max-width: 1100px) {
        #fwmap-layout { flex-direction: column; height: auto; }
        #fwmap-split-side { display: none; }
        #fwmap-side { width: auto; flex: none; height: auto; }
        #fwmap-map { flex: none; height: 60vh; }
        #fwmap-toolbar .fwmap-tool-text { display: none; }
    }
</style>

<link rel="stylesheet" href="/ui/css/flags/flag-icon.css">
<script>
    // json_encode: a translation containing a quote cannot break out of the string
    window.FirewallMapPageText = {
        firewall_map: {{ lang._('Firewall Map')|json_encode }},
        no_flows: {{ lang._('No active public flows')|json_encode }},
        starting: {{ lang._('Starting flow collector…')|json_encode }},
        unavailable: {{ lang._('Live flow data is unavailable')|json_encode }},
        webgl: {{ lang._('WebGL is required for Firewall Map+')|json_encode }},
        renderer_failed: {{ lang._('Map renderer failed to initialise')|json_encode }},
        carp_backup: {{ lang._('CARP backup: traffic is passing through the master')|json_encode }},
        key_missing: {{ lang._('A MaxMind license key is needed: add it in the Firewall Map widget settings or in the GeoIP alias settings, or choose DB-IP Lite')|json_encode }},
        downloading: {{ lang._('Downloading the geolocation database…')|json_encode }},
        database_failed: {{ lang._('Geolocation database download failed')|json_encode }},
        all_services: {{ lang._('All services')|json_encode }},
        all_interfaces: {{ lang._('All interfaces')|json_encode }},
        all_hosts: {{ lang._('All inside hosts')|json_encode }},
        all_countries: {{ lang._('All countries')|json_encode }},
        no_talkers: {{ lang._('No traffic yet')|json_encode }},
        filter_hint: {{ lang._('Show only this on the map')|json_encode }},
        click_hint: {{ lang._('Click an endpoint or arc on the map for details and actions.')|json_encode }},
        ids_flow: {{ lang._('IDS flow')|json_encode }},
        ids_flows: {{ lang._('IDS flows')|json_encode }},
        ids_address: {{ lang._('IDS address')|json_encode }},
        ids_addresses: {{ lang._('IDS addresses')|json_encode }},
        sec_connection: {{ lang._('Connection')|json_encode }},
        sec_firewall: {{ lang._('Firewall')|json_encode }},
        sec_reputation: {{ lang._('Reputation')|json_encode }},
        via: {{ lang._('Public side')|json_encode }},
        closed: {{ lang._('closed')|json_encode }},
        transferred: {{ lang._('Transferred')|json_encode }},
        decision: {{ lang._('Decision')|json_encode }},
        allowed: {{ lang._('Allowed')|json_encode }},
        rule: {{ lang._('Rule')|json_encode }},
        severity: {{ lang._('Severity')|json_encode }},
        ips_dropped: {{ lang._('dropped by IPS')|json_encode }},
        copy: {{ lang._('Copy')|json_encode }},
        whois: {{ lang._('Whois')|json_encode }},
        show_states: {{ lang._('States')|json_encode }},
        kill_states: {{ lang._('Kill states')|json_encode }},
        add_to_alias: {{ lang._('Add to alias')|json_encode }},
        add_country: {{ lang._('Add country to GeoIP alias')|json_encode }},
        close: {{ lang._('Close')|json_encode }},
        confirm: {{ lang._('Confirm')|json_encode }},
        cancel: {{ lang._('Cancel')|json_encode }},
        kill_confirm: {{ lang._('Kill all firewall states involving')|json_encode }},
        kill_scope: {{ lang._('This ends the connections of every inside host to this address, and any traffic routed through it.')|json_encode }},
        killed: {{ lang._('States killed:')|json_encode }},
        add_confirm: {{ lang._('Add')|json_encode }},
        no_aliases: {{ lang._('No suitable alias exists yet. Create one under Firewall ▸ Aliases first.')|json_encode }},
        action_failed: {{ lang._('The action failed')|json_encode }},
        states_for: {{ lang._('States for')|json_encode }},
        no_states: {{ lang._('No states found.')|json_encode }},
        more_states: {{ lang._('Only the first 100 states are shown.')|json_encode }},
        interface: {{ lang._('Interface')|json_encode }},
        protocol: {{ lang._('Protocol')|json_encode }},
        source: {{ lang._('Source')|json_encode }},
        destination: {{ lang._('Destination')|json_encode }},
        state: {{ lang._('State')|json_encode }},
        bytes: {{ lang._('Bytes')|json_encode }},
        investigate: {{ lang._('Investigate')|json_encode }},
        looking_up: {{ lang._('Looking up registry, routing and reputation…')|json_encode }},
        lookup_failed: {{ lang._('Lookup failed')|json_encode }},
        registry: {{ lang._('Registry (RDAP)')|json_encode }},
        routing: {{ lang._('Routing (RIPEstat)')|json_encode }},
        owner: {{ lang._('Owner')|json_encode }},
        network: {{ lang._('Network')|json_encode }},
        range: {{ lang._('Range')|json_encode }},
        country: {{ lang._('Country')|json_encode }},
        abuse_contact: {{ lang._('Abuse contact')|json_encode }},
        registered: {{ lang._('Registered')|json_encode }},
        updated: {{ lang._('updated')|json_encode }},
        prefix: {{ lang._('Prefix')|json_encode }},
        origin_as: {{ lang._('Origin AS')|json_encode }},
        announced: {{ lang._('Announced')|json_encode }},
        yes: {{ lang._('yes')|json_encode }},
        no: {{ lang._('no')|json_encode }},
        confidence: {{ lang._('Abuse confidence')|json_encode }},
        reports: {{ lang._('Reports (90 days)')|json_encode }},
        reporters: {{ lang._('reporters')|json_encode }},
        last_reported: {{ lang._('Last reported')|json_encode }},
        usage: {{ lang._('Usage')|json_encode }},
        abuseipdb_hint: {{ lang._('Add an AbuseIPDB API key in the Firewall Map widget settings to see abuse reports here.')|json_encode }},
        mark_threat: {{ lang._('Mark as threat')|json_encode }},
        mark_confirm: {{ lang._('Add')|json_encode }},
        mark_scope: {{ lang._('to the FWMAP_Watchlist alias? The map will flag its traffic as a threat. No firewall rule is added.')|json_encode }},
        marked: {{ lang._('Its traffic is flagged on the map within five minutes.')|json_encode }},
        inbound: {{ lang._('Inbound')|json_encode }},
        outbound: {{ lang._('Outbound')|json_encode }},
        this_firewall: {{ lang._('this firewall')|json_encode }},
        blacklist: {{ lang._('AbuseIPDB blacklist (downloaded daily)')|json_encode }},
        blacklist_addresses: {{ lang._('addresses')|json_encode }},
        blacklist_pending: {{ lang._('Not downloaded yet')|json_encode }},
        blacklist_error: {{ lang._('last attempt failed')|json_encode }},
        blacklist_no_key: {{ lang._('Add an AbuseIPDB API key in the Firewall Map widget settings to download it.')|json_encode }},
        active: {{ lang._('Active')|json_encode }},
        allowed_flagged: {{ lang._('Allowed · flagged')|json_encode }},
        attempts: {{ lang._('Attempts')|json_encode }},
        blocked: {{ lang._('Blocked')|json_encode }},
        blocked_attempts: {{ lang._('Blocked attempts')|json_encode }},
        blocked_flagged: {{ lang._('Blocked · flagged')|json_encode }},
        flagged: {{ lang._('flagged')|json_encode }},
        ips_dropped_flagged: {{ lang._('Dropped by IPS · flagged')|json_encode }},
        ips_dropped_title: {{ lang._('Dropped by IPS')|json_encode }},
        clean: {{ lang._('Clean')|json_encode }},
        connections: {{ lang._('Connections')|json_encode }},
        current_rate: {{ lang._('Current rate')|json_encode }},
        egress: {{ lang._('Egress')|json_encode }},
        idle: {{ lang._('Idle')|json_encode }},
        ids_on_address: {{ lang._('Alerts on this address in the last hour (not necessarily this traffic)')|json_encode }},
        ids_on_connection: {{ lang._('Alerts raised by this exact connection')|json_encode }},
        ids_only: {{ lang._('Seen by Suricata')|json_encode }},
        ids_only_sub: {{ lang._('No open connection')|json_encode }},
        in_minutes: {{ lang._('in %s min')|json_encode }},
        inside_side: {{ lang._('Inside side')|json_encode }},
        listed: {{ lang._('Listed')|json_encode }},
        more: {{ lang._('More')|json_encode }},
        no_connection: {{ lang._('No connection is open right now.')|json_encode }},
        no_ids: {{ lang._('No IDS alerts for this address')|json_encode }},
        no_ids_sub: {{ lang._('Suricata has not alerted on this address in the last hour.')|json_encode }},
        no_ids_talkers: {{ lang._('No Suricata alerts in the last hour')|json_encode }},
        select_hint: {{ lang._('Show the details')|json_encode }},
        last_updated: {{ lang._('Last updated:')|json_encode }},
        ids_alert: {{ lang._('IDS alert')|json_encode }},
        open_ids: {{ lang._('Open Suricata alerts')|json_encode }},
        open_log: {{ lang._('Open the firewall log')|json_encode }},
        port_word: {{ lang._('Port')|json_encode }},
        checking: {{ lang._('checking…')|json_encode }},
        check_now: {{ lang._('Check now')|json_encode }},
        no_key: {{ lang._('no API key')|json_encode }},
        not_listed_short: {{ lang._('Not listed')|json_encode }},
        status_dropped: {{ lang._('Dropped by IPS')|json_encode }},
        fw_passed: {{ lang._('Passed')|json_encode }},
        fw_blocked: {{ lang._('Blocked')|json_encode }},
        fw_not_seen: {{ lang._('not seen by the firewall')|json_encode }},
        ips_dropped_short: {{ lang._('IPS drop')|json_encode }},
        query: {{ lang._('query')|json_encode }},
        more_connection: {{ lang._('more connection')|json_encode }},
        more_connections: {{ lang._('more connections')|json_encode }},
        connection_col: {{ lang._('Connection')|json_encode }},
        no_snapshot: {{ lang._('No connection snapshot yet: it is taken the next time this address has an open connection.')|json_encode }},
        show_more: {{ lang._('Show %s more')|json_encode }},
        showing: {{ lang._('%s of %t shown')|json_encode }},
        dismiss_all: {{ lang._('Dismiss all (%s)')|json_encode }},
        dismiss_all_confirm: {{ lang._('Dismiss all %s new entries? You can reopen them from the Dismissed tab.')|json_encode }},
        delete_all: {{ lang._('Delete all (%s)')|json_encode }},
        delete_all_confirm: {{ lang._('Delete all %s %status entries for good? This cannot be undone. New traffic from these addresses would create new entries.')|json_encode }},
        sample: {{ lang._('sample')|json_encode }},
        other_target: {{ lang._('other target')|json_encode }},
        other_targets: {{ lang._('other targets')|json_encode }},
        targets_seen: {{ lang._('Targets')|json_encode }},
        other_hosts: {{ lang._('more inside')|json_encode }},
        more_details: {{ lang._('More details')|json_encode }},
        services_seen: {{ lang._('Services seen')|json_encode }},
        new_short: {{ lang._('new')|json_encode }},
        remote_port: {{ lang._('Remote port')|json_encode }},
        duration: {{ lang._('Duration')|json_encode }},
        alerts_short: {{ lang._('alerts')|json_encode }},
        flow_one: {{ lang._('flow')|json_encode }},
        flow_many: {{ lang._('flows')|json_encode }},
        organization: {{ lang._('Organization')|json_encode }},
        other_ports: {{ lang._('Other ports')|json_encode }},
        other_services: {{ lang._('Other services')|json_encode }},
        port_forward: {{ lang._('Port forward')|json_encode }},
        remote_addresses_here: {{ lang._('addresses here:')|json_encode }},
        remote_side: {{ lang._('Remote side')|json_encode }},
        sec_ids_long: {{ lang._('IDS (Suricata)')|json_encode }},
        started: {{ lang._('Started')|json_encode }},
        started_inside_long: {{ lang._('Started inside')|json_encode }},
        started_outside_long: {{ lang._('Started outside')|json_encode }},
        target: {{ lang._('Target')|json_encode }},
        this_firewall_title: {{ lang._('This firewall')|json_encode }},
        tried: {{ lang._('Tried')|json_encode }},
        review_queue: {{ lang._('Threats')|json_encode }},
        review_intro: {{ lang._('Flagged traffic organized by observed firewall and IPS disposition')|json_encode }},
        record_threats: {{ lang._('Record in the background')|json_encode }},
        record_threats_hint: {{ lang._('Keep recording while the map is closed, as long as the widget is on a dashboard. Setting a status never changes firewall rules.')|json_encode }},
        queue_search: {{ lang._('Filter by address, network, list, host…')|json_encode }},
        ago: {{ lang._('ago')|json_encode }},
        blacklist_short: {{ lang._('AbuseIPDB blacklist')|json_encode }},
        status_new: {{ lang._('New')|json_encode }},
        status_reviewed: {{ lang._('Reviewed')|json_encode }},
        status_dismissed: {{ lang._('Dismissed')|json_encode }},
        status_blocked: {{ lang._('Blocked')|json_encode }},
        status_all: {{ lang._('All')|json_encode }},
        status_passed: {{ lang._('Passed / reached host')|json_encode }},
        status_firewall_blocked: {{ lang._('Blocked by firewall')|json_encode }},
        status_ips_dropped: {{ lang._('Dropped by IPS')|json_encode }},
        disposition_passed: {{ lang._('Passed · reached host')|json_encode }},
        disposition_firewall_blocked: {{ lang._('Blocked at firewall')|json_encode }},
        disposition_ips_dropped: {{ lang._('Dropped by IPS')|json_encode }},
        passed_attention: {{ lang._('need attention')|json_encode }},
        mark_reviewed: {{ lang._('Mark reviewed')|json_encode }},
        dismiss: {{ lang._('Dismiss')|json_encode }},
        reopen: {{ lang._('Reopen')|json_encode }},
        block: {{ lang._('Block…')|json_encode }},
        block_title: {{ lang._('Add to a blocking alias')|json_encode }},
        block_hint: {{ lang._('The address is added to the alias you choose. It is blocked only if a firewall rule uses that alias.')|json_encode }},
        edit_note: {{ lang._('Note')|json_encode }},
        note_title: {{ lang._('Note for')|json_encode }},
        save: {{ lang._('Save')|json_encode }},
        first_seen: {{ lang._('First seen')|json_encode }},
        samples: {{ lang._('samples')|json_encode }},
        peak: {{ lang._('peak')|json_encode }},
        seen_after_block: {{ lang._('Traffic was seen after it was marked blocked: check that a rule uses the alias.')|json_encode }},
        active_flows_one: {{ lang._('{count} active flow')|json_encode }},
        active_flows_many: {{ lang._('{count} active flows')|json_encode }},
        blocked_sources_one: {{ lang._('{count} blocked source')|json_encode }},
        blocked_sources_many: {{ lang._('{count} blocked sources')|json_encode }},
        below_threshold: {{ lang._('{count} below threshold')|json_encode }},
        listed_flows_one: {{ lang._('{count} to a listed address')|json_encode }},
        listed_flows_many: {{ lang._('{count} to listed addresses')|json_encode }},
        dismiss_shown: {{ lang._('Dismiss %s shown')|json_encode }},
        dismiss_shown_confirm: {{ lang._('Dismiss the %s new entries this search shows? You can reopen them from the Dismissed tab.')|json_encode }},
        delete_shown: {{ lang._('Delete %s shown')|json_encode }},
        queue_no_match: {{ lang._('No entries match this search.')|json_encode }},
        queue_empty: {{ lang._('Nothing here.')|json_encode }},
        queue_empty_passed: {{ lang._('No unreviewed flagged traffic reached a host.')|json_encode }},
        queue_empty_firewall_blocked: {{ lang._('No unreviewed flagged traffic was blocked by PF.')|json_encode }},
        queue_empty_ips_dropped: {{ lang._('No unreviewed flagged traffic was dropped by IPS.')|json_encode }},
        queue_empty_reviewed: {{ lang._('No entries marked reviewed yet.')|json_encode }},
        queue_empty_dismissed: {{ lang._('No dismissed entries.')|json_encode }},
        queue_empty_all: {{ lang._('Threat history is empty.')|json_encode }},
        too_many_states: {{ lang._('The state table is too large to map ({count} states). The map resumes below {limit}.')|json_encode }},
        resize_hint: {{ lang._('Drag or use the arrow keys to resize; double-click or Home to reset')|json_encode }},
        today: {{ lang._('Today')|json_encode }},
        snapshot: {{ lang._('Snapshot')|json_encode }},
        snapshots: {{ lang._('Snapshots')|json_encode }},
        snapshot_flows_one: {{ lang._('{count} flow')|json_encode }},
        snapshot_flows_many: {{ lang._('{count} flows')|json_encode }},
        snapshot_flagged_one: {{ lang._('{count} flagged')|json_encode }},
        snapshot_flagged_many: {{ lang._('{count} flagged')|json_encode }},
        snapshot_saved: {{ lang._('Snapshot saved')|json_encode }},
        snapshot_open: {{ lang._('Open')|json_encode }},
        snapshot_note: {{ lang._('Snapshot note')|json_encode }},
        snapshot_add_note: {{ lang._('Add a note')|json_encode }},
        snapshot_edit_note: {{ lang._('Edit note')|json_encode }},
        snapshot_has_note: {{ lang._('note')|json_encode }},
        snapshot_download: {{ lang._('Download as JSON')|json_encode }},
        snapshot_delete: {{ lang._('Delete snapshot')|json_encode }},
        snapshot_delete_confirm: {{ lang._('Delete the snapshot taken')|json_encode }},
        snapshot_by: {{ lang._('by')|json_encode }},
        snapshot_partial: {{ lang._('summary only')|json_encode }},
        snapshot_partial_hint: {{ lang._('The collector did not answer in time: the map as shown was saved, without the connection states.')|json_encode }},
        snapshot_no_states: {{ lang._('This snapshot was saved without connection states.')|json_encode }},
        snapshot_show: {{ lang._('Show this snapshot')|json_encode }},
        snapshot_older: {{ lang._('Older snapshot')|json_encode }},
        snapshot_newer: {{ lang._('Newer snapshot')|json_encode }},
        no_snapshots: {{ lang._('No snapshots yet: take one with the camera button on the map.')|json_encode }},
        snapshots_kept: {{ lang._('The newest %s are kept, for up to %d days.')|json_encode }},
        back_to_live: {{ lang._('Back to live')|json_encode }},
        timeline: {{ lang._('Timeline')|json_encode }},
        timeline_expand: {{ lang._('Show the timeline')|json_encode }},
        timeline_collapse: {{ lang._('Collapse the timeline')|json_encode }},
        timeline_previous_day: {{ lang._('Previous day with snapshots')|json_encode }},
        timeline_next_day: {{ lang._('Next day with snapshots')|json_encode }},
        snapshots_here_one: {{ lang._('{count} snapshot')|json_encode }},
        snapshots_here_many: {{ lang._('{count} snapshots taken close together')|json_encode }},
        captured: {{ lang._('Captured')|json_encode }},
        as_captured: {{ lang._('As captured at')|json_encode }},
        may_have_closed: {{ lang._('this connection may have closed since')|json_encode }},
        states_at: {{ lang._('States at')|json_encode }},
        current_states: {{ lang._('Current states')|json_encode }},
        // the renderer's words: legend, hover cards and flow sentences ({name} is filled in)
        map_started_inside: {{ lang._('Started inside')|json_encode }},
        map_started_outside: {{ lang._('Started outside')|json_encode }},
        map_started_both: {{ lang._('Started from both sides')|json_encode }},
        map_toward: {{ lang._('Toward the firewall')|json_encode }},
        map_away: {{ lang._('Away from the firewall')|json_encode }},
        map_blocked: {{ lang._('Blocked')|json_encode }},
        map_flagged_blocked: {{ lang._('Flagged · blocked')|json_encode }},
        map_flagged_allowed: {{ lang._('Flagged · allowed')|json_encode }},
        map_allowed: {{ lang._('Allowed')|json_encode }},
        map_ids_alert: {{ lang._('IDS alert')|json_encode }},
        map_minutes: {{ lang._('{count} min')|json_encode }},
        map_hours: {{ lang._('{count} h')|json_encode }},
        map_days: {{ lang._('{count} days')|json_encode }},
        map_moments: {{ lang._('moments')|json_encode }},
        map_port: {{ lang._('port {port}')|json_encode }},
        map_traffic: {{ lang._('traffic')|json_encode }},
        map_this_firewall: {{ lang._('this firewall')|json_encode }},
        map_this_firewall_title: {{ lang._('This firewall')|json_encode }},
        map_other_targets_one: {{ lang._(' (and {count} other target)')|json_encode }},
        map_other_targets_many: {{ lang._(' (and {count} other targets)')|json_encode }},
        map_through_forward: {{ lang._(' through a port forward')|json_encode }},
        map_open_for: {{ lang._(', open for {duration}')|json_encode }},
        map_reached: {{ lang._('{other} reached {where} on {service}{more}{forwarded}{open}.')|json_encode }},
        map_other_hosts_one: {{ lang._('{host} and {count} other host')|json_encode }},
        map_other_hosts_many: {{ lang._('{host} and {count} other hosts')|json_encode }},
        map_other_services_one: {{ lang._(' and {count} other service')|json_encode }},
        map_other_services_many: {{ lang._(' and {count} other services')|json_encode }},
        map_queried: {{ lang._('{who} queried {service}{more} at {other}')|json_encode }},
        map_synced: {{ lang._('{who} synced time with {other} over {service}{more}')|json_encode }},
        map_mailed: {{ lang._('{who} delivered mail to {other} over {service}{more}')|json_encode }},
        map_pinged: {{ lang._('{who} pinged {other}')|json_encode }},
        map_opened: {{ lang._('{who} opened {service}{more} to {other}')|json_encode }},
        map_a_connection: {{ lang._('a connection')|json_encode }},
        map_other_ports_one: {{ lang._(' and {count} other port')|json_encode }},
        map_other_ports_many: {{ lang._(' and {count} other ports')|json_encode }},
        map_and: {{ lang._(' and ')|json_encode }},
        map_by_rule: {{ lang._(' by "{rule}"')|json_encode }},
        map_on_interface: {{ lang._(' on {interface}')|json_encode }},
        map_first_seen_ago: {{ lang._(', first seen {duration} ago')|json_encode }},
        map_block_sentence: {{ lang._('{source}{place} tried {tried} on this firewall: blocked {hits}× in the last {minutes} min{rule}{where}{since}.')|json_encode }},
        map_ids_line: {{ lang._('Suricata: {signature} (severity {severity}{category})')|json_encode }},
        map_ids_first: {{ lang._(', {count}× in the last {window}, latest {latest} ago')|json_encode }},
        map_ids_count: {{ lang._(', {count}×')|json_encode }},
        map_more_alerts_one: {{ lang._('and {count} more alert')|json_encode }},
        map_more_alerts_many: {{ lang._('and {count} more alerts')|json_encode }},
        map_more_addresses_one: {{ lang._('+{count} more address here')|json_encode }},
        map_more_addresses_many: {{ lang._('+{count} more addresses here')|json_encode }},
        map_addresses_many: {{ lang._('{count} addresses')|json_encode }},
        map_via: {{ lang._('via {egress}')|json_encode }},
        map_open_state: {{ lang._('open for {duration}')|json_encode }},
        map_closed: {{ lang._('closed')|json_encode }},
        map_ips_dropped: {{ lang._('Dropped by IPS')|json_encode }},
        map_ips_dropped_flagged: {{ lang._('Dropped by IPS · flagged')|json_encode }},
        map_ids_connection: {{ lang._('Suricata alerted on this connection')|json_encode }},
        map_ids_connection_dropped: {{ lang._('Suricata alerted on this connection · dropped by IPS')|json_encode }},
        map_rule: {{ lang._('rule: {rule}')|json_encode }},
        map_seen_by_suricata: {{ lang._('Seen by Suricata')|json_encode }},
        map_seen_by_suricata_flagged: {{ lang._('Seen by Suricata · flagged')|json_encode }},
        map_no_connection: {{ lang._('No connection is open right now')|json_encode }},
        map_last_minute: {{ lang._('{count} in the last minute')|json_encode }},
        map_hammering: {{ lang._(' · hammering')|json_encode }},
        map_active_links_one: {{ lang._('{count} active link')|json_encode }},
        map_active_links_many: {{ lang._('{count} active links')|json_encode }},
    };
</script>
<script src="/ui/js/firewall-map-renderer.js?v={{ rendererVersion }}"></script>
<script src="/ui/js/firewall-map-page.js?v={{ pageVersion }}"></script>

<div class="content-box" style="padding: 12px;">
    <div id="fwmap-layout">
        <div id="fwmap-main">
    <div id="fwmap-toolbar">
            <div id="fwmap-mode" class="fwmap-mode" role="group" aria-label="{{ lang._('Map mode') }}">
                <button type="button" id="fwmap-mode-live" class="active" data-mode="live" aria-pressed="true"><i class="fwmap-live"></i>{{ lang._('Live') }}</button>
                <button type="button" id="fwmap-mode-snapshots" data-mode="snapshots" aria-pressed="false" disabled><svg class="fwmap-ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M3 8.5A1.5 1.5 0 0 1 4.5 7h2.6l1.6-2.4h6.6L16.9 7h2.6A1.5 1.5 0 0 1 21 8.5v9A1.5 1.5 0 0 1 19.5 19h-15A1.5 1.5 0 0 1 3 17.5z"/><circle cx="12" cy="12.8" r="3.4"/></svg>{{ lang._('Snapshots') }} <span class="badge" id="fwmap-snapshot-count"></span></button>
            </div>
            <span class="fwmap-tool-sep" aria-hidden="true"></span>
            <div id="fwmap-chips" role="group" aria-label="{{ lang._('Filters') }}">
                <span class="fwmap-chip" data-filter="traffic"><svg class="fwmap-ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M7 20V4M3 8l4-4 4 4M17 4v16M13 16l4 4 4-4"/></svg><select id="fwmap-filter-traffic" aria-label="{{ lang._('Traffic') }}">
                    <option value="all">{{ lang._('All traffic') }}</option>
                    <option value="permitted">{{ lang._('Permitted') }}</option>
                    <option value="blocked">{{ lang._('Blocked') }}</option>
                    <option value="threats">{{ lang._('Threats that got through') }}</option>
                    <option value="ids">{{ lang._('IDS alerts') }}</option>
                    <option value="ids_flows">{{ lang._('IDS flows') }}</option>
                    <option value="ids_addresses">{{ lang._('IDS addresses') }}</option>
                </select><svg class="fwmap-ic fwmap-chip-caret" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m6 9 6 6 6-6"/></svg><button type="button" class="fwmap-chip-clear" title="{{ lang._('Show all') }}" aria-label="{{ lang._('Show all') }}"><svg class="fwmap-ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" aria-hidden="true"><path d="M18 6 6 18M6 6l12 12"/></svg></button></span>
                <span class="fwmap-chip" data-filter="iface"><svg class="fwmap-ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="9" y="2" width="6" height="6" rx="1"/><rect x="16" y="16" width="6" height="6" rx="1"/><rect x="2" y="16" width="6" height="6" rx="1"/><path d="M5 16v-3a1 1 0 0 1 1-1h12a1 1 0 0 1 1 1v3M12 12V8"/></svg><select id="fwmap-filter-iface" aria-label="{{ lang._('Interface') }}"></select><svg class="fwmap-ic fwmap-chip-caret" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m6 9 6 6 6-6"/></svg><button type="button" class="fwmap-chip-clear" title="{{ lang._('Show all') }}" aria-label="{{ lang._('Show all') }}"><svg class="fwmap-ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" aria-hidden="true"><path d="M18 6 6 18M6 6l12 12"/></svg></button></span>
                <span class="fwmap-chip" data-filter="host"><svg class="fwmap-ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="4" y="4" width="16" height="11" rx="1.5"/><path d="M2 19h20"/></svg><select id="fwmap-filter-host" aria-label="{{ lang._('Inside host') }}"></select><svg class="fwmap-ic fwmap-chip-caret" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m6 9 6 6 6-6"/></svg><button type="button" class="fwmap-chip-clear" title="{{ lang._('Show all') }}" aria-label="{{ lang._('Show all') }}"><svg class="fwmap-ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" aria-hidden="true"><path d="M18 6 6 18M6 6l12 12"/></svg></button></span>
                <span class="fwmap-chip" data-filter="service"><svg class="fwmap-ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/></svg><select id="fwmap-filter-service" aria-label="{{ lang._('Service') }}"></select><svg class="fwmap-ic fwmap-chip-caret" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m6 9 6 6 6-6"/></svg><button type="button" class="fwmap-chip-clear" title="{{ lang._('Show all') }}" aria-label="{{ lang._('Show all') }}"><svg class="fwmap-ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" aria-hidden="true"><path d="M18 6 6 18M6 6l12 12"/></svg></button></span>
                <span class="fwmap-chip" data-filter="country"><svg class="fwmap-ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="10"/><path d="M2 12h20"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg><select id="fwmap-filter-country" aria-label="{{ lang._('Country') }}"></select><svg class="fwmap-ic fwmap-chip-caret" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m6 9 6 6 6-6"/></svg><button type="button" class="fwmap-chip-clear" title="{{ lang._('Show all') }}" aria-label="{{ lang._('Show all') }}"><svg class="fwmap-ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" aria-hidden="true"><path d="M18 6 6 18M6 6l12 12"/></svg></button></span>
                <span id="fwmap-filter-asn" class="fwmap-chip active"><span></span><a href="#" class="fwmap-chip-clear" title="{{ lang._('Remove') }}" aria-label="{{ lang._('Remove') }}">&times;</a></span>
                <div id="fwmap-more-wrap" style="display:none">
                    <button type="button" id="fwmap-more" class="fwmap-chip" aria-haspopup="true" aria-expanded="false"><svg class="fwmap-ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M3 5h18l-7 8v6l-4 2v-8z"/></svg><span>{{ lang._('Filters') }}</span> <span class="badge" id="fwmap-more-count"></span><svg class="fwmap-ic fwmap-chip-caret" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m6 9 6 6 6-6"/></svg></button>
                    <div id="fwmap-more-menu" role="group" aria-label="{{ lang._('More filters') }}"></div>
                </div>
                <button id="fwmap-reset" type="button" title="{{ lang._('Reset filters') }}" aria-label="{{ lang._('Reset filters') }}" style="display:none"><svg class="fwmap-ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M3 12a9 9 0 1 0 3-6.7L3 8"/><path d="M3 3v5h5"/></svg></button>
            </div>
            <button id="fwmap-review" class="btn btn-default btn-sm fwmap-tool-btn" type="button" style="display:none" title="{{ lang._('Threats') }}">
                <svg class="fwmap-ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01"/></svg><span class="fwmap-tool-text">{{ lang._('Threats') }}</span> <span class="badge" id="fwmap-review-count"></span>
            </button>
        </div>
        <div id="fwmap-map">
            <div id="fwmap-grid" aria-hidden="true"></div>
            <div id="fwmap-canvas"></div>
            <div id="fwmap-legend">
                <label class="fwmap-legend-mode"><span>{{ lang._('Colour') }}</span>
                    <select id="fwmap-color" aria-label="{{ lang._('Colour') }}">
                        <option value="initiator">{{ lang._('By who connected') }}</option>
                        <option value="direction">{{ lang._('By data direction') }}</option>
                        <option value="egress">{{ lang._('By egress') }}</option>
                        <option value="service">{{ lang._('By service') }}</option>
                    </select><svg class="fwmap-ic fwmap-chip-caret" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m6 9 6 6 6-6"/></svg></label>
                <span id="fwmap-legend-items"></span>
            </div>
            <div id="fwmap-zoom">
                <button type="button" data-zoom="1" title="{{ lang._('Zoom in') }}" aria-label="{{ lang._('Zoom in') }}"><svg class="fwmap-ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 5v14M5 12h14"/></svg></button>
                <button type="button" data-zoom="-1" title="{{ lang._('Zoom out') }}" aria-label="{{ lang._('Zoom out') }}"><svg class="fwmap-ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12h14"/></svg></button>
                <button type="button" data-zoom="fit" title="{{ lang._('Whole world') }}" aria-label="{{ lang._('Whole world') }}"><svg class="fwmap-ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M8 3H5a2 2 0 0 0-2 2v3M21 8V5a2 2 0 0 0-2-2h-3M3 16v3a2 2 0 0 0 2 2h3M16 21h3a2 2 0 0 0 2-2v-3"/></svg></button>
                <button type="button" id="fwmap-follow" data-zoom="follow" aria-pressed="false" title="{{ lang._('Follow traffic: keep the map zoomed to the current arcs') }}" aria-label="{{ lang._('Follow traffic') }}"><svg class="fwmap-ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="7"/><circle cx="12" cy="12" r="2.5"/><path d="M12 2v3M12 19v3M2 12h3M19 12h3"/></svg></button>
            </div>
            <button type="button" id="fwmap-camera" title="{{ lang._('Take a snapshot: save the map as it is now, to review later') }}" aria-label="{{ lang._('Take a snapshot') }}"><svg class="fwmap-ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M3 8.5A1.5 1.5 0 0 1 4.5 7h2.6l1.6-2.4h6.6L16.9 7h2.6A1.5 1.5 0 0 1 21 8.5v9A1.5 1.5 0 0 1 19.5 19h-15A1.5 1.5 0 0 1 3 17.5z"/><circle cx="12" cy="12.8" r="3.4"/></svg></button>
            <div id="fwmap-banner" style="display:none" aria-live="polite"></div>
            <div id="fwmap-timeline" style="display:none"></div>
            <div id="fwmap-credit"></div>
        </div>
        <div id="fwmap-statusbar"><div id="fwmap-status" aria-live="polite"></div><div id="fwmap-updated"></div></div>
        </div>
        <div class="fwmap-splitter fwmap-splitter-v" id="fwmap-split-side" title="{{ lang._('Drag or use the arrow keys to resize; double-click or Home to reset') }}"></div>
        <div id="fwmap-side">
            <div id="fwmap-talkers">
                <ul class="nav nav-tabs" role="tablist" aria-label="{{ lang._('Top talkers') }}">
                    <li class="active" role="presentation"><a href="#" role="tab" aria-selected="true" data-tab="hosts" title="{{ lang._('Hosts') }}">{{ lang._('Hosts') }}</a></li>
                    <li role="presentation"><a href="#" role="tab" aria-selected="false" data-tab="countries" title="{{ lang._('Countries') }}">{{ lang._('Countries') }}</a></li>
                    <li role="presentation"><a href="#" role="tab" aria-selected="false" data-tab="networks" title="{{ lang._('Networks') }}">{{ lang._('Networks') }}</a></li>
                    <li role="presentation"><a href="#" role="tab" aria-selected="false" data-tab="ids" title="{{ lang._('IDS') }}">{{ lang._('IDS') }}</a></li>
                    <li role="presentation"><a href="#" role="tab" aria-selected="false" data-tab="snapshots" title="{{ lang._('Snapshots') }}">{{ lang._('Snapshots') }}</a></li>
                </ul>
                <div class="fwmap-talker-tools">
                    <div class="fwmap-talker-search"><svg class="fwmap-ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="7"/><path d="m21 21-5-5"/></svg>
                        <input type="search" class="form-control" id="fwmap-talker-search" placeholder="{{ lang._('Search…') }}" aria-label="{{ lang._('Search…') }}"></div>
                    <select class="form-control" id="fwmap-talker-sort" aria-label="{{ lang._('Sort') }}">
                        <option value="rate">{{ lang._('Top talkers') }}</option>
                        <option value="flows">{{ lang._('Most flows') }}</option>
                        <option value="name">{{ lang._('Name') }}</option>
                    </select>
                </div>
                <div id="fwmap-talkers-list"></div>
            </div>
            <div class="fwmap-splitter fwmap-splitter-h" id="fwmap-split-details" title="{{ lang._('Drag or use the arrow keys to resize; double-click or Home to reset') }}"></div>
            <div id="fwmap-details-box">
                <div id="fwmap-details"></div>
            </div>
        </div>
    </div>
</div>
