"""Embedded operator dashboard page for the IronMesh bridge daemon.

``GUI_HTML`` is the complete, self-contained dashboard document
(inline CSS + JS, no external assets) served by the bridge daemon's
GUI HTTP endpoint. It is kept in its own module so the daemon logic
in ``bridge.py`` stays navigable; the served bytes are unchanged.

The ``{{IRONMESH_VERSION}}`` placeholder is substituted at serve time.
"""

GUI_HTML = r"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<!-- CSP: lock the rendered dashboard to same-origin only. Pull the plug on your router — this keeps working.
     'unsafe-inline' for style/script is scoped to the bytes baked into bridge.py; peer payloads are HTML-escaped. -->
<meta http-equiv="Content-Security-Policy" content="default-src 'self'; connect-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'">
<title>IRONMESH · Operator Console</title>
<link rel="manifest" href="/manifest.json">
<meta name="theme-color" content="#050505">
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
 --bg:#050505; --surface:#0c0c0c; --surface-2:#121212;
 --border:#1a1a1a; --border-2:#222;
 --text:#e8e8e8; --text-dim:#888; --text-faint:#555;
 --signal:#5aff6e; --signal-dim:#3bcc4d;
 --warn:#ffb340; --alarm:#f85149;
 --metallic:#9aa0a6;
 --mono:ui-monospace,SFMono-Regular,"Cascadia Code",Consolas,"Liberation Mono",monospace;
 --sans:ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif;
}
html,body{height:100%}
body{font-family:var(--sans);background:var(--bg);color:var(--text);font-size:13px;line-height:1.5;overflow-x:hidden}
.mono{font-family:var(--mono)}
button{font-family:inherit}

/* Background grid, subtle — matches site identity. */
body::before{content:'';position:fixed;inset:0;pointer-events:none;z-index:0;
 background-image:linear-gradient(rgba(90,255,110,.02) 1px,transparent 1px),linear-gradient(90deg,rgba(90,255,110,.02) 1px,transparent 1px);
 background-size:48px 48px}

/* === HEADER === */
.chrome{position:sticky;top:0;z-index:50;background:rgba(5,5,5,.92);backdrop-filter:blur(10px);
 border-bottom:1px solid var(--border);padding:10px 20px;
 display:flex;align-items:center;gap:14px;flex-wrap:wrap}
.wordmark{font-family:var(--mono);font-weight:700;font-size:16px;letter-spacing:2px;color:var(--signal);
 text-shadow:0 0 18px rgba(90,255,110,.28)}
.version-pill{font-family:var(--mono);font-size:10px;color:var(--warn);background:rgba(255,179,64,.08);
 border:1px solid rgba(255,179,64,.3);padding:2px 8px;border-radius:3px;letter-spacing:1px}
.node-fp{font-family:var(--mono);font-size:11px;color:var(--text-dim);cursor:pointer;user-select:none;
 padding:2px 6px;border-radius:3px}
.node-fp:hover{color:var(--signal);background:rgba(90,255,110,.05)}
.mesh-state{display:inline-flex;align-items:center;gap:6px;font-family:var(--mono);font-size:11px;
 letter-spacing:1.5px;padding:4px 10px;border-radius:3px;border:1px solid}
.mesh-state[data-state="OPERATIONAL"]{color:var(--signal);border-color:rgba(90,255,110,.3);background:rgba(90,255,110,.05)}
.mesh-state[data-state="DEGRADED"]   {color:var(--warn);  border-color:rgba(255,179,64,.3);background:rgba(255,179,64,.05)}
.mesh-state[data-state="ISOLATED"]   {color:var(--alarm); border-color:rgba(248,81,73,.3); background:rgba(248,81,73,.05)}
.mesh-state .dot{width:6px;height:6px;border-radius:50%;background:currentColor;box-shadow:0 0 8px currentColor}
.uptime{font-family:var(--mono);font-size:11px;color:var(--text-dim)}
.offline-badge{font-family:var(--mono);font-size:10px;color:var(--signal);
 border:1px solid var(--signal-dim);padding:3px 8px;border-radius:3px;letter-spacing:1.5px}
.token-box{display:flex;align-items:center;gap:4px;background:var(--surface);border:1px solid var(--border);
 padding:2px 6px;border-radius:3px;font-family:var(--mono);font-size:11px;color:var(--text-dim);margin-left:auto}
.token-box > span:first-child{letter-spacing:1.5px;padding-right:4px;border-right:1px solid var(--border-2);font-size:10px}
.token-box input{background:transparent;border:0;color:var(--text-dim);font-family:var(--mono);font-size:11px;
 width:130px;outline:none;padding:2px 4px}
.icon-btn{background:transparent;border:0;color:var(--text-dim);cursor:pointer;padding:3px;display:inline-flex;align-items:center;border-radius:3px}
.icon-btn:hover{color:var(--signal);background:rgba(90,255,110,.08)}
.icon{width:14px;height:14px;fill:none;stroke:currentColor;stroke-width:2;stroke-linecap:round;stroke-linejoin:round}

/* === STAT STRIP === */
.stat-strip{display:grid;grid-template-columns:repeat(6,1fr);gap:1px;background:var(--border);
 border-bottom:1px solid var(--border);position:relative;z-index:1}
@media(max-width:1200px){.stat-strip{grid-template-columns:repeat(3,1fr)}}
@media(max-width:600px){.stat-strip{grid-template-columns:repeat(2,1fr)}}
.stat{background:var(--bg);padding:14px 16px;display:flex;flex-direction:column;gap:4px;position:relative;min-height:78px}
.stat .label{font-family:var(--mono);font-size:10px;text-transform:uppercase;letter-spacing:1.5px;color:var(--text-faint)}
.stat .value{font-family:var(--mono);font-size:22px;font-weight:700;color:var(--text);line-height:1.15}
.stat .value.signal{color:var(--signal)} .stat .value.warn{color:var(--warn)} .stat .value.alarm{color:var(--alarm)}
.stat .sub{font-family:var(--mono);font-size:10px;color:var(--text-faint)}
.stat .spark{position:absolute;right:12px;bottom:10px;width:64px;height:20px;opacity:.75}

/* === MAIN === */
main{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr);gap:1px;background:var(--border);
 position:relative;z-index:1}
@media(max-width:1100px){main{grid-template-columns:1fr}}
.panel{background:var(--bg);display:flex;flex-direction:column;min-width:0}
.panel-hdr{display:flex;align-items:center;gap:10px;padding:10px 16px;border-bottom:1px solid var(--border);
 font-family:var(--mono);font-size:10px;text-transform:uppercase;letter-spacing:2px;color:var(--text-dim)}
.panel-hdr .title{color:var(--text)}
.panel-hdr .count{color:var(--signal);background:rgba(90,255,110,.08);padding:1px 6px;border-radius:2px;font-size:10px;letter-spacing:1px}
.panel-hdr .tools{margin-left:auto;display:flex;gap:4px}
.panel-hdr input.filter{background:var(--surface);border:1px solid var(--border);color:var(--text);
 font-family:var(--mono);font-size:11px;padding:4px 8px;border-radius:3px;outline:none;width:140px}
.panel-hdr input.filter:focus{border-color:var(--signal-dim)}

/* === PEER TABLE === */
.peer-wrap{overflow-x:auto}
table.peers{width:100%;border-collapse:collapse}
table.peers th{text-align:left;padding:8px 12px;font-family:var(--mono);font-size:9px;
 text-transform:uppercase;letter-spacing:1.5px;color:var(--text-faint);
 border-bottom:1px solid var(--border);position:sticky;top:0;background:var(--bg);z-index:1}
table.peers td{padding:8px 12px;border-bottom:1px solid var(--border);font-family:var(--mono);font-size:12px;
 color:var(--text);white-space:nowrap}
table.peers tr{cursor:pointer}
table.peers tr:hover td{background:rgba(90,255,110,.03)}
table.peers tr.selected td{background:rgba(90,255,110,.08);border-left:2px solid var(--signal);padding-left:10px}
table.peers tr.mismatch td{background:rgba(248,81,73,.08)}
table.peers tr.mismatch:hover td{background:rgba(248,81,73,.14)}
.peer-name{color:var(--signal)}
.trust-state{display:inline-block;padding:1px 6px;font-size:10px;border-radius:2px;letter-spacing:1px}
.trust-verified{color:var(--signal);background:rgba(90,255,110,.1)}
.trust-tofu    {color:var(--metallic);background:rgba(154,160,166,.1)}
.trust-pending {color:var(--warn);background:rgba(255,179,64,.1)}
.trust-mismatch{color:var(--alarm);background:rgba(248,81,73,.15);font-weight:700}
.transport-badge{display:inline-block;font-size:10px;padding:1px 6px;border-radius:2px;
 border:1px solid var(--border-2);color:var(--text-dim);letter-spacing:1px}
.transport-ws  {color:var(--signal);border-color:rgba(90,255,110,.3)}
.transport-rns {color:var(--warn);  border-color:rgba(255,179,64,.3)}
.transport-both{color:var(--signal);border-color:rgba(90,255,110,.3);background:rgba(90,255,110,.04)}
.cap-pill{display:inline-block;font-size:10px;color:var(--text-dim);background:var(--surface);
 padding:1px 5px;border-radius:2px;margin-right:3px}

/* === HANDSHAKE === */
.hs-box{padding:14px 18px;font-family:var(--mono);font-size:11px;color:var(--text-dim);
 white-space:pre;overflow-x:auto;line-height:1.5}
.hs-stage{color:var(--text-faint);display:block}
.hs-stage.ok    {color:var(--signal)}
.hs-stage.active{color:var(--warn)}
.hs-stage.fail  {color:var(--alarm)}

/* === TRANSPORT === */
.transport-panel{display:grid;grid-template-columns:1fr 1fr;border-top:1px solid var(--border)}
@media(max-width:900px){.transport-panel{grid-template-columns:1fr}}
.tp-cell{padding:10px 16px;border-right:1px solid var(--border);font-family:var(--mono);font-size:11px;color:var(--text)}
.tp-cell:last-child{border-right:0}
.tp-cell.disabled{opacity:.45}
.tp-cell .tp-title{font-size:10px;letter-spacing:1.5px;color:var(--text-faint);text-transform:uppercase;margin-bottom:6px}
.tp-cell .tp-row{display:flex;justify-content:space-between;padding:2px 0}
.tp-cell .tp-row .k{color:var(--text-dim)}
.tp-cell .tp-row .v{color:var(--text)}

/* === FEED === */
.feed-tools{display:flex;gap:8px;padding:8px 12px;border-bottom:1px solid var(--border);align-items:center}
.feed-tools input[type=text]{flex:1;background:var(--surface);border:1px solid var(--border);
 color:var(--text);font-family:var(--mono);font-size:11px;padding:5px 8px;border-radius:3px;outline:none}
.feed-tools input[type=text]:focus{border-color:var(--signal-dim)}
.feed-tools label{font-family:var(--mono);font-size:10px;color:var(--text-dim);display:inline-flex;align-items:center;gap:4px;cursor:pointer;user-select:none}
.feed-body{overflow-y:auto;font-family:var(--mono);font-size:11px;max-height:420px;min-height:260px}
.feed-row{display:grid;grid-template-columns:4px 70px 12px 68px 96px 1fr;gap:8px;padding:3px 12px;
 border-bottom:1px solid rgba(26,26,26,.55);line-height:1.5}
.feed-row:hover{background:rgba(90,255,110,.02)}
.feed-row .gutter{border-left:2px solid transparent;height:100%}
.feed-row.sev-info  .gutter{border-color:var(--text-faint)}
.feed-row.sev-ok    .gutter{border-color:var(--signal-dim)}
.feed-row.sev-warn  .gutter{border-color:var(--warn)}
.feed-row.sev-alarm .gutter{border-color:var(--alarm)}
.feed-row .time{color:var(--text-faint);font-size:10px}
.feed-row .dir {color:var(--text-dim);text-align:center}
.feed-row .dir.in {color:var(--signal)}
.feed-row .dir.out{color:var(--warn)}
.feed-row .type{color:var(--metallic);font-size:10px;text-transform:uppercase;letter-spacing:1px}
.feed-row .peer{color:var(--text-dim);overflow:hidden;text-overflow:ellipsis}
.feed-row .payload{color:var(--text);word-break:break-all;white-space:pre-wrap;font-size:11px}

/* === SEND === */
.send-wrap{border-top:1px solid var(--border);padding:10px 12px;background:var(--surface)}
.send-row{display:flex;gap:6px;margin-bottom:6px;align-items:center;flex-wrap:wrap}
.send-row:last-child{margin-bottom:0}
.send-row select,.send-row input,.send-row textarea{background:var(--bg);border:1px solid var(--border);
 color:var(--text);font-family:var(--mono);font-size:12px;padding:6px 8px;border-radius:3px;outline:none;min-width:0}
.send-row select,.send-row input[type=text],.send-row textarea{flex:1}
.send-row select:focus,.send-row input:focus,.send-row textarea:focus{border-color:var(--signal-dim)}
.send-row input[type=number]{max-width:70px;flex:0 0 auto}
.send-row textarea{resize:vertical;font-family:var(--mono)}
.btn-signal{background:transparent;color:var(--signal);border:1px solid var(--signal-dim);
 cursor:pointer;font-weight:700;letter-spacing:2px;text-transform:uppercase;padding:6px 14px;font-size:11px;
 font-family:var(--mono);border-radius:3px}
.btn-signal:hover{background:rgba(90,255,110,.08)}
.btn-alarm{background:transparent;color:var(--alarm);border:1px solid rgba(248,81,73,.4);cursor:pointer;
 font-size:11px;font-family:var(--mono);text-transform:uppercase;letter-spacing:1.5px;padding:6px 12px;border-radius:3px}
.btn-alarm:hover{background:rgba(248,81,73,.1)}

/* === FOOTER === */
footer.ops{border-top:1px solid var(--border);background:var(--bg);padding:10px 20px;
 display:flex;gap:8px;flex-wrap:wrap;align-items:center;font-family:var(--mono);font-size:11px;position:relative;z-index:1}
footer.ops .ops-label{color:var(--text-faint);letter-spacing:1.5px;text-transform:uppercase;font-size:10px;margin-right:6px}
footer.ops button{background:transparent;border:1px solid var(--border);color:var(--text-dim);
 padding:5px 10px;border-radius:3px;cursor:pointer;font-family:var(--mono);font-size:11px;
 display:inline-flex;align-items:center;gap:6px;letter-spacing:1px}
footer.ops button:hover{color:var(--signal);border-color:var(--signal-dim)}
footer.ops button.btn-alarm:hover{color:var(--alarm);border-color:var(--alarm)}
footer.ops .spacer{flex:1}
footer.ops .legal{color:var(--text-faint);font-size:10px;letter-spacing:.5px}

/* === STATUSLINE === */
.statusline{position:fixed;bottom:0;left:0;right:0;background:var(--surface);
 border-top:1px solid var(--signal-dim);color:var(--signal);padding:6px 16px;
 font-family:var(--mono);font-size:11px;transform:translateY(100%);
 transition:transform .18s ease;z-index:100;letter-spacing:.5px}
.statusline.show{transform:translateY(0)}
.statusline.warn {color:var(--warn); border-top-color:var(--warn)}
.statusline.alarm{color:var(--alarm);border-top-color:var(--alarm)}

/* === SCROLLBARS === */
::-webkit-scrollbar{width:6px;height:6px}
::-webkit-scrollbar-track{background:var(--bg)}
::-webkit-scrollbar-thumb{background:var(--border-2)}
::-webkit-scrollbar-thumb:hover{background:var(--text-faint)}

.empty{padding:28px 16px;text-align:center;color:var(--text-faint);font-family:var(--mono);font-size:11px;letter-spacing:1px}

/* === MOBILE === */
@media(max-width:600px){
 .chrome{padding:8px 10px;gap:8px}
 .wordmark{font-size:14px;letter-spacing:1.5px}
 .token-box{display:none}
 .stat{padding:10px 12px;min-height:64px}
 .stat .value{font-size:18px}
 .stat .spark{display:none}
 .feed-body{max-height:320px}
 .send-row select,.send-row input,.send-row textarea,.send-row button{min-height:36px;font-size:13px}
}
</style></head><body>

<!-- Inline SVG sprite — no CDN, no outbound requests. -->
<svg style="display:none" aria-hidden="true">
 <symbol id="i-copy" viewBox="0 0 24 24"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></symbol>
 <symbol id="i-eye" viewBox="0 0 24 24"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></symbol>
 <symbol id="i-eye-off" viewBox="0 0 24 24"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></symbol>
 <symbol id="i-refresh" viewBox="0 0 24 24"><polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/></symbol>
 <symbol id="i-pause" viewBox="0 0 24 24"><rect x="6" y="4" width="4" height="16"/><rect x="14" y="4" width="4" height="16"/></symbol>
 <symbol id="i-play" viewBox="0 0 24 24"><polygon points="5 3 19 12 5 21 5 3"/></symbol>
 <symbol id="i-download" viewBox="0 0 24 24"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></symbol>
 <symbol id="i-search" viewBox="0 0 24 24"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></symbol>
 <symbol id="i-shield" viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></symbol>
 <symbol id="i-alert" viewBox="0 0 24 24"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></symbol>
 <symbol id="i-link" viewBox="0 0 24 24"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></symbol>
 <symbol id="i-trash" viewBox="0 0 24 24"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></symbol>
 <symbol id="i-key" viewBox="0 0 24 24"><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/></symbol>
</svg>

<!-- HEADER -->
<header class="chrome">
 <div class="wordmark">IRONMESH</div>
 <span class="version-pill">{{IRONMESH_VERSION}} · PRE-1.0</span>
 <div class="node-fp" id="node-fp" title="click to copy full fingerprint">— · —</div>
 <div class="mesh-state" id="mesh-state" data-state="ISOLATED">
  <span class="dot"></span>
  <span id="mesh-state-label">INITIALIZING</span>
 </div>
 <div class="uptime" id="uptime">uptime 0s</div>
 <div class="offline-badge" title="Content-Security-Policy locks this page to same-origin. No Google Fonts, no CDNs, no analytics. Yank your router — this keeps working.">OFFLINE-FIRST</div>
 <div class="token-box" title="Bearer token for this dashboard session (printed at startup)">
  <span>TOKEN</span>
  <input type="password" id="token-input" readonly autocomplete="off" spellcheck="false" value="">
  <button class="icon-btn" id="token-reveal" title="reveal / hide token"><svg class="icon"><use href="#i-eye"/></svg></button>
  <button class="icon-btn" id="token-copy" title="copy dashboard URL"><svg class="icon"><use href="#i-link"/></svg></button>
  <button class="icon-btn" id="token-rotate" title="rotate session token"><svg class="icon"><use href="#i-refresh"/></svg></button>
 </div>
</header>

<!-- STAT STRIP -->
<section class="stat-strip">
 <div class="stat"><div class="label">Active Peers</div><div class="value signal" id="s-peers">0</div><div class="sub" id="s-peers-sub">0 total · 0 routes</div><svg class="spark" id="sp-peers" viewBox="0 0 64 20" preserveAspectRatio="none"></svg></div>
 <div class="stat"><div class="label">Messages · 15m</div><div class="value" id="s-msgs">0 / 0</div><div class="sub">in / out</div><svg class="spark" id="sp-msgs" viewBox="0 0 64 20" preserveAspectRatio="none"></svg></div>
 <div class="stat"><div class="label">Handshakes</div><div class="value signal" id="s-hs">0 / 0</div><div class="sub">✓ success · ✗ fail</div><svg class="spark" id="sp-hs" viewBox="0 0 64 20" preserveAspectRatio="none"></svg></div>
 <div class="stat"><div class="label">Queue Depth</div><div class="value" id="s-q">0</div><div class="sub" id="s-q-sub">pending · evicted 0</div><svg class="spark" id="sp-q" viewBox="0 0 64 20" preserveAspectRatio="none"></svg></div>
 <div class="stat"><div class="label">Bytes · Encrypted</div><div class="value" id="s-bytes">0B</div><div class="sub">↓ in  ·  ↑ out</div><svg class="spark" id="sp-bytes" viewBox="0 0 64 20" preserveAspectRatio="none"></svg></div>
 <div class="stat"><div class="label">Auth-Fail Blocks</div><div class="value" id="s-auth">0</div><div class="sub" id="s-auth-sub">IP-level · rate-limited 0</div><svg class="spark" id="sp-auth" viewBox="0 0 64 20" preserveAspectRatio="none"></svg></div>
</section>

<!-- MAIN GRID -->
<main>
 <section class="panel">
  <div class="panel-hdr">
   <span class="title">PEERS</span>
   <span class="count" id="peer-count">0</span>
   <span class="tools"><input type="text" class="filter" id="peer-filter" placeholder="filter peers…"></span>
  </div>
  <div class="peer-wrap">
   <table class="peers">
    <thead><tr>
     <th>Name</th><th>Fingerprint</th><th>Transport</th><th>Latency</th><th>Trust</th><th>Last</th><th>Capabilities</th>
    </tr></thead>
    <tbody id="peer-body"><tr><td colspan="7" class="empty">no peers yet · mDNS default-deny · --allowed-peers to gate</td></tr></tbody>
   </table>
  </div>

  <div class="panel-hdr" style="border-top:1px solid var(--border)">
   <span class="title">HANDSHAKE</span>
   <span class="count" id="hs-peer-label">no peer selected</span>
  </div>
  <pre class="hs-box" id="hs-diagram">Client                                    Server
  |                                        |
<span class="hs-stage" data-stage="1">  |&lt;── PASSPHRASE_CHALLENGE ──────────────|</span> (32-byte server nonce)
<span class="hs-stage" data-stage="1">  |─── HMAC-SHA256(pass, nonce) ─────────&gt;|</span>
<span class="hs-stage" data-stage="1">  |&lt;── PASSPHRASE_VERIFIED + server_proof─|</span> (mutual auth)
  |                                        |
<span class="hs-stage" data-stage="2">  |─── HELLO (eph_pub_A, id_pub_A) ──────&gt;|</span> signed Ed25519 + channel_binding
<span class="hs-stage" data-stage="2">  |&lt;── HELLO (eph_pub_B, id_pub_B) ───────|</span> signed Ed25519 + channel_binding
<span class="hs-stage" data-stage="2">  |    TOFU check on id_pub_B              |</span> TOFU check on id_pub_A
  |                                        |
<span class="hs-stage" data-stage="3">  | ECDH(eph_priv_A, eph_pub_B)            |</span> ECDH(eph_priv_B, eph_pub_A)
<span class="hs-stage" data-stage="3">  |    = shared_secret                     |</span>    = shared_secret
<span class="hs-stage" data-stage="3">  |  (ephemeral privkeys destroyed)        |</span> (ephemeral privkeys destroyed)
  |                                        |
<span class="hs-stage" data-stage="4">  |&lt;═══ Encrypted + Signed Messages ═════&gt;|</span> XSalsa20-Poly1305 + Ed25519
</pre>

  <div class="transport-panel">
   <div class="tp-cell" id="tp-ws">
    <div class="tp-title">WebSocket · LAN</div>
    <div class="tp-row"><span class="k">peers</span><span class="v" id="tp-ws-peers">0</span></div>
    <div class="tp-row"><span class="k">throughput</span><span class="v" id="tp-ws-tput">0 B/s</span></div>
    <div class="tp-row"><span class="k">latency p50</span><span class="v" id="tp-ws-lat">—</span></div>
   </div>
   <div class="tp-cell" id="tp-rns">
    <div class="tp-title">Reticulum · LoRa</div>
    <div class="tp-row"><span class="k">status</span><span class="v" id="tp-rns-status">install ironmesh[rns] to enable</span></div>
    <div class="tp-row"><span class="k">dest hash</span><span class="v" id="tp-rns-dest">—</span></div>
    <div class="tp-row"><span class="k">profile</span><span class="v" id="tp-rns-prof">—</span></div>
   </div>
  </div>

  <!-- v0.8.5: pending-trust message gate -->
  <div class="panel-hdr" style="border-top:1px solid var(--border)">
   <span class="title">PENDING TRUST</span>
   <span class="count" id="pending-trust-count">0</span>
   <span class="tools">
    <span id="pending-trust-status" style="font-size:10px;color:var(--text-dim);text-transform:uppercase;letter-spacing:.06em">gate off</span>
   </span>
  </div>
  <div class="pending-trust-wrap" id="pending-trust-wrap" style="padding:6px 10px 12px">
   <div class="empty" id="pending-trust-empty" style="font-size:11px;color:var(--text-dim);padding:6px 0">no peers awaiting promotion</div>
   <table class="peers" id="pending-trust-table" style="display:none">
    <thead><tr>
     <th>Node</th><th>Fingerprint</th><th>Queued</th><th>First seen</th><th>Action</th>
    </tr></thead>
    <tbody id="pending-trust-body"></tbody>
   </table>
  </div>

  <!-- v0.8.5.7: pending capability-set change (cap-binding operator surface) -->
  <div class="panel-hdr" style="border-top:1px solid var(--border)">
   <span class="title">PENDING CAP CHANGE</span>
   <span class="count" id="pending-cap-count">0</span>
   <span class="tools">
    <span id="pending-cap-hint" style="font-size:10px;color:var(--text-dim);text-transform:uppercase;letter-spacing:.06em">capability-set binding</span>
   </span>
  </div>
  <div class="pending-cap-wrap" id="pending-cap-wrap" style="padding:6px 10px 12px">
   <div class="empty" id="pending-cap-empty" style="font-size:11px;color:var(--text-dim);padding:6px 0">no peers awaiting cap review</div>
   <table class="peers" id="pending-cap-table" style="display:none">
    <thead><tr>
     <th>Node</th><th>Added</th><th>Removed</th><th>Action</th>
    </tr></thead>
    <tbody id="pending-cap-body"></tbody>
   </table>
  </div>
 </section>

 <section class="panel">
  <div class="panel-hdr">
   <span class="title">MESSAGE FEED</span>
   <span class="count" id="feed-count">0</span>
   <span class="tools">
    <button class="icon-btn" id="feed-pause" title="pause tail"><svg class="icon"><use href="#i-pause"/></svg></button>
    <button class="icon-btn" id="feed-export" title="export CSV"><svg class="icon"><use href="#i-download"/></svg></button>
    <button class="icon-btn" id="feed-clear" title="clear feed"><svg class="icon"><use href="#i-trash"/></svg></button>
   </span>
  </div>
  <div class="feed-tools">
   <svg class="icon" style="color:var(--text-dim);flex:0 0 auto"><use href="#i-search"/></svg>
   <input type="text" id="feed-search" placeholder="filter (substring or /regex/i)…" autocomplete="off">
   <label><input type="checkbox" id="feed-show-chatter"> chatter</label>
  </div>
  <div class="feed-body" id="feed"><div class="empty">waiting for encrypted traffic…</div></div>

  <div class="send-wrap">
   <div class="send-row">
    <select id="send-peer"><option value="">— select peer —</option></select>
    <input type="text" id="send-type" value="MSG" maxlength="16" style="max-width:80px;flex:0 0 auto" title="message type">
    <select id="send-prio" style="max-width:110px;flex:0 0 auto" title="priority">
     <option value="normal">normal</option><option value="high">high</option><option value="low">low</option>
    </select>
   </div>
   <div class="send-row">
    <textarea id="send-payload" rows="2" placeholder="signed + encrypted before leaving this host…"></textarea>
    <button class="btn-signal" id="send-btn" style="flex:0 0 auto">SEND</button>
   </div>
   <div class="send-row" style="border-top:1px dashed var(--border);padding-top:8px">
    <select id="dlg-a"><option value="">— AI peer A —</option></select>
    <select id="dlg-b"><option value="">— AI peer B —</option></select>
    <input type="number" id="dlg-turns" value="4" min="1" max="20" title="max turns">
    <input type="text" id="dlg-seed" placeholder="seed prompt…">
    <button class="btn-signal" id="dlg-btn" style="flex:0 0 auto">A2A</button>
   </div>
  </div>
 </section>
</main>

<!-- FOOTER OPS -->
<footer class="ops">
 <span class="ops-label">OPS</span>
 <button id="op-audit" title="view tamper-evident audit log"><svg class="icon" style="width:12px;height:12px"><use href="#i-shield"/></svg>AUDIT LOG</button>
 <button id="op-rotate-keys" title="rotate identity keypair"><svg class="icon" style="width:12px;height:12px"><use href="#i-key"/></svg>ROTATE KEYS</button>
 <button id="op-rekey" title="force session rekey"><svg class="icon" style="width:12px;height:12px"><use href="#i-refresh"/></svg>SESSION REKEY</button>
 <button id="op-panic" class="btn-alarm" title="wipe ephemeral keys, disconnect all peers"><svg class="icon" style="width:12px;height:12px"><use href="#i-alert"/></svg>PANIC WIPE</button>
 <span class="spacer"></span>
 <span class="legal">XSalsa20-Poly1305 · X25519 · Ed25519 · Argon2id · TOFU · MIT · No cloud · No internet required</span>
</footer>

<div class="statusline" id="statusline">—</div>

<script>
(function(){
 const $ = id => document.getElementById(id);
 const token = new URLSearchParams(location.search).get('token') || '';
 const WS_URL = 'ws://' + location.host + '/ws' + (token ? '?token=' + token : '');

 let ws = null;
 let state = { peers:[], metrics:{}, capabilities:{}, history:[] };
 let selectedPeer = null;
 let feedPaused = false;
 let showChatter = false;
 let feedBuf = [];
 const FEED_CAP = 1500;
 const sparkBuf = { peers:[], msgs:[], hs:[], q:[], bytes:[], auth:[] };
 const SPARK_N = 48;
 let _seeded = false;

 const fmtBytes = b => b<1024?b+'B':b<1048576?(b/1024).toFixed(1)+'KB':b<1073741824?(b/1048576).toFixed(1)+'MB':(b/1073741824).toFixed(2)+'GB';
 const fmtUp    = s => { const h=Math.floor(s/3600), m=Math.floor((s%3600)/60), x=Math.floor(s%60); return (h?h+'h ':'')+(m?m+'m ':'')+x+'s'; };
 const fmtRel   = t => { const d=Date.now()/1000 - t; if(d<0)return 'now'; if(d<60)return Math.floor(d)+'s'; if(d<3600)return Math.floor(d/60)+'m'; return Math.floor(d/3600)+'h'; };
 const escHtml  = s => String(s==null?'':s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
 const shortFp  = fp => fp && fp.length>=12 ? fp.slice(0,4)+'…'+fp.slice(-4) : (fp||'—');

 function statusline(msg, kind){
  const el = $('statusline');
  el.textContent = msg;
  el.className = 'statusline show' + (kind?' '+kind:'');
  clearTimeout(el._t);
  el._t = setTimeout(() => el.classList.remove('show'), 2600);
 }
 async function copy(text){
  try{
   if(navigator.clipboard && window.isSecureContext) await navigator.clipboard.writeText(text);
   else { const ta=document.createElement('textarea'); ta.value=text; ta.style.position='fixed'; ta.style.opacity='0'; document.body.appendChild(ta); ta.select(); document.execCommand('copy'); document.body.removeChild(ta); }
   statusline('copied · '+(text.length>40?text.slice(0,40)+'…':text));
  }catch(e){ statusline('copy failed', 'alarm'); }
 }

 // Token box
 $('token-input').value = token || '(none — check startup log)';
 $('token-reveal').addEventListener('click', () => {
  const inp = $('token-input');
  const isPwd = inp.type === 'password';
  inp.type = isPwd ? 'text' : 'password';
  $('token-reveal').innerHTML = isPwd ? '<svg class="icon"><use href="#i-eye-off"/></svg>' : '<svg class="icon"><use href="#i-eye"/></svg>';
 });
 $('token-copy').addEventListener('click', () => copy(location.href));
 $('token-rotate').addEventListener('click', () => {
  if(!confirm('Rotate the dashboard session token? This invalidates the current URL.')) return;
  if(ws && ws.readyState === 1) ws.send(JSON.stringify({action:'rotate_gui_token'}));
  statusline('token rotation requested · backend wiring pending', 'warn');
 });
 $('node-fp').addEventListener('click', () => { if(state.node_id) copy(state.node_id); });

 // WS
 function connect(){
  ws = new WebSocket(WS_URL);
  ws.onopen    = () => {
   setMeshState('ISOLATED','control channel open');
   statusline('control channel open · ephemeral ECDH complete');
   // v0.8.5: pull initial pending-trust state for the panel.
   try{ ws.send(JSON.stringify({action:'list_pending_trust'})); }catch(e){}
   // v0.8.5.7: pull initial pending-cap-change state.
   try{ ws.send(JSON.stringify({action:'list_pending_cap'})); }catch(e){}
  };
  ws.onclose   = () => { setMeshState('ISOLATED','CONTROL CHANNEL CLOSED'); statusline('control channel closed · reconnecting…', 'warn'); setTimeout(connect, 2000); };
  ws.onerror   = () => { try{ ws.close(); }catch(e){} };
  ws.onmessage = e => { try{ handle(JSON.parse(e.data)); }catch(x){ console.error(x); } };
 }

 function handle(msg){
  if(msg.type === 'snapshot' || msg.type === 'state_update'){
   state = Object.assign(state, msg.data || msg);
   updateUI();
  } else if(msg.type === 'message_event'){
   pushFeed(toFeedRow(msg));
  } else if(msg.type === 'peer_event'){
   const ok = msg.event === 'connected';
   pushFeed({ t:Date.now()/1000, dir:'sys', sev:ok?'ok':'warn', type:ok?'CONNECT':'DISCONNECT', peer:msg.peer_id||'', payload:msg.reason||'' });
  } else if(msg.type === 'send_ack'){
   pushFeed({ t:Date.now()/1000, dir:'out', sev:'ok', type:'ACK', peer:'self', payload:'sent · '+msg.msg_id });
  } else if(msg.type === 'send_error'){
   pushFeed({ t:Date.now()/1000, dir:'sys', sev:'alarm', type:'ERROR', peer:'self', payload:msg.error||'' });
  } else if(msg.type === 'dialogue_event'){
   pushFeed(toDialogueRow(msg));
  } else if(msg.type === 'auth_failure'){
   pushFeed({ t:Date.now()/1000, dir:'sys', sev:'alarm', type:'AUTHFAIL', peer:msg.ip||'', payload:msg.reason||'' });
  } else if(msg.type === 'pending_trust_list'){
   renderPendingTrust(msg.pending || [], !!msg.gate_enabled);
  } else if(msg.type === 'pending_trust'){
   // Incremental: a new MSG just got queued for a pending peer. Refresh the panel.
   pushFeed({ t:Date.now()/1000, dir:'sys', sev:'warn', type:'PENDING',
              peer:(msg.source_node_id||'').slice(0,12), payload:'queued · count='+msg.queued_count });
   if(ws && ws.readyState === 1) ws.send(JSON.stringify({action:'list_pending_trust'}));
  } else if(msg.type === 'promote_ack'){
   statusline('promoted '+(msg.target||'').slice(0,12)+' · drained '+msg.drained, msg.ok?'ok':'alarm');
   if(ws && ws.readyState === 1) ws.send(JSON.stringify({action:'list_pending_trust'}));
  } else if(msg.type === 'block_ack'){
   statusline('blocked '+(msg.target||'').slice(0,12)+' · discarded '+msg.discarded, msg.ok?'warn':'alarm');
   if(ws && ws.readyState === 1) ws.send(JSON.stringify({action:'list_pending_trust'}));
  } else if(msg.type === 'pending_cap_list'){
   // v0.8.5.7: initial or refreshed list of peers in pending-cap-change
   renderPendingCap(msg.pending || []);
  } else if(msg.type === 'cap_change_detected'){
   // v0.8.5.7: a peer's cap-set just changed. Surface on feed + refresh panel.
   pushFeed({ t:Date.now()/1000, dir:'sys', sev:'warn', type:'CAPCHG',
              peer:(msg.peer||'').slice(0,12),
              payload:'+'+(msg.added||[]).length+' -'+(msg.removed||[]).length+' caps · review in panel' });
   if(ws && ws.readyState === 1) ws.send(JSON.stringify({action:'list_pending_cap'}));
  } else if(msg.type === 'cap_promote_ack'){
   statusline('cap-accepted '+(msg.node_id||'').slice(0,12)+' · new baseline '+(msg.new_hash||'').slice(0,8), msg.ok?'ok':'alarm');
   if(ws && ws.readyState === 1) ws.send(JSON.stringify({action:'list_pending_cap'}));
  }
 }

 function renderPendingTrust(rows, gateEnabled){
  $('pending-trust-status').textContent = gateEnabled ? 'gate on' : 'gate off';
  $('pending-trust-status').style.color = gateEnabled ? 'var(--ok, #4ade80)' : 'var(--text-dim)';
  $('pending-trust-count').textContent = rows.length;
  const empty = $('pending-trust-empty');
  const table = $('pending-trust-table');
  if(!rows.length){
   empty.style.display = '';
   empty.textContent = gateEnabled ? 'no peers awaiting promotion' : 'gate disabled — start daemon with --require-message-promotion to gate new peers';
   table.style.display = 'none';
   return;
  }
  empty.style.display = 'none';
  table.style.display = '';
  $('pending-trust-body').innerHTML = rows.map(r => {
   const nid = r.node_id || '';
   const fp = r.fingerprint || '';
   const queued = r.queued_count != null ? r.queued_count : 0;
   const first = r.first_seen ? fmtRel(r.first_seen) + ' ago' : '—';
   return '<tr>'
    + '<td><code title="'+escHtml(nid)+'">'+escHtml(nid.slice(0,12))+'…</code></td>'
    + '<td>'+escHtml(shortFp(fp))+'</td>'
    + '<td style="text-align:right">'+queued+'</td>'
    + '<td>'+escHtml(first)+'</td>'
    + '<td>'
    +  '<button class="btn-signal pending-promote" data-node="'+escHtml(nid)+'" style="padding:2px 8px;font-size:10px">PROMOTE</button> '
    +  '<button class="btn-alarm pending-block" data-node="'+escHtml(nid)+'" style="padding:2px 8px;font-size:10px">BLOCK</button>'
    + '</td>'
    + '</tr>';
  }).join('');
  // Wire button handlers (delegated rebind on each render).
  document.querySelectorAll('#pending-trust-body .pending-promote').forEach(b => {
   b.addEventListener('click', () => {
    const node = b.getAttribute('data-node');
    if(ws && ws.readyState === 1) ws.send(JSON.stringify({action:'promote_peer', target_node_id:node}));
   });
  });
  document.querySelectorAll('#pending-trust-body .pending-block').forEach(b => {
   b.addEventListener('click', () => {
    const node = b.getAttribute('data-node');
    if(!confirm('Block peer '+node.slice(0,12)+'…? This drops queued messages and silences future MSGs from this peer.')) return;
    if(ws && ws.readyState === 1) ws.send(JSON.stringify({action:'block_peer', target_node_id:node}));
   });
  });
 }

 // v0.8.5.7: render the pending capability-set change panel. Parallels
 // renderPendingTrust for the cap-binding feature. A row per peer whose
 // currently-announced cap set differs from the accepted baseline;
 // shows the diff (added/removed tokens) so the operator can decide.
 function renderPendingCap(rows){
  rows = rows || [];
  $('pending-cap-count').textContent = rows.length;
  const empty = $('pending-cap-empty');
  const table = $('pending-cap-table');
  if(!rows.length){
   empty.style.display = '';
   empty.textContent = 'no peers awaiting cap review';
   table.style.display = 'none';
   return;
  }
  empty.style.display = 'none';
  table.style.display = '';
  $('pending-cap-body').innerHTML = rows.map(r => {
   const nid = r.node_id || '';
   const added = (r.added || []).map(escHtml).join(', ') || '—';
   const removed = (r.removed || []).map(escHtml).join(', ') || '—';
   const addedTitle = 'Baseline hash: ' + (r.baseline_hash||'').slice(0,16) +
                      '…\nPending hash:  ' + (r.pending_hash||'').slice(0,16) + '…';
   return '<tr>'
    + '<td><code title="'+escHtml(nid)+'">'+escHtml(nid.slice(0,12))+'…</code></td>'
    + '<td style="color:var(--ok,#4ade80);max-width:180px;overflow:hidden;text-overflow:ellipsis" title="'+escHtml(addedTitle)+'">+ '+added+'</td>'
    + '<td style="color:var(--warn,#f87171);max-width:180px;overflow:hidden;text-overflow:ellipsis">− '+removed+'</td>'
    + '<td>'
    +  '<button class="btn-signal cap-promote" data-node="'+escHtml(nid)+'" style="padding:2px 8px;font-size:10px" title="Accept the new capability set as the baseline and restore trust.">ACCEPT</button>'
    + '</td>'
    + '</tr>';
  }).join('');
  document.querySelectorAll('#pending-cap-body .cap-promote').forEach(b => {
   b.addEventListener('click', () => {
    const node = b.getAttribute('data-node');
    if(!confirm('Accept the new capability set for '+node.slice(0,12)+'…?\n\nThis pins the peer\'s currently-advertised capability set as the new baseline and restores the trusted state. Inbound messages that were queueing at the daemon will drain.')) return;
    if(ws && ws.readyState === 1) ws.send(JSON.stringify({action:'cap_promote_peer', target_node_id:node}));
   });
  });
 }

 function toFeedRow(msg){
  const mt = msg.msg_type || '?';
  let payload = msg.payload;
  if(payload instanceof ArrayBuffer || payload instanceof Uint8Array) payload = '[binary]';
  else if(typeof payload === 'object'){ try{ payload = JSON.stringify(payload); }catch(e){ payload = String(payload); } }
  else payload = String(payload==null?'':payload);
  if(payload.charAt(0)==='{' && payload.indexOf('"conv_id"')>0){
   try{ const e=JSON.parse(payload); payload='['+e.kind+' turn '+e.turn+'/'+e.max_turns+'] '+e.body; }catch(x){}
  }
  return { t: msg.timestamp || Date.now()/1000, dir: msg.direction||'in',
   sev: mt==='ERROR'?'alarm':(mt==='MSG'||mt==='CONV'?'ok':'info'),
   type: mt, peer: msg.peer_id||'', payload };
 }
 function toDialogueRow(msg){
  const ev = msg.event || '?';
  let line = '', sev = 'info';
  if(ev==='started')           line = 'start · '+(msg.peer_a||'').slice(0,8)+' ↔ '+(msg.peer_b||'').slice(0,8)+' · max_turns='+msg.max_turns;
  else if(ev==='turn')        { line = 'T'+msg.turn+' '+(msg.speaker||'?')+': '+(msg.body||'').slice(0,400); sev='ok'; }
  else if(ev==='end')           line = '[END] '+(msg.speaker||'?')+': '+(msg.reason||'');
  else if(ev==='error')       { line = '[ERR] '+(msg.speaker||'?')+': '+(msg.reason||''); sev='alarm'; }
  else if(ev==='timeout')     { line = '[TIMEOUT] waiting on '+(msg.waiting_on||'?')+' ('+msg.timeout+'s)'; sev='warn'; }
  else if(ev==='turn_cap_reached') line = '[CAP] '+msg.cap+' turns reached';
  else if(ev==='finished')     line = '[FINISHED]';
  else                         line = '['+ev+'] '+JSON.stringify(msg);
  return { t:Date.now()/1000, dir: ev==='turn'?'in':'sys', sev, type:'A2A', peer: msg.conv_id||'', payload: line };
 }

 const isChatter = r => r.type==='PING' || r.type==='PONG' || r.type==='HEARTBEAT' || r.type==='ROUTE_ANNOUNCE' || r.type==='CAPABILITY_ANNOUNCE';

 function pushFeed(row){
  feedBuf.push(row);
  if(feedBuf.length > FEED_CAP) feedBuf.splice(0, feedBuf.length - FEED_CAP);
  if(!feedPaused) renderFeed(true);
 }

 function renderFeed(appendHint){
  const feed = $('feed');
  const search = $('feed-search').value.trim();
  let matcher = null;
  if(search){
   const rx = /^\/(.+)\/([a-z]*)$/.exec(search);
   try{ matcher = rx ? new RegExp(rx[1], rx[2]) : { test: s => s.toLowerCase().includes(search.toLowerCase()) }; }
   catch(e){ matcher = { test: s => s.includes(search) }; }
  }
  const rows = feedBuf.filter(r => (showChatter || !isChatter(r)) && (!matcher || matcher.test(r.type+' '+r.peer+' '+r.payload)));
  $('feed-count').textContent = rows.length;
  if(!rows.length){
   // Disambiguate empty buffer vs filtered-to-zero — operators kept asking "why nothing?" after clear.
   const msg = feedBuf.length === 0 ? 'waiting for encrypted traffic…' : 'no matching events · adjust filter';
   feed.innerHTML = '<div class="empty">'+msg+'</div>';
   return;
  }
  const atBottom = feed.scrollTop + feed.clientHeight >= feed.scrollHeight - 24;
  const shown = rows.slice(-300);
  feed.innerHTML = shown.map(renderRow).join('');
  if(atBottom && !feedPaused) feed.scrollTop = feed.scrollHeight;
 }
 function renderRow(r){
  const t = new Date(r.t*1000);
  const ts = t.toLocaleTimeString([], { hour12:false });
  const arrow = r.dir==='out' ? '↑' : (r.dir==='sys' ? '·' : '↓');
  const peerLabel = peerName(r.peer);
  // r.sev/r.dir are daemon-set enums, not peer input, but interpolate into
  // class attributes — constrain to [a-z] so an unexpected value can never
  // break out of the attribute (defense-in-depth, matches the esc discipline
  // applied to every remote field below).
  const sev = (r.sev||'').replace(/[^a-z]/g,'');
  const dir = (r.dir||'').replace(/[^a-z]/g,'');
  return '<div class="feed-row sev-'+sev+'">'+
   '<span class="gutter"></span>'+
   '<span class="time">'+ts+'</span>'+
   '<span class="dir '+dir+'">'+arrow+'</span>'+
   '<span class="type">'+escHtml(r.type)+'</span>'+
   '<span class="peer">'+escHtml(peerLabel)+'</span>'+
   '<span class="payload">'+escHtml((r.payload||'').slice(0,500))+'</span>'+
   '</div>';
 }
 function peerName(id){
  if(!id) return '';
  if(id==='self' || id==='a2a') return id;
  const p = (state.peers||[]).find(p => p.node_id===id);
  return p ? (p.name || id.slice(0,8)) : id.slice(0,8);
 }

 $('feed-pause').addEventListener('click', () => {
  feedPaused = !feedPaused;
  $('feed-pause').innerHTML = feedPaused ? '<svg class="icon"><use href="#i-play"/></svg>' : '<svg class="icon"><use href="#i-pause"/></svg>';
  $('feed-pause').title = feedPaused ? 'resume tail' : 'pause tail';
  if(!feedPaused) renderFeed();
  statusline(feedPaused ? 'tail paused' : 'tail resumed');
 });
 $('feed-export').addEventListener('click', () => {
  const header = 'timestamp_iso,direction,severity,type,peer,payload';
  const lines = [header];
  feedBuf.forEach(r => {
   const esc = (r.payload||'').replace(/"/g,'""').replace(/\r?\n/g,' ');
   lines.push([new Date(r.t*1000).toISOString(), r.dir, r.sev, r.type, r.peer, '"'+esc+'"'].join(','));
  });
  const blob = new Blob([lines.join('\n')], { type:'text/csv' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a'); a.href=url; a.download='ironmesh-feed-'+Date.now()+'.csv'; a.click();
  setTimeout(()=>URL.revokeObjectURL(url), 1000);
  statusline('feed exported');
 });
 $('feed-clear').addEventListener('click', () => { feedBuf = []; renderFeed(); statusline('feed cleared'); });
 $('feed-search').addEventListener('input', renderFeed);
 $('feed-show-chatter').addEventListener('change', e => { showChatter = e.target.checked; renderFeed(); });
 $('peer-filter').addEventListener('input', () => renderPeers(state.peers||[]));

 // Mesh state
 function setMeshState(s, label){
  const el = $('mesh-state');
  el.dataset.state = s;
  $('mesh-state-label').textContent = label || s;
 }

 function updateUI(){
  const m = state.metrics || {};
  const peers = state.peers || [];
  const online = peers.filter(p => p.status === 'online').length;

  if(state.node_id) $('node-fp').textContent = shortFp(state.node_id) + ' · ' + (state.name || '—');
  $('uptime').textContent = 'uptime ' + fmtUp(m.uptime_seconds || 0);

  if(online === 0) setMeshState('ISOLATED', 'ISOLATED · 0 PEERS');
  else if(peers.some(p => p.status==='handshaking' || !p.verified)) setMeshState('DEGRADED', 'DEGRADED · '+online+'/'+peers.length);
  else setMeshState('OPERATIONAL', online+' PEER'+(online===1?'':'S')+' ONLINE');

  $('s-peers').textContent = m.active_peers != null ? m.active_peers : online;
  $('s-peers-sub').textContent = (m.total_peers||peers.length)+' total · '+(m.routes_known||0)+' routes';
  $('s-msgs').textContent  = (m.messages_received||0) + ' / ' + (m.messages_sent||0);
  const hsF = m.handshake_failures||0;
  $('s-hs').textContent    = (m.handshake_successes||0) + ' / ' + hsF;
  $('s-hs').className = 'value ' + (hsF > 0 ? 'warn' : 'signal');
  const qDepth = peers.reduce((a,p)=>a+(p.pending_queue_size||0), 0);
  $('s-q').textContent     = qDepth;
  $('s-q-sub').textContent = 'pending · evicted '+(m.pending_evicted||0);
  $('s-bytes').textContent = fmtBytes((m.bytes_sent||0)+(m.bytes_received||0));
  const authBlocks = m.auth_fail_blocks || 0;
  $('s-auth').textContent  = authBlocks;
  $('s-auth').className    = 'value ' + (authBlocks > 0 ? 'alarm' : '');
  $('s-auth-sub').textContent = 'IP-level · rate-limited '+(m.rate_limits_triggered||0);

  pushSpark('peers', online);
  pushSpark('msgs',  (m.messages_received||0) + (m.messages_sent||0));
  pushSpark('hs',    m.handshake_successes || 0);
  pushSpark('q',     qDepth);
  pushSpark('bytes', (m.bytes_sent||0)+(m.bytes_received||0));
  pushSpark('auth',  authBlocks);

  renderPeers(peers);
  renderTransports(peers, m);
  seedFeedFromHistory();
 }

 function renderPeers(peers){
  const filter = ($('peer-filter').value || '').toLowerCase();
  const shown = peers.filter(p => !filter || (p.name||'').toLowerCase().includes(filter) || (p.node_id||'').toLowerCase().includes(filter));
  $('peer-count').textContent = shown.length;
  const body = $('peer-body');
  if(!shown.length){
   body.innerHTML = '<tr><td colspan="7" class="empty">'+(filter?'no peers match filter':'no peers yet · mDNS default-deny · --allowed-peers to gate')+'</td></tr>';
   populateSends(peers);
   renderHandshake(null);
   return;
  }
  body.innerHTML = shown.map(p => {
   const trust = trustState(p);
   const transport = transportBadge(p);
   const latency = p.latency_ms != null ? p.latency_ms.toFixed(0)+'ms' : '—';
   const last = p.last_seen ? fmtRel(p.last_seen) : '—';
   const caps = capabilitiesFor(p.node_id).slice(0,3).map(c => '<span class="cap-pill">'+escHtml(c)+'</span>').join('');
   const sel = p.node_id === selectedPeer ? ' selected' : '';
   const mm  = trust.kind === 'mismatch' ? ' mismatch' : '';
   return '<tr class="peer-row'+sel+mm+'" data-id="'+escHtml(p.node_id)+'">'+
    '<td class="peer-name">'+escHtml(p.name||'—')+'</td>'+
    '<td>'+shortFp(p.node_id)+'</td>'+
    '<td>'+transport+'</td>'+
    '<td>'+latency+'</td>'+
    '<td><span class="trust-state '+trust.cls+'">'+trust.label+'</span></td>'+
    '<td title="'+new Date((p.last_seen||0)*1000).toISOString()+'">'+last+'</td>'+
    '<td>'+(caps||'<span style="color:var(--text-faint)">—</span>')+'</td>'+
    '</tr>';
  }).join('');
  body.querySelectorAll('tr.peer-row').forEach(tr => {
   tr.addEventListener('click', () => {
    selectedPeer = tr.dataset.id;
    body.querySelectorAll('tr.peer-row').forEach(x => x.classList.toggle('selected', x.dataset.id===selectedPeer));
    renderHandshake(peers.find(p => p.node_id===selectedPeer));
   });
  });
  populateSends(peers);
  if(selectedPeer){
   const peer = peers.find(p => p.node_id===selectedPeer);
   if(peer) renderHandshake(peer); else renderHandshake(null);
  } else renderHandshake(null);
 }

 function trustState(p){
  if(p.trust_state === 'mismatch' || p.mismatch === true) return { kind:'mismatch', cls:'trust-mismatch', label:'✗ MISMATCH' };
  if(p.status === 'handshaking')                          return { kind:'pending',  cls:'trust-pending',  label:'… HANDSHAKING' };
  if(!p.verified)                                          return { kind:'pending',  cls:'trust-pending',  label:'… UNVERIFIED' };
  // v0.8.5.2: when the daemon ran with --require-message-promotion the trust
  // store carries a tri-state (pending/trusted/blocked). Surface that here so
  // operators see gate state in the main peers table, not only in PENDING TRUST.
  if(p.trust_gate_state === 'blocked')                    return { kind:'blocked',  cls:'trust-mismatch', label:'⛔ BLOCKED' };
  if(p.trust_gate_state === 'pending')                    return { kind:'pending',  cls:'trust-pending',  label:'… PENDING-PROMOTE' };
  // v0.8.3 backend pins on first sight (trust.py TOFU); fresh vs returning requires a new field.
  return { kind:'tofu', cls:'trust-verified', label:'✓ TOFU-PINNED' };
 }
 function transportBadge(p){
  const hasWs  = p.ws_address || (p.transport_type||'websocket') === 'websocket';
  const hasRns = p.rns_dest_hash || p.transport_type === 'reticulum' || p.transport_type === 'both';
  if(hasWs && hasRns) return '<span class="transport-badge transport-both">WS+RNS</span>';
  if(hasRns)          return '<span class="transport-badge transport-rns">RNS</span>';
  return '<span class="transport-badge transport-ws">WS</span>';
 }
 function capabilitiesFor(nodeId){
  const out = [];
  const caps = state.capabilities || {};
  Object.keys(caps).forEach(c => { if((caps[c]||[]).indexOf(nodeId) !== -1) out.push(c); });
  return out;
 }

 function renderHandshake(peer){
  const stages = document.querySelectorAll('#hs-diagram .hs-stage');
  stages.forEach(s => s.classList.remove('ok','active','fail'));
  if(!peer){ $('hs-peer-label').textContent = 'no peer selected'; return; }
  $('hs-peer-label').textContent = (peer.name||'—') + ' · ' + shortFp(peer.node_id);
  let maxOk = 0;
  if(peer.trust_state === 'mismatch' || peer.mismatch){ stages.forEach(s => { if(+s.dataset.stage<=2) s.classList.add('ok'); else s.classList.add('fail'); }); return; }
  if(peer.status === 'offline'){ stages.forEach(s => s.classList.add('fail')); return; }
  if(peer.status === 'online' && peer.verified) maxOk = 4;
  else if(peer.status === 'online')              maxOk = 3;
  else if(peer.status === 'handshaking')         maxOk = 1;
  stages.forEach(s => {
   const st = +s.dataset.stage;
   if(st <= maxOk) s.classList.add('ok');
   else if(st === maxOk+1) s.classList.add('active');
  });
 }

 function renderTransports(peers, m){
  const wsPeers = peers.filter(p => (p.transport_type||'websocket') !== 'reticulum');
  const rnsPeers = peers.filter(p => p.rns_dest_hash);
  $('tp-ws-peers').textContent = wsPeers.length;
  const totalBytes = (m.bytes_sent||0) + (m.bytes_received||0);
  const up = Math.max(1, m.uptime_seconds||1);
  $('tp-ws-tput').textContent = fmtBytes(totalBytes / up) + '/s';
  const lats = wsPeers.map(p => p.latency_ms).filter(x => x != null).sort((a,b)=>a-b);
  $('tp-ws-lat').textContent = lats.length ? lats[Math.floor(lats.length/2)].toFixed(0)+'ms' : '—';
  const tpRns = $('tp-rns');
  if(rnsPeers.length){
   tpRns.classList.remove('disabled');
   $('tp-rns-status').textContent = rnsPeers.length+' destination'+(rnsPeers.length===1?'':'s');
   $('tp-rns-dest').textContent   = rnsPeers[0].rns_dest_hash ? rnsPeers[0].rns_dest_hash.slice(0,10)+'…' : '—';
   $('tp-rns-prof').textContent   = 'SF8 · BW125 · ~1.1s @ 16B';
  } else {
   tpRns.classList.add('disabled');
   $('tp-rns-status').textContent = 'install ironmesh[rns] to enable';
   $('tp-rns-dest').textContent   = '—';
   $('tp-rns-prof').textContent   = '—';
  }
 }

 function populateSends(peers){
  const peerSel = $('send-peer'), a = $('dlg-a'), b = $('dlg-b');
  const prev = { p: peerSel.value, a: a.value, b: b.value };
  const opts = p => '<option value="'+escHtml(p.node_id)+'">'+escHtml(p.name||p.node_id.slice(0,8))+' · '+p.status+'</option>';
  peerSel.innerHTML = '<option value="">— select peer —</option>' + peers.map(opts).join('');
  const llm = new Set();
  Object.keys(state.capabilities||{}).forEach(c => { if(c.indexOf('llm:')===0) (state.capabilities[c]||[]).forEach(n => llm.add(n)); });
  const llmPeers = peers.filter(p => llm.has(p.node_id));
  // CAPABILITY_ANNOUNCE is periodic (~30s) and may not have arrived yet when the
  // first peer snapshot lands. Fall back to every peer so the A2A form is usable
  // immediately; the placeholder signals that the llm:* filter is inactive.
  const a2aPeers = llmPeers.length ? llmPeers : peers;
  const a2aHint  = llmPeers.length ? '' : ' · no llm:* advertised';
  a.innerHTML = '<option value="">— AI peer A'+a2aHint+' —</option>' + a2aPeers.map(opts).join('');
  b.innerHTML = '<option value="">— AI peer B'+a2aHint+' —</option>' + a2aPeers.map(opts).join('');
  if(prev.p) peerSel.value = prev.p;
  if(prev.a) a.value = prev.a;
  if(prev.b) b.value = prev.b;
 }

 $('send-btn').addEventListener('click', sendMessage);
 // Enter sends; Shift+Enter inserts a newline (standard chat-input convention).
 $('send-payload').addEventListener('keydown', e => {
  if(e.key === 'Enter' && !e.shiftKey){ e.preventDefault(); sendMessage(); }
 });
 function sendMessage(){
  const peer = $('send-peer').value, typ = ($('send-type').value.trim()||'MSG'), payload = $('send-payload').value;
  if(!peer)    { statusline('pick a peer first', 'warn'); return; }
  if(!payload) { statusline('empty payload', 'warn'); return; }
  try{
   ws.send(JSON.stringify({ action:'send_message', to_node:peer, msg_type:typ, payload, priority:$('send-prio').value }));
   pushFeed({ t:Date.now()/1000, dir:'out', sev:'ok', type:typ, peer, payload });
   $('send-payload').value = '';
  } catch(err){
   statusline('send failed · ws closed', 'alarm');
   pushFeed({ t:Date.now()/1000, dir:'sys', sev:'alarm', type:'ERROR', peer:'self', payload:'ws.send: '+(err && err.message || err) });
  }
 }

 $('dlg-btn').addEventListener('click', () => {
  const a = $('dlg-a').value, b = $('dlg-b').value, seed = $('dlg-seed').value, turns = parseInt($('dlg-turns').value||'4', 10);
  if(!a || !b || !seed){ statusline('pick two AI peers and a seed prompt', 'warn'); return; }
  if(a === b){ statusline('A and B must differ', 'warn'); return; }
  ws.send(JSON.stringify({ action:'start_dialogue', peer_a:a, peer_b:b, seed, max_turns:turns }));
  $('dlg-seed').value = '';
  statusline('A2A dialogue dispatched · '+turns+' turns');
 });

 // Footer ops
 $('op-audit').addEventListener('click', () => statusline('audit is HMAC-chained at ~/.ironmesh/audit.log · GUI viewer queued for v0.9'));
 $('op-rotate-keys').addEventListener('click', () => {
  if(!confirm('Rotate identity keypair? Every pinned peer must re-TOFU on next session.')) return;
  statusline('identity rotation requires offline CLI: ironmesh keys rotate', 'warn');
 });
 $('op-rekey').addEventListener('click', () => {
  if(ws && ws.readyState === 1) ws.send(JSON.stringify({action:'force_rekey'}));
  statusline('session rekey requested across active peers');
 });
 $('op-panic').addEventListener('click', () => {
  if(!confirm('PANIC WIPE: drop every ephemeral key and disconnect all peers. Continue?')) return;
  if(!confirm('Second confirmation — really wipe?')) return;
  if(ws && ws.readyState === 1) ws.send(JSON.stringify({action:'panic_wipe'}));
  statusline('panic wipe dispatched', 'alarm');
 });

 // Sparklines
 function pushSpark(key, val){
  const buf = sparkBuf[key];
  buf.push(val);
  if(buf.length > SPARK_N) buf.shift();
  drawSpark('sp-'+key, buf);
 }
 function drawSpark(id, data){
  const el = document.getElementById(id);
  if(!el || !data.length) return;
  const w = 64, h = 20;
  const max = Math.max.apply(null, data.concat([1])), min = Math.min.apply(null, data.concat([0]));
  const range = (max - min) || 1;
  const pts = data.map((v, i) => {
   const x = (i / Math.max(1, data.length-1)) * w;
   const y = h - ((v - min) / range) * (h - 2) - 1;
   return x.toFixed(1)+','+y.toFixed(1);
  }).join(' ');
  el.innerHTML = '<polyline points="'+pts+'" fill="none" stroke="#5aff6e" stroke-width="1.2" />';
 }

 function seedFeedFromHistory(){
  if(_seeded) return;
  _seeded = true;
  (state.history || []).forEach(h => {
   pushFeed(toFeedRow({ msg_type:h.type||'?', peer_id:(h.data&&h.data.peer_id)||'', direction:'in', payload:(h.data&&h.data.payload)||'', timestamp:h.timestamp }));
  });
 }

 // Relative-time tick
 setInterval(() => { if(state.peers && state.peers.length) renderPeers(state.peers); }, 5000);

 connect();
})();
</script></body></html>"""
