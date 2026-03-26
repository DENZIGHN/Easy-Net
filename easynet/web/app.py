"""Optional web UI for managing EasyNet rules and monitoring.

A simple localhost-only web interface built with aiohttp that provides:
- Dashboard showing proxy status and active connections
- Blocklist management (add/remove domains)
- Bypass method status and per-domain configuration
- DNS resolution testing
"""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING

from aiohttp import web

if TYPE_CHECKING:
    from easynet.core.engine import BypassEngine
    from easynet.routing.router import SmartRouter
    from easynet.utils.config import Config

logger = logging.getLogger(__name__)

# Inline HTML template (avoids requiring jinja2/template files)
DASHBOARD_HTML = """<!DOCTYPE html>
<html>
<head>
    <title>EasyNet Dashboard</title>
    <meta charset="utf-8">
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
               background: #1a1a2e; color: #eee; padding: 20px; }
        h1 { color: #0f3460; background: #16213e; padding: 15px 20px;
             border-radius: 8px; margin-bottom: 20px; color: #e94560; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
                gap: 20px; }
        .card { background: #16213e; border-radius: 8px; padding: 20px;
                border: 1px solid #0f3460; }
        .card h2 { color: #e94560; margin-bottom: 15px; font-size: 1.1em; }
        .stat { display: flex; justify-content: space-between; padding: 8px 0;
                border-bottom: 1px solid #0f3460; }
        .stat:last-child { border-bottom: none; }
        .stat .label { color: #a8a8b3; }
        .stat .value { color: #0ff; font-family: monospace; }
        .domain-list { max-height: 200px; overflow-y: auto; }
        .domain { padding: 4px 8px; font-family: monospace; font-size: 0.9em; }
        .domain:nth-child(odd) { background: rgba(255,255,255,0.05); }
        input[type=text] { background: #0f3460; border: 1px solid #533483;
                           color: #eee; padding: 8px 12px; border-radius: 4px;
                           width: 70%; font-family: monospace; }
        button { background: #e94560; color: white; border: none; padding: 8px 16px;
                 border-radius: 4px; cursor: pointer; margin-left: 8px; }
        button:hover { background: #c73e54; }
        .method { display: inline-block; background: #533483; padding: 3px 10px;
                  border-radius: 12px; margin: 3px; font-size: 0.85em; }
        #status { color: #0f0; font-size: 0.9em; margin-top: 8px; }
    </style>
</head>
<body>
    <h1>EasyNet Dashboard</h1>
    <div class="grid">
        <div class="card">
            <h2>Status</h2>
            <div id="stats"></div>
        </div>
        <div class="card">
            <h2>Bypass Methods</h2>
            <div id="methods"></div>
        </div>
        <div class="card">
            <h2>Blocked Domains</h2>
            <div id="domains" class="domain-list"></div>
            <div style="margin-top: 10px;">
                <input type="text" id="newDomain" placeholder="example.com">
                <button onclick="addDomain()">Add</button>
            </div>
            <div id="status"></div>
        </div>
        <div class="card">
            <h2>DNS Test</h2>
            <input type="text" id="dnsQuery" placeholder="Domain to resolve">
            <button onclick="testDns()">Resolve</button>
            <pre id="dnsResult" style="margin-top:10px; font-size:0.85em; color:#a8a8b3;"></pre>
        </div>
    </div>
    <script>
        async function loadStatus() {
            const resp = await fetch('/api/status');
            const data = await resp.json();
            document.getElementById('stats').innerHTML = Object.entries(data.router)
                .map(([k,v]) => `<div class="stat"><span class="label">${k}</span><span class="value">${v}</span></div>`)
                .join('');
            document.getElementById('methods').innerHTML =
                data.methods.map(m => `<span class="method">${m}</span>`).join('');
            document.getElementById('domains').innerHTML =
                (data.router.blocked_domains || []).map(d => `<div class="domain">${d}</div>`).join('');
        }
        async function addDomain() {
            const domain = document.getElementById('newDomain').value.trim();
            if (!domain) return;
            const resp = await fetch('/api/blocklist', {
                method: 'POST', headers: {'Content-Type':'application/json'},
                body: JSON.stringify({domain, action: 'add'})
            });
            const data = await resp.json();
            document.getElementById('status').textContent = data.message;
            document.getElementById('newDomain').value = '';
            loadStatus();
        }
        async function testDns() {
            const domain = document.getElementById('dnsQuery').value.trim();
            if (!domain) return;
            const resp = await fetch(`/api/dns?domain=${encodeURIComponent(domain)}`);
            const data = await resp.json();
            document.getElementById('dnsResult').textContent = JSON.stringify(data, null, 2);
        }
        loadStatus();
        setInterval(loadStatus, 5000);
    </script>
</body>
</html>"""


class WebUI:
    """Localhost web interface for EasyNet management."""

    def __init__(
        self, config: Config, router: SmartRouter, engine: BypassEngine
    ) -> None:
        self.config = config
        self.router = router
        self.engine = engine
        self._app = web.Application()
        self._runner: web.AppRunner | None = None
        self._setup_routes()

    def _setup_routes(self) -> None:
        self._app.router.add_get("/", self._handle_dashboard)
        self._app.router.add_get("/api/status", self._handle_status)
        self._app.router.add_post("/api/blocklist", self._handle_blocklist)
        self._app.router.add_get("/api/dns", self._handle_dns)

    async def start(self) -> None:
        self._runner = web.AppRunner(self._app)
        await self._runner.setup()
        site = web.TCPSite(
            self._runner, self.config.web.host, self.config.web.port
        )
        await site.start()
        logger.info(f"Web UI started on {self.config.web.host}:{self.config.web.port}")

    async def stop(self) -> None:
        if self._runner:
            await self._runner.cleanup()

    async def _handle_dashboard(self, request: web.Request) -> web.Response:
        return web.Response(text=DASHBOARD_HTML, content_type="text/html")

    async def _handle_status(self, request: web.Request) -> web.Response:
        return web.json_response({
            "router": self.router.get_status(),
            "methods": self.engine.available_methods,
        })

    async def _handle_blocklist(self, request: web.Request) -> web.Response:
        data = await request.json()
        domain = data.get("domain", "").strip().lower()
        action = data.get("action", "add")

        if not domain:
            return web.json_response({"error": "Domain required"}, status=400)

        if action == "add":
            self.router.blocklist.add(domain)
            await self.router.blocklist.save()
            return web.json_response({"message": f"Added {domain}"})
        elif action == "remove":
            self.router.blocklist.remove(domain)
            await self.router.blocklist.save()
            return web.json_response({"message": f"Removed {domain}"})
        else:
            return web.json_response({"error": "Invalid action"}, status=400)

    async def _handle_dns(self, request: web.Request) -> web.Response:
        domain = request.query.get("domain", "").strip()
        if not domain:
            return web.json_response({"error": "Domain required"}, status=400)

        from easynet.dns.resolver import DnsResolver
        resolver = DnsResolver(self.config)
        await resolver.initialize()
        try:
            results = await resolver.resolve_all_providers(domain)
            return web.json_response({
                "domain": domain,
                "results": [
                    {
                        "source": r.source,
                        "provider": r.provider,
                        "addresses": r.addresses,
                        "query_time_ms": round(r.query_time_ms, 1),
                        "error": r.error,
                    }
                    for r in results
                ],
            })
        finally:
            await resolver.shutdown()
