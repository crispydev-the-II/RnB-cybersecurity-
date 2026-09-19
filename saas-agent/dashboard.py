"""
dashboard.py
Live terminal dashboard using rich.
Subscribes to event_emitter events and renders a live-updating display.
"""

import threading
import time
from collections import defaultdict

from rich.console import Console
from rich.live import Live
from rich.layout import Layout
from rich.panel import Panel
from rich.progress import Progress, BarColumn, TextColumn
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

from event_emitter import EventEmitter


# ─── Severity Colors ───────────────────────────────────────────────────────────

def sev_color(sev):
    return {
        "CRITICAL": "bold red",
        "HIGH": "yellow",
        "MEDIUM": "blue",
        "LOW": "dim",
        "INFO": "dim white",
    }.get(sev.upper() if sev else "INFO", "white")


# ─── Dashboard State ───────────────────────────────────────────────────────────

class DashboardState:
    def __init__(self):
        self.emitter = EventEmitter()
        self._lock = threading.Lock()
        self.scan_done = False
        self.scan_total = 0
        self.scan_progress = 0
        self.probed = []          # (method, path, status)
        self.accessible = []
        self.deviations = []      # {type, severity, path}
        self.sev_counts = defaultdict(int)
        self.nodes = set(["guest", "user", "admin", "system"])
        self.edges = []           # {from_node, to_node, reason}
        self.attack_steps = []    # {step, title, method, result, success}
        self.target_reached = False
        self.target_keys = []
        self.event_count = 0
        self.agent_email = "—"

        # ── Blue Agent State ───────────────────────────────────────────────
        self.blue_running = False
        self.blue_breach_detected = False
        self.blue_patch_history = []   # {vuln, status, description, timestamp}
        self.blue_vuln_status = {}     # vuln_id -> status string
        self.blue_detections = []      # {vuln, description, severity}
        self.blue_mode = "red"         # "red" | "blue" | "red-blue"

        self._subscribe()

    def _subscribe(self):
        e = self.emitter

        def on_registered(etype, data):
            with self._lock:
                self.agent_email = data.get('email', '-')

        def on_scan_progress(etype, data):
            with self._lock:
                self.scan_total = data.get('total', 0)
                self.scan_progress = data.get('current', 0)

        def on_probed(etype, data):
            with self._lock:
                method = data.get('method', '?')
                path = data.get('path', '?')
                status = data.get('status', 0)
                self.probed.append((method, path, status))
                self.scan_progress = len(self.probed)
                if 200 <= status < 300:
                    self.accessible.append((method, path, status))

        def on_scan_complete(etype, data):
            with self._lock:
                self.scan_done = True

        def on_deviation(etype, data):
            with self._lock:
                d = {
                    'type': data.get('type', '?'),
                    'severity': data.get('severity', 'INFO'),
                    'path': data.get('path', '?'),
                }
                self.deviations.insert(0, d)
                self.sev_counts[data.get('severity', 'INFO')] += 1
                self.deviations = self.deviations[:50]

        def on_edge(etype, data):
            with self._lock:
                edge = {
                    'from_node': data.get('from_node', ''),
                    'to_node': data.get('to_node', ''),
                    'reason': data.get('reason', ''),
                    'method': data.get('method', ''),
                    'endpoint': data.get('endpoint', ''),
                }
                self.edges.append(edge)
                self.nodes.add(data.get('from_node', ''))
                self.nodes.add(data.get('to_node', ''))

        def on_step(etype, data):
            with self._lock:
                step = {
                    'step': data.get('step', len(self.attack_steps) + 1),
                    'title': data.get('title', 'Unknown Step'),
                    'method': data.get('method', '?'),
                    'result': data.get('result', '?'),
                    'success': data.get('success', False),
                }
                self.attack_steps.append(step)

        def on_target(etype, data):
            with self._lock:
                self.target_reached = True
                self.target_keys = data.get('keys', [])

        e.on('agent_registered', on_registered)
        e.on('scan_progress', on_scan_progress)
        e.on('endpoint_probed', on_probed)
        e.on('scan_complete', on_scan_complete)
        e.on('deviation_found', on_deviation)
        e.on('graph_edge', on_edge)
        e.on('escalation_step', on_step)
        e.on('target_reached', on_target)

        # ── Blue Agent Events ──────────────────────────────────────────────
        def on_blue_start(etype, data):
            with self._lock:
                self.blue_running = True
                self.blue_mode = data.get('mode', 'daemon')

        def on_blue_snapshot_start(etype, data):
            with self._lock:
                self.blue_running = True
                self.blue_mode = 'snapshot'

        def on_anomaly(etype, data):
            with self._lock:
                d = {
                    'vuln': data.get('vuln', '?'),
                    'description': data.get('description', '?'),
                    'severity': data.get('severity', 'medium'),
                    'rule_id': data.get('rule_id', ''),
                }
                self.blue_detections.insert(0, d)
                self.blue_detections = self.blue_detections[:20]

        def on_patch_attempt(etype, data):
            with self._lock:
                vuln = data.get('vuln', '?')
                self.blue_vuln_status[vuln] = 'patching'

        def on_patch_applied(etype, data):
            with self._lock:
                vuln = data.get('vuln', '?')
                status = data.get('status', 'unknown')
                self.blue_vuln_status[vuln] = 'patched' if status == 'applied' else status
                self.blue_patch_history.insert(0, {
                    'vuln': vuln,
                    'status': status,
                    'description': data.get('description', ''),
                    'timestamp': data.get('timestamp', ''),
                })
                self.blue_patch_history = self.blue_patch_history[:20]

        def on_breach(etype, data):
            with self._lock:
                self.blue_breach_detected = True

        def on_patch_all_complete(etype, data):
            with self._lock:
                for vuln in data.get('patched', []):
                    self.blue_vuln_status[vuln] = 'patched'
                for vuln in data.get('already_patched', []):
                    self.blue_vuln_status[vuln] = 'already_patched'

        e.on('blue_start', on_blue_start)
        e.on('blue_snapshot_start', on_blue_snapshot_start)
        e.on('anomaly_detected', on_anomaly)
        e.on('patch_attempt', on_patch_attempt)
        e.on('patch_applied', on_patch_applied)
        e.on('breach_detected', on_breach)
        e.on('patch_all_complete', on_patch_all_complete)

def render_scan_panel(state):
    """Left panel: endpoint scanner progress + recent probes."""
    table = Table(title="[bold]ENDPOINT SCANNER", expand=False, box=None,
                  header_style="bold cyan", border_style="cyan")

    table.add_column("Status", width=6, style="bold")
    table.add_column("Method", width=7, style="dim")
    table.add_column("Path", min_width=35)

    with state._lock:
        # Show last 12 probed endpoints
        recent = list(reversed(state.probed))[:12]
        scan_pct = 0
        if state.scan_total > 0:
            scan_pct = int(100 * state.scan_progress / state.scan_total)

    status_colors = {
        200: "green", 201: "green", 204: "green",
        400: "yellow", 401: "yellow", 403: "yellow", 404: "yellow",
        422: "yellow",
        500: "red", 502: "red", 503: "red",
    }

    for method, path, status in recent:
        color = status_colors.get(status, "dim")
        status_str = str(status) if status > 0 else "ERR"
        table.add_row(
            f"[{color}]{status_str}[/{color}]",
            f"[dim]{method}[/dim]",
            path[:60]
        )

    if not state.scan_done:
        bar = f"[cyan]{scan_pct}%[/cyan] ({state.scan_progress}/{state.scan_total})"
    else:
        bar = "[green]DONE[/green]"

    panel = Panel(
        table,
        title=f"[cyan]Scanning... {bar}[/cyan]",
        border_style="cyan",
        padding=(1, 1),
    )
    return panel


def render_deviation_panel(state):
    """Right panel: deviation feed."""
    table = Table(title="[bold]DEVIATION FEED", expand=False, box=None,
                  header_style="bold yellow", border_style="yellow")
    table.add_column("Sev", width=9)
    table.add_column("Type", width=20)
    table.add_column("Endpoint", min_width=25)

    with state._lock:
        devs = list(state.deviations)[:12]

    for dev in devs:
        sev = dev.get("severity", "INFO")
        color = sev_color(sev)
        table.add_row(
            f"[{color}]{sev}[/{color}]",
            f"[{color}]{dev.get('type', '?')[:20]}[/{color}]",
            dev.get("path", "?")[:40]
        )

    panel = Panel(
        table,
        title="[yellow]Anomalies Detected[/yellow]",
        border_style="yellow",
        padding=(1, 1),
    )
    return panel


def render_graph_panel(state):
    """Middle panel: permission graph."""
    with state._lock:
        nodes = set(state.nodes)
        edges = list(state.edges)

    tree = Tree("[bold cyan]PERMISSION GRAPH[/bold cyan]", guide_style="cyan")

    PERM_ORDER = ["guest", "user", "admin", "system"]

    def add_node(parent_tree, node_name, level):
        label_styles = {
            "guest": "dim",
            "user": "green",
            "admin": "yellow bold",
            "system": "red bold",
        }
        style = label_styles.get(node_name, "")
        branch = parent_tree.add(f"[{style}]{node_name.upper()}[/{style}] "
                                 f"[dim](level {level})[/dim]")

        # Find edges FROM this node
        with state._lock:
            from_edges = [e for e in state.edges if e["from_node"] == node_name]

        for e in from_edges:
            reason_short = e.get("reason", "")[:35]
            branch.add(f"[dim]-> {e['to_node'].upper()}[/dim]  [dim]{reason_short}[/dim]")

        return branch

    # Build tree structure
    root = tree
    if "guest" in nodes:
        root = add_node(tree, "guest", 0)
    if "user" in nodes:
        add_node(tree if "guest" not in nodes else root, "user", 1)

    # If user has edges, add them under user node
    with state._lock:
        user_edges = [e for e in state.edges if e["from_node"] == "user"]
        if user_edges and "user" in nodes:
            pass  # already added above

    for node in ["admin", "system"]:
        if node in nodes:
            add_node(tree, node, PERM_ORDER.index(node))

    panel = Panel(
        tree,
        title="[bold magenta]PRIVILEGE ESCALATION PATH[/bold magenta]",
        border_style="magenta",
        padding=(1, 1),
        height=10,
    )
    return panel


def render_attack_panel(state):
    """Bottom panel: attack chain timeline."""
    table = Table(title="[bold]ATTACK CHAIN[/bold]", expand=False, box=None,
                  header_style="bold red", border_style="red")
    table.add_column("Step", width=6)
    table.add_column("Vulnerability", width=30)
    table.add_column("Method", width=25)
    table.add_column("Status", width=12)

    with state._lock:
        steps = list(state.attack_steps)

    for i, step in enumerate(steps):
        step_num = step.get("step", i + 1)
        title = step.get("title", "Unknown")[:30]
        method = step.get("method", "?")[:25]
        success = step.get("success", False)

        if success:
            status = "[green]SUCCESS[/green]"
        else:
            status = "[red]FAILED[/red]"

        table.add_row(
            f"[bold cyan]{step_num}[/bold cyan]",
            title,
            f"[dim]{method}[/dim]",
            status,
        )

    # Add pending steps if target not reached
    with state._lock:
        current_step = len(steps) + 1
        if not state.target_reached:
            pending = ["V6: Stripe Webhook Bypass", "V10: Role Management",
                       "Target: /internal/api-keys"]
            for title in pending[len(steps):]:
                table.add_row(
                    f"[dim]{current_step}[/dim]",
                    f"[dim]{title}[/dim]",
                    "[dim]pending...[/dim]",
                    "[dim]PENDING[/dim]"
                )
                current_step += 1
        else:
            # Show target reached
            pass

    panel = Panel(
        table,
        title="[bold red]ATTACK EXECUTION[/bold red]",
        border_style="red",
        padding=(1, 1),
    )
    return panel


def render_target_panel(state):
    """Shows target data when reached."""
    with state._lock:
        reached = state.target_reached
        keys = list(state.target_keys)

    if not reached:
        return Panel(
            "[yellow]Target: /internal/api-keys[/yellow]\n"
            "[dim]Waiting for attack chain to complete...[/dim]",
            title="[bold]TARGET STATUS[/bold]",
            border_style="white",
            height=6,
        )

    table = Table(title="[bold green]TARGET REACHED[/bold green]", expand=False, box=None,
                  header_style="bold green")
    table.add_column("Name", width=20)
    table.add_column("Email", width=25)
    table.add_column("Scopes", min_width=30)

    for k in keys[:5]:
        table.add_row(
            k.get("name", "?"),
            k.get("email", "?"),
            str(k.get("scopes", []))[:50],
        )

    msg = f"[green bold]TARGET ACCESSED — {len(keys)} API keys exposed[/green bold]"
    panel = Panel(
        Group(table, f"\n{msg}"),
        title="[bold green]TARGET: /internal/api-keys[/bold green]",
        border_style="green",
        padding=(1, 1),
    )
    return panel


def render_blue_panel(state):
    """Blue agent status panel — vulnerability patch tracker."""
    from rich.table import Table

    with state._lock:
        vuln_status = dict(state.blue_vuln_status)
        patch_history = list(state.blue_patch_history)
        detections = list(state.blue_detections)
        breach = state.blue_breach_detected
        running = state.blue_running
        mode = state.blue_mode

    # Vulnerability status grid
    table = Table(title="[bold]VULNERABILITY STATUS[/bold]", expand=False, box=None,
                  header_style="bold blue", border_style="blue", show_header=True)
    table.add_column("Vuln", width=8, style="bold")
    table.add_column("Status", width=14)
    table.add_column("Description", min_width=40)

    VULN_DESCS = {
        "V1": "OAuth token leakage",
        "V2": "File IDOR",
        "V3": "API key scope escalation",
        "V4": "Job result enumeration",
        "V5": "Webhook replay attack",
        "V6": "Stripe webhook bypass",
        "V7": "Path traversal",
        "V8": "Email tracking pixel",
        "V9": "OAuth CSRF",
        "V10": "Admin role escalation",
    }

    for vuln in ["V1", "V2", "V3", "V4", "V5", "V6", "V7", "V8", "V9", "V10"]:
        status = vuln_status.get(vuln, "unpatched")
        if status == "unpatched":
            style = "red"
            label = "[red]UNPATCHED[/red]"
        elif status == "patching":
            style = "yellow"
            label = "[yellow]PATCHING...[/yellow]"
        elif status in ("applied", "patched"):
            style = "green"
            label = "[green]PATCHED[/green]"
        elif status == "already_patched":
            style = "cyan"
            label = "[cyan]FIXED[/cyan]"
        else:
            style = "dim"
            label = f"[dim]{status}[/dim]"

        table.add_row(
            f"[bold]{vuln}[/bold]",
            label,
            f"[dim]{VULN_DESCS.get(vuln, '')}[/dim]",
        )

    # Mode / breach indicator
    if breach:
        status_bar = "[bold red on white]  BREACH DETECTED — EMERGENCY PATCH IN PROGRESS  [/]"
    elif running:
        status_bar = f"[bold blue]BLUE AGENT: {mode.upper()} MODE[/bold blue]"
    else:
        status_bar = "[dim]Blue Agent: not running[/dim]"

    from rich.console import Group
    panel = Panel(
        Group(table, f"\n{status_bar}"),
        title="[bold blue]BLUE AGENT STATUS[/bold blue]",
        border_style="blue",
        padding=(1, 1),
    )
    return panel


def make_layout(state):
    """Build the full rich Layout."""
    from rich.layout import Layout as RLayout
    from rich.console import Group as RGroup

    layout = RLayout()
    layout.split_column(
        RLayout(name="header", size=3),
        RLayout(name="main"),
        RLayout(name="attack", size=10),
        RLayout(name="blue", size=10),
        RLayout(name="target", size=8),
    )
    layout["main"].split_row(
        RLayout(name="scan", ratio=2),
        RLayout(name="deviation", ratio=2),
        RLayout(name="graph", ratio=1),
    )
    return layout


def build_header(state):
    """Build header panel."""
    from rich.console import Group
    from rich.text import Text

    with state._lock:
        email = state.agent_email
        total = state.event_count
        leaks = len(state.deviations)

    status = "[green]RUNNING[/green]" if not state.target_reached else "[bold green]TARGET REACHED[/bold green]"
    header_text = Text.assemble(
        ("  NEXUS RED AGENT  ", "bold cyan"),
        f"  {status}  |  ",
        ("Target: ", "dim"),
        ("/internal/api-keys", "bold white"),
        f"  |  Events: {total}  |  Agent: {email}",
    )

    from rich.panel import Panel
    return Panel(
        header_text,
        style="cyan on black",
        border_style="cyan",
        padding=(0, 1),
    )


def render(state):
    """Build the full render output for Live."""
    from rich.console import Group

    with state._lock:
        scan_pct = 0
        if state.scan_total > 0:
            scan_pct = int(100 * state.scan_progress / state.scan_total)

    return Group(
        build_header(state),
        render_scan_panel(state),
        render_deviation_panel(state),
        render_graph_panel(state),
        render_attack_panel(state),
        render_blue_panel(state),
        render_target_panel(state),
    )


# ─── Main ──────────────────────────────────────────────────────────────────────

def run_dashboard():
    """Launch the live dashboard, blocking."""
    state = DashboardState()
    console = Console()

    with Live(render(state), console=console, refresh_per_second=8,
              screen=True, transient=False) as live:
        while True:
            time.sleep(0.125)
            try:
                live.update(render(state))
            except Exception:
                break

            # Check if all stages done
            with state._lock:
                # Exit when scan is done — target may or may not be reached
                # (in red-blue mode, patches may block the target)
                if state.scan_done:
                    time.sleep(1)
                    break

    # Final render (not live)
    console.print()
    console.print("[bold green]Target reached![/bold green]")
    console.print("[bold]Final State:[/bold]")
    console.print(f"  Deviations found: {len(state.deviations)}")
    console.print(f"  Graph edges: {len(state.edges)}")
    console.print(f"  Attack steps: {len(state.attack_steps)}")


if __name__ == "__main__":
    run_dashboard()
