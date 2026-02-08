# eos.py
# EOS – EduOps Suite (v1.1) Windows 10/11
# + comando DIFF tra due scans JSON

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import subprocess
from pathlib import Path
from typing import Any, Dict, Tuple, List

BASE_DIR = Path(__file__).resolve().parent
PS_ENGINE = BASE_DIR / "eos_win.ps1"
OUT_DIR = BASE_DIR / "output"


def now_stamp() -> str:
    return dt.datetime.now().strftime("%Y%m%d_%H%M%S")


def ensure_outdir() -> None:
    OUT_DIR.mkdir(exist_ok=True)


def run_powershell(mode: str, apply: bool = False) -> Dict[str, Any]:
    if not PS_ENGINE.exists():
        raise FileNotFoundError(f"No encuentro {PS_ENGINE}")

    cmd = [
        "powershell.exe",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        (
            "[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new(); "
            f"& '{PS_ENGINE}' -Mode {mode} "
            + ("-Apply" if apply else "")
        ),
    ]

    p = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    raw = (p.stdout or "").strip()

    if not raw:
        raise RuntimeError(
            "PowerShell no devolvió salida.\n"
            f"ExitCode: {p.returncode}\n"
            f"STDERR:\n{p.stderr}\n"
        )

    try:
        env = json.loads(raw)
    except json.JSONDecodeError:
        raise RuntimeError(
            "No pude parsear JSON desde PowerShell.\n"
            f"STDOUT:\n{raw}\n\nSTDERR:\n{p.stderr}\n"
        )

    if isinstance(env, dict) and env.get("ok") is False:
        errs = "\n".join(env.get("errors") or [])
        raise RuntimeError(f"PowerShell falló (mode={mode}).\n{errs}")

    if isinstance(env, dict) and "data" in env:
        return env["data"] or {}

    return env


def ensure_list(x: Any) -> list:
    if x is None:
        return []
    if isinstance(x, list):
        return x
    if isinstance(x, dict):
        return [x]
    return []


def semaforo(status: str) -> Tuple[str, str]:
    s = (status or "").upper()
    if s == "OK":
        return "🟢", "ok"
    if s == "WARN":
        return "🟡", "warn"
    if s == "CRIT":
        return "🔴", "crit"
    return "⚪", "neutral"


def score_simple(inv: Dict[str, Any], diag: Dict[str, Any], sec: Dict[str, Any]) -> Dict[str, Any]:
    items = []

    disk_warn = False
    for d in ensure_list(inv.get("Storage")):
        try:
            fp = d.get("FreePct")
            if fp is not None and float(fp) < 15:
                disk_warn = True
        except Exception:
            pass
    items.append({"name": "Espacio en disco", "status": "WARN" if disk_warn else "OK",
                  "detail": "Volúmenes con poco espacio (<15%)." if disk_warn else "Correcto."})

    ping = ensure_list(diag.get("Ping"))
    ip_targets = [p for p in ping if p.get("Target") in ("1.1.1.1", "8.8.8.8")]
    ping_fail = any((p.get("Success") is False) for p in ip_targets) if ip_targets else False
    items.append({"name": "Conectividad Internet (ICMP)", "status": "CRIT" if ping_fail else "OK",
                  "detail": "Falla ping a 1.1.1.1/8.8.8.8. Revisar red/DNS/firewall." if ping_fail else "OK."})

    fw_profiles = ensure_list(sec.get("FirewallProfiles"))
    fw_disabled = any((str(p.get("Enabled")).lower() == "false") for p in fw_profiles) if fw_profiles else False
    items.append({"name": "Firewall", "status": "WARN" if fw_disabled else "OK",
                  "detail": "Algún perfil desactivado." if fw_disabled else "Activado."})

    defender = sec.get("Defender") or {}
    rt = defender.get("RealTimeProtectionEnabled") if isinstance(defender, dict) else None
    if rt is None:
        items.append({"name": "Antivirus/Defender", "status": "WARN",
                      "detail": "No se pudo leer Defender (¿tercer AV? ¿permisos?)."})
    else:
        items.append({"name": "Antivirus/Defender", "status": "OK" if bool(rt) else "WARN",
                      "detail": "Protección en tiempo real desactivada." if not bool(rt) else "OK."})

    rdp = str(sec.get("RDP") or "UNKNOWN").upper()
    items.append({"name": "RDP", "status": "WARN" if rdp == "ENABLED" else "OK",
                  "detail": "RDP habilitado: asegurar VPN/MFA/limitación IP." if rdp == "ENABLED" else "Deshabilitado."})

    smb1 = str(sec.get("SMB1") or "Unknown").lower()
    smb1_bad = "enabled" in smb1
    items.append({"name": "SMBv1", "status": "CRIT" if smb1_bad else "OK",
                  "detail": "SMBv1 activado: deshabilitar." if smb1_bad else "No activo / no detectado."})

    is_admin = bool(inv.get("IsAdmin"))
    items.append({"name": "Permisos", "status": "OK" if is_admin else "WARN",
                  "detail": "Ejecutado como admin." if is_admin else "No admin: checks/fixes limitados."})

    crits = sum(1 for i in items if i["status"] == "CRIT")
    warns = sum(1 for i in items if i["status"] == "WARN")
    global_status = "CRIT" if crits else ("WARN" if warns else "OK")

    return {"global": global_status, "items": items}


def html_report(bundle: Dict[str, Any], out_html: Path) -> None:
    inv = bundle["inventory"]
    diag = bundle["diagnostics"]
    sec = bundle["security"]
    score = bundle["score"]

    g_emoji, g_cls = semaforo(score["global"])

    def esc(x: Any) -> str:
        return ("" if x is None else str(x)).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    rows_score = "\n".join(
        f"<tr><td>{esc(i['name'])}</td><td class='{semaforo(i['status'])[1]}'>{semaforo(i['status'])[0]} {esc(i['status'])}</td><td>{esc(i['detail'])}</td></tr>"
        for i in score["items"]
    )

    storage_rows = "\n".join(
        f"<tr><td>{esc(d.get('Drive'))}</td><td>{esc(d.get('FileSystem'))}</td><td>{esc(d.get('SizeGB'))}</td><td>{esc(d.get('FreeGB'))}</td><td>{esc(d.get('FreePct'))}%</td></tr>"
        for d in ensure_list(inv.get("Storage"))
    )

    net_rows = "\n".join(
        f"<tr><td>{esc(n.get('Name'))}</td><td>{esc(n.get('Status'))}</td><td>{esc(n.get('Mac'))}</td><td>{esc(n.get('LinkSpeed'))}</td><td>{esc(n.get('IPv4'))}</td></tr>"
        for n in ensure_list(inv.get("Network"))
    )

    ping_rows = "\n".join(
        f"<tr><td>{esc(p.get('Target'))}</td><td>{'✅' if p.get('Success') else '❌'}</td><td>{esc(p.get('AvgMs'))}</td></tr>"
        for p in ensure_list(diag.get("Ping"))
    )

    fw_rows = "\n".join(
        f"<tr><td>{esc(p.get('Name'))}</td><td>{esc(p.get('Enabled'))}</td></tr>"
        for p in ensure_list(sec.get("FirewallProfiles"))
    )

    osinfo = inv.get("OS") or {}
    hw = inv.get("Hardware") or {}

    html = f"""<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>EOS Report</title>
<style>
body {{ font-family: Arial, sans-serif; margin: 24px; background: #0b0e14; color: #e8eefc; }}
.card {{ background: #121826; border: 1px solid #22304d; border-radius: 14px; padding: 16px; margin-bottom: 16px; }}
h1,h2,h3 {{ margin: 0 0 10px 0; }}
small {{ color: #a9b6d6; }}
table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
th, td {{ border-bottom: 1px solid #22304d; padding: 8px; text-align: left; vertical-align: top; }}
th {{ color: #a9b6d6; font-weight: 600; }}
.ok {{ color: #4ade80; }}
.warn {{ color: #fbbf24; }}
.crit {{ color: #fb7185; }}
.neutral {{ color: #cbd5e1; }}
.badge {{ display:inline-block; padding: 6px 10px; border-radius: 999px; border: 1px solid #22304d; }}
.mono {{ font-family: Consolas, monospace; }}
</style>
</head>
<body>
  <div class="card">
    <h1>EOS – EduOps Suite Report</h1>
    <small>Generado: {esc(bundle['meta']['generated_at'])} · Equipo: <b>{esc(inv.get('ComputerName'))}</b> · Usuario: {esc(inv.get('User'))}</small>
    <div style="margin-top:10px;">
      <span class="badge {g_cls}">{g_emoji} Estado global: {esc(score['global'])}</span>
      <span class="badge mono">Hotfix: {esc(inv.get('HotfixCount'))}</span>
      <span class="badge mono">Admin: {esc(inv.get('IsAdmin'))}</span>
    </div>
  </div>

  <div class="card">
    <h2>Semáforo técnico</h2>
    <table>
      <thead><tr><th>Área</th><th>Estado</th><th>Detalle</th></tr></thead>
      <tbody>{rows_score}</tbody>
    </table>
  </div>

  <div class="card">
    <h2>Inventario</h2>
    <p><b>SO:</b> {esc(osinfo.get('Caption'))} · v{esc(osinfo.get('Version'))} · Build {esc(osinfo.get('BuildNumber'))}</p>
    <p><b>HW:</b> {esc(hw.get('Manufacturer'))} {esc(hw.get('Model'))} · Serial: {esc(hw.get('Serial'))}</p>
    <p><b>CPU:</b> {esc(hw.get('CPU'))} · <b>RAM:</b> {esc(hw.get('RAM_GB'))} GB</p>

    <h3>Almacenamiento</h3>
    <table>
      <thead><tr><th>Unidad</th><th>FS</th><th>Tamaño (GB)</th><th>Libre (GB)</th><th>Libre (%)</th></tr></thead>
      <tbody>{storage_rows}</tbody>
    </table>

    <h3>Red</h3>
    <table>
      <thead><tr><th>NIC</th><th>Estado</th><th>MAC</th><th>Velocidad</th><th>IPv4</th></tr></thead>
      <tbody>{net_rows}</tbody>
    </table>
  </div>

  <div class="card">
    <h2>Diagnóstico rápido</h2>
    <p><b>Gateway por defecto:</b> {esc(diag.get('DefaultGateway'))}</p>
    <h3>Ping</h3>
    <table>
      <thead><tr><th>Destino</th><th>OK</th><th>Media (ms)</th></tr></thead>
      <tbody>{ping_rows}</tbody>
    </table>
  </div>

  <div class="card">
    <h2>Seguridad (check básico)</h2>
    <p><b>RDP:</b> {esc(sec.get('RDP'))} · <b>SMBv1:</b> {esc(sec.get('SMB1'))}</p>

    <h3>Firewall (perfiles)</h3>
    <table>
      <thead><tr><th>Perfil</th><th>Enabled</th></tr></thead>
      <tbody>{fw_rows}</tbody>
    </table>
  </div>
</body>
</html>
"""
    out_html.write_text(html, encoding="utf-8")


def load_scan(path: str) -> Dict[str, Any]:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"No existe: {p}")
    return json.loads(p.read_text(encoding="utf-8"))


def _kv(label: str, old: Any, new: Any) -> Dict[str, Any]:
    return {"label": label, "old": old, "new": new}


def diff_scans(old: Dict[str, Any], new: Dict[str, Any]) -> Dict[str, Any]:
    oinv, ninv = old.get("inventory", {}), new.get("inventory", {})
    osec, nsec = old.get("security", {}), new.get("security", {})
    odiag, ndiag = old.get("diagnostics", {}), new.get("diagnostics", {})

    changes: List[Dict[str, Any]] = []

    # OS + HW
    changes.append(_kv("OS.Caption", (oinv.get("OS") or {}).get("Caption"), (ninv.get("OS") or {}).get("Caption")))
    changes.append(_kv("OS.BuildNumber", (oinv.get("OS") or {}).get("BuildNumber"), (ninv.get("OS") or {}).get("BuildNumber")))
    changes.append(_kv("HotfixCount", oinv.get("HotfixCount"), ninv.get("HotfixCount")))

    # Disk summary (per drive)
    def disk_map(inv: Dict[str, Any]) -> Dict[str, Any]:
        m = {}
        for d in ensure_list(inv.get("Storage")):
            m[d.get("Drive")] = {"FreePct": d.get("FreePct"), "FreeGB": d.get("FreeGB")}
        return m

    od, nd = disk_map(oinv), disk_map(ninv)
    all_drives = sorted(set(od.keys()) | set(nd.keys()))
    for drv in all_drives:
        changes.append(_kv(f"Disk.{drv}.FreePct", (od.get(drv) or {}).get("FreePct"), (nd.get(drv) or {}).get("FreePct")))
        changes.append(_kv(f"Disk.{drv}.FreeGB", (od.get(drv) or {}).get("FreeGB"), (nd.get(drv) or {}).get("FreeGB")))

    # Network summary
    def net_map(inv: Dict[str, Any]) -> Dict[str, Any]:
        m = {}
        for n in ensure_list(inv.get("Network")):
            m[n.get("Name")] = {"Status": n.get("Status"), "IPv4": n.get("IPv4"), "LinkSpeed": n.get("LinkSpeed")}
        return m

    on, nn = net_map(oinv), net_map(ninv)
    all_nics = sorted(set(on.keys()) | set(nn.keys()))
    for nic in all_nics:
        changes.append(_kv(f"NIC.{nic}.Status", (on.get(nic) or {}).get("Status"), (nn.get(nic) or {}).get("Status")))
        changes.append(_kv(f"NIC.{nic}.IPv4", (on.get(nic) or {}).get("IPv4"), (nn.get(nic) or {}).get("IPv4")))
        changes.append(_kv(f"NIC.{nic}.LinkSpeed", (on.get(nic) or {}).get("LinkSpeed"), (nn.get(nic) or {}).get("LinkSpeed")))

    # Security key fields
    changes.append(_kv("Security.RDP", osec.get("RDP"), nsec.get("RDP")))
    changes.append(_kv("Security.SMB1", osec.get("SMB1"), nsec.get("SMB1")))

    # Ping summary (targets)
    def ping_map(diag: Dict[str, Any]) -> Dict[str, Any]:
        m = {}
        for p in ensure_list(diag.get("Ping")):
            m[p.get("Target")] = {"Success": p.get("Success"), "AvgMs": p.get("AvgMs")}
        return m

    op, np = ping_map(odiag), ping_map(ndiag)
    all_targets = sorted(set(op.keys()) | set(np.keys()))
    for t in all_targets:
        changes.append(_kv(f"Ping.{t}.Success", (op.get(t) or {}).get("Success"), (np.get(t) or {}).get("Success")))
        changes.append(_kv(f"Ping.{t}.AvgMs", (op.get(t) or {}).get("AvgMs"), (np.get(t) or {}).get("AvgMs")))

    # Filter: solo lo que cambia
    changed = [c for c in changes if c["old"] != c["new"]]

    return {
        "meta": {
            "old": old.get("meta", {}),
            "new": new.get("meta", {}),
            "generated_at": dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        },
        "changed_count": len(changed),
        "changes": changed,
    }


def html_diff_report(diff: Dict[str, Any], out_html: Path) -> None:
    def esc(x: Any) -> str:
        return ("" if x is None else str(x)).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    rows = "\n".join(
        f"<tr><td>{esc(c['label'])}</td><td>{esc(c['old'])}</td><td>{esc(c['new'])}</td></tr>"
        for c in diff["changes"]
    ) or "<tr><td colspan='3'>Sin cambios detectados.</td></tr>"

    html = f"""<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>EOS DIFF</title>
<style>
body {{ font-family: Arial, sans-serif; margin: 24px; background: #0b0e14; color: #e8eefc; }}
.card {{ background: #121826; border: 1px solid #22304d; border-radius: 14px; padding: 16px; margin-bottom: 16px; }}
table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
th, td {{ border-bottom: 1px solid #22304d; padding: 8px; text-align: left; vertical-align: top; }}
th {{ color: #a9b6d6; font-weight: 600; }}
.mono {{ font-family: Consolas, monospace; }}
</style>
</head>
<body>
  <div class="card">
    <h1>EOS – DIFF (Cambios entre scans)</h1>
    <p class="mono">Generado: {esc(diff['meta']['generated_at'])}</p>
    <p>Cambios detectados: <b>{diff['changed_count']}</b></p>
  </div>

  <div class="card">
    <h2>Listado de cambios</h2>
    <table>
      <thead><tr><th>Campo</th><th>Antes</th><th>Después</th></tr></thead>
      <tbody>{rows}</tbody>
    </table>
  </div>
</body>
</html>
"""
    out_html.write_text(html, encoding="utf-8")


def make_bundle() -> Dict[str, Any]:
    inv = run_powershell("inventory")
    diag = run_powershell("diagnostics")
    sec = run_powershell("security")
    score = score_simple(inv, diag, sec)
    return {
        "meta": {"generated_at": dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "tool": "EOS v1.1"},
        "inventory": inv,
        "diagnostics": diag,
        "security": sec,
        "score": score,
    }


def cmd_scan(_: argparse.Namespace) -> None:
    ensure_outdir()
    stamp = now_stamp()
    bundle = make_bundle()

    out_json = OUT_DIR / f"eos_{stamp}.json"
    out_json.write_text(json.dumps(bundle, indent=2, ensure_ascii=False), encoding="utf-8")

    out_html = OUT_DIR / f"eos_{stamp}.html"
    html_report(bundle, out_html)

    print("\n✅ SCAN completado")
    print(f"- JSON: {out_json}")
    print(f"- HTML: {out_html}")


def cmd_diff(args: argparse.Namespace) -> None:
    ensure_outdir()
    old = load_scan(args.old)
    new = load_scan(args.new)

    diff = diff_scans(old, new)

    stamp = now_stamp()
    out_json = OUT_DIR / f"eos_diff_{stamp}.json"
    out_html = OUT_DIR / f"eos_diff_{stamp}.html"
    out_json.write_text(json.dumps(diff, indent=2, ensure_ascii=False), encoding="utf-8")
    html_diff_report(diff, out_html)

    print("\n🧾 DIFF completado")
    print(f"- Cambios: {diff['changed_count']}")
    print(f"- JSON: {out_json}")
    print(f"- HTML: {out_html}")


def cmd_fix(args: argparse.Namespace) -> None:
    ensure_outdir()
    stamp = now_stamp()

    fix = run_powershell("fix", apply=bool(args.apply))
    out_json = OUT_DIR / f"eos_fix_{stamp}.json"
    out_json.write_text(json.dumps(fix, indent=2, ensure_ascii=False), encoding="utf-8")

    print("\n🧰 FIXPACK")
    print(f"- Modo: {'APPLY' if args.apply else 'DRY-RUN'}")
    print(f"- Admin: {fix.get('IsAdmin')}")
    print(f"- Log : {out_json}\n")
    for a in ensure_list(fix.get("Actions")):
        print(f"• {a.get('Status')}: {a.get('Name')} | Admin={a.get('NeedsAdmin')} | Puede ahora={a.get('CanRunNow')}")


def cmd_secure(_: argparse.Namespace) -> None:
    ensure_outdir()
    stamp = now_stamp()

    sec = run_powershell("security")
    out_json = OUT_DIR / f"eos_security_{stamp}.json"
    out_json.write_text(json.dumps(sec, indent=2, ensure_ascii=False), encoding="utf-8")

    print("\n🛡️ SECURITY (check básico)")
    print(f"- Log: {out_json}")
    print(f"- RDP : {sec.get('RDP')}")
    print(f"- SMB1: {sec.get('SMB1')}")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="eos",
        description="EOS – EduOps Suite (Windows 10/11) | Diagnóstico + Fixpack + Seguridad + DIFF",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("scan", help="Scan (JSON + HTML)").set_defaults(func=cmd_scan)

    d = sub.add_parser("diff", help="Comparar dos scans JSON y generar reporte de cambios")
    d.add_argument("old", help="Ruta al JSON antiguo")
    d.add_argument("new", help="Ruta al JSON nuevo")
    d.set_defaults(func=cmd_diff)

    s_fix = sub.add_parser("fix", help="Fixpack helpdesk (dry-run por defecto)")
    s_fix.add_argument("--apply", action="store_true", help="Aplicar cambios (requiere admin para varias acciones)")
    s_fix.set_defaults(func=cmd_fix)

    sub.add_parser("secure", help="Chequeo de seguridad básico").set_defaults(func=cmd_secure)

    return p


def main() -> int:
    if os.name != "nt":
        print("EOS está pensado para Windows 10/11.")
        return 2

    args = build_parser().parse_args()
    try:
        args.func(args)
        return 0
    except Exception as e:
        print("\n❌ ERROR:", e)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
