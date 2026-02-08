# EOS – EduOps Suite (Windows 10/11)

Herramienta híbrida **Python + PowerShell** para **inventario**, **diagnóstico**, **chequeo básico de seguridad**, **fixpack** (opcional) y **DIFF** entre scans. Pensada para **helpdesk**, **técnicos** y **docentes** (laboratorios reales).

## ✅ Qué hace
- `scan`: genera **JSON + HTML** (y PDF opcional) con:
  - Inventario (HW/OS, disco, red, hotfix)
  - Diagnóstico (ping, servicios básicos, top CPU)
  - Seguridad básica (Firewall, RDP, SMBv1, Defender, BitLocker si aplica)
- `diff`: compara dos scans y crea un **reporte de cambios** (JSON + HTML)
- `fix`: propone acciones tipo helpdesk (dry-run por defecto; `--apply` opcional)

> ⚠️ Privacidad: los informes pueden incluir datos sensibles (IP, nombre de equipo, software).  
> **Nunca subas `output/` a GitHub**.

## 📦 Requisitos
- Windows 10/11
- Python 3.x instalado
- PowerShell (incluido en Windows)

PDF opcional:
- `reportlab` (si quieres PDF)

## 🚀 Instalación rápida
Clona el repo y entra a la carpeta:

```powershell
git clone <TU_REPO_URL>
cd EOS

(Optativo) PDF:
python -m pip install -r requirements.txt

▶️ Uso
1) Scan (genera output)
python eos.py scan
2) Diff (compara dos JSON)
python eos.py diff ".\output\eos_YYYYMMDD_HHMMSS.json" ".\output\eos_YYYYMMDD_HHMMSS.json"
3) Fixpack (dry-run)
python eos.py fix
Aplicar cambios (requiere admin para varias acciones):
python eos.py fix --apply
