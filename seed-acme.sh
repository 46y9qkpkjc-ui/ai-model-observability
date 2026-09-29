#!/usr/bin/env bash
# seed-acme.sh — drop demo asset files (MNPI / regulated / OT-IoT / core IP)
# where the workspace observability agent scans (~/AcmeDocs, depth <= 3).
#
#   ./seed-acme.sh            # all classes (good for the shared dev box)
#   ./seed-acme.sh ceo        # james.collins  — board/deal/treasury (MNPI)
#   ./seed-acme.sh cto        # jonathan.lim   — OT/IoT + source/model (core IP)
#   ./seed-acme.sh ops        # neha.choudhry  — clinical/claims (regulated)
#   ./seed-acme.sh --home DIR # seed a different user's home (run as root/sudo)
set -euo pipefail

ROLE='all'
HOME_DIR="${HOME:-~}"
while [ $# -gt 0 ]; do
  case "$1" in
    --home) HOME_DIR="$2"; shift 2 ;;
    ceo|cto|ops|all) ROLE="$1"; shift ;;
    *) echo "unknown arg: $1" >&2; exit 1 ;;
  esac
done

ROOT="$HOME_DIR/AcmeDocs"
mkdir -p "$ROOT"
put() { # put <path> <<EOF ... EOF  (path relative to ROOT)
  mkdir -p "$ROOT/$(dirname "$1")"
  cat > "$ROOT/$1"
}

MNPI_SEEDS() {
put 'board/Q3_earnings_draft.csv' <<'EOF'
quarter,metric,actual_forecast,consensus,delta,status
Q3,revenue_usd_m,412.8,391.0,+5.6%,DRAFT-NDA
Q3,gross_margin_pct,71.2,69.8,+1.4pp,DRAFT-NDA
Q3,ebitda_usd_m,88.4,74.1,+19.3%,BOARD-CONFIDENTIAL
EOF
put 'board/board_deck_unannounced.docx' <<'EOF'
ACME Corp — Board Deck (UNANNOUNCED)
Item 4: strategic alternatives review
- Project Meridian: LOI signed, exclusivity until 15 Dec
- Do NOT distribute outside the board (NDA on file)
EOF
put 'deal/mna_pipeline.csv' <<'EOF'
target,sector,stage,indicative_value_usd_m,owner
Helio Robotics,industrial automation,LOI signed,780,james.collins
Nimbus Health,clinical data,exclusive talks,410,james.collins
Beacon IoT,device telemetry,dd complete,265,cfo.office
EOF
put 'deal/term_sheet_confidential.pdf' <<'EOF'
CONFIDENTIAL TERM SHEET — Project Meridian
Acquirer: ACME Corp. Target: Helio Robotics
Equity value: USD 780,000,000. Exclusivity: 45 days.
EOF
put 'finance/treasury_forecast.xlsx' <<'EOF'
month,cash_in_m,cash_out_m,net_m
Oct,54.2,49.8,4.4
Nov,61.0,52.3,8.7
Dec,88.5,57.1,31.4
EOF
put 'finance/compensation_bands_confidential.csv' <<'EOF'
band,title,base_usd,bonus_pct,equity_usd
E1,Chief Executive,720000,40,1800000
E2,Chief Technology,560000,30,950000
M6,VP Engineering,385000,25,420000
EOF
}

REGULATED_SEEDS() {
put 'clinical/PHASE3_trial_results.csv' <<'EOF'
site,arm,n,endpoint_rate,ae_grade3_pct,p_value
01,drug,142,68.3,4.2,0.004
02,drug,137,66.1,5.1,0.007
03,placebo,140,41.4,4.0,
EOF
put 'clinical/patient_phi_export.csv' <<'EOF'
mrn_hash,site,age_band,sex,outcome
a91f..c2,01,50-59,F,responder
77b0..1e,02,60-69,M,responder
c4d2..90,03,40-49,F,non-responder
EOF
put 'insurance/claims_phi_export.csv' <<'EOF'
claim_id,member_hash,provider,dx_code,billed_usd,status
CLM-88214,9f2a..31,Meridian Clinic,J44.1,14820,adjudicated
CLM-88230,1b77..ce,Northside Lab,C80.9,9640,pending-review
EOF
put 'insurance/underwriting_guidelines.pdf' <<'EOF'
ACME Underwriting — regulated policy extract
Pre-existing conditions: manual review, do not auto-decline.
Regulator reference: gov_sg circular 14/2025.
EOF
}

OT_SEEDS() {
put 'ot/plc_gateway.cfg' <<'EOF'
[gateway]
vendor=siemens
model=scada-rtu-4400
protocol=modbus-tcp
poll_ms=250
firmware=4.1.2-legacy
EOF
put 'ot/scada_hmi_layout.cfg' <<'EOF'
[screens]
plant_overview=1
boiler_room=2
conveyor_line_b=3
[alarm_poll_s]=5
EOF
put 'ot/modbus_registers.yaml' <<'EOF'
registers:
  - addr: 40001
    name: pump_1_status
    type: holding
  - addr: 40110
    name: boiler_setpoint
    type: holding
EOF
put 'iot/device_registry.json' <<'EOF'
{
  "devices": [
    {"id": "cam-lobby-01", "type": "nvr-camera", "ip": "10.40.7.11", "fw": "2.3.1"},
    {"id": "rtu-line-b", "type": "plc-gateway", "ip": "10.40.9.4", "fw": "4.1.2"}
  ]
}
EOF
put 'iot/camera_nvr_config.ini' <<'EOF'
[nvr]
model=vault-16ch
rtsp_user=admin
retention_days=30
[router-edge]
model=palo-alto-3220
EOF
}

CORE_SEEDS() {
put 'src/source_code_backup.sql' <<'EOF'
CREATE TABLE inference_log (id BIGINT PRIMARY KEY, model_ver TEXT, features JSONB);
INSERT INTO inference_log VALUES (1, 'fraud-gbdt-17', '{"score": 0.82}');
EOF
put 'research/model_registry.json' <<'EOF'
{
  "models": [
    {"name": "fraud-gbdt", "version": 17, "stage": "production", "artifact": "s3://ml/model-17.bin"},
    {"name": "churn-xgb", "version": 4, "stage": "staging", "artifact": "s3://ml/churn-4.bin"}
  ]
}
EOF
put 'research/patent_formulas.docx' <<'EOF'
ACME proprietary — patent pending 17/221,445
Ensemble drift correction: w_t = w_{t-1} * (1 - lr * grad(log_psi))
Trade secret — do not disclose outside research.
EOF
}

case "$ROLE" in
  ceo)  MNPI_SEEDS ;;
  cto)  OT_SEEDS; CORE_SEEDS ;;
  ops)  REGULATED_SEEDS ;;
  all)  MNPI_SEEDS; REGULATED_SEEDS; OT_SEEDS; CORE_SEEDS ;;
esac

# shared scenery (all personas) — field observations from DConnect deployments
put 'field/field_trip_observations.csv' <<'EOF'
date,site,engineer,notes
2025-09-02,Plant-14,neha.choudhry,rtu firmware drift observed
2025-09-09,Clinic-03,neha.choudhry,claims export runbook updated
EOF

echo "seed-acme: role=$ROLE -> $ROOT"
find "$ROOT" -type f | sed "s|^$HOME_DIR|~|"
