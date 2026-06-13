#!/usr/bin/env bash
# Dừng toàn bộ SOC AI pipeline
BASE_DIR="/opt/soc_ai"
PID_DIR="${BASE_DIR}/pids"

echo "[stop] Stopping SOC AI pipeline..."

for svc in ai_alert enricher dedup normalize; do
    PID_FILE="${PID_DIR}/${svc}.pid"
    if [[ -f "${PID_FILE}" ]]; then
        PID=$(cat "${PID_FILE}" 2>/dev/null || echo "")
        if [[ -n "${PID}" ]] && kill -0 "${PID}" 2>/dev/null; then
            kill -TERM "${PID}" && echo "[stop] Sent SIGTERM to ${svc} (pid=${PID})"
            # Chờ tối đa 5 giây để service tự shutdown gracefully
            for i in {1..5}; do
                sleep 1
                if ! kill -0 "${PID}" 2>/dev/null; then
                    echo "[stop] ${svc} stopped cleanly"
                    break
                fi
            done
            # Force kill nếu vẫn còn
            if kill -0 "${PID}" 2>/dev/null; then
                kill -9 "${PID}" && echo "[stop] Force killed ${svc}"
            fi
        else
            echo "[stop] ${svc} not running"
        fi
        rm -f "${PID_FILE}"
    else
        echo "[stop] ${svc}: no pid file"
    fi
done

echo "[stop] Done."