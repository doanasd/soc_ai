# 🚀 Hướng Dẫn Chạy Dự Án SOC-AI

## Tổng quan kiến trúc

Dự án gồm **2 service độc lập** chạy song song, giao tiếp qua 1 file queue dùng chung:

```
┌─────────────────────────────────────────────────────────────┐
│  NGUỒN LOG                                                    │
│  /var/ossec/logs/log_dedup.json  (Wazuh / SIEM output)       │
└──────────────────────┬──────────────────────────────────────┘
                       │ đọc file (tail)
                       ▼
┌─────────────────────────────────────────────────────────────┐
│  SERVICE 1: AI Alert  (d:\SOC-AI\SOC_AI\SOC_AI\AI_alert\)   │
│                                                               │
│  • Đọc log theo time-window 5 phút                           │
│  • Gọi Groq LLM để phân tích batch                          │
│  • Phát alert → Telegram                                      │
│  • Nếu alert nghiêm trọng → ghi vào queue file              │
└──────────────────────┬──────────────────────────────────────┘
                       │ ghi file
                       ▼
         📄 pending_investigations.jsonl
                       │ đọc file (polling 10s)
                       ▼
┌─────────────────────────────────────────────────────────────┐
│  SERVICE 2: Threat Hunter  (d:\SOC-AI\SOC_AI\SOC_AI\threat_hunter\) │
│                                                               │
│  • EVENT-DRIVEN: Xử lý alert từ queue ngay lập tức          │
│  • SCHEDULED: Hunt toàn bộ log mỗi 6 giờ                    │
│  • Dùng MCP → OpenSearch để query raw logs                   │
│  • Groq LLM ReAct agent để điều tra                         │
│  • Kết quả → hunt_findings.jsonl + Telegram                  │
└─────────────────────────────────────────────────────────────┘
                       │
                       ▼
         📡 OpenSearch MCP Server (http://10.10.10.20:9900/mcp/)
```

---

## Điều kiện tiên quyết

| Yêu cầu | Chi tiết |
|---------|---------|
| Python | >= 3.11 (dùng `slots=True` trong dataclass) |
| OpenSearch MCP Server | Chạy tại `http://10.10.10.20:9900/mcp/` |
| Groq API Key | Đã có sẵn trong `.env` |
| Telegram Bot | Đã config sẵn trong `.env` |
| Log source | File `log_dedup.json` (AI Alert đọc từ đây) |

---

## Bước 1: Cài đặt môi trường

### Service 1 — AI Alert

```powershell
# Di chuyển vào thư mục AI Alert
cd d:\SOC-AI\SOC_AI\SOC_AI\AI_alert

# Tạo virtual environment (nếu chưa có)
python -m venv .venv

# Kích hoạt venv
.\.venv\Scripts\Activate.ps1

# Cài dependencies
pip install -r requirements.txt
```

### Service 2 — Threat Hunter

```powershell
# Di chuyển vào thư mục Threat Hunter
cd d:\SOC-AI\SOC_AI\SOC_AI\threat_hunter

# Tạo virtual environment (nếu chưa có)
python -m venv .venv

# Kích hoạt venv
.\.venv\Scripts\Activate.ps1

# Cài dependencies
pip install -r requirements.txt
```

---

## Bước 2: Chuẩn bị thư mục data

```powershell
# Tạo thư mục data cho cả 2 service
mkdir d:\SOC-AI\SOC_AI\SOC_AI\AI_alert\data -ErrorAction SilentlyContinue
mkdir d:\SOC-AI\SOC_AI\SOC_AI\threat_hunter\data -ErrorAction SilentlyContinue
```

> **Quan trọng:** File queue `pending_investigations.jsonl` phải cùng đường dẫn mà cả 2 service trỏ tới.
> - AI Alert ghi vào: `../threat_hunter/data/pending_investigations.jsonl`
> - Threat Hunter đọc từ: `./data/pending_investigations.jsonl`

---

## Bước 3: Kiểm tra cấu hình `.env`

### AI Alert `.env` (d:\SOC-AI\SOC_AI\SOC_AI\AI_alert\.env)

```env
GROQ_API_KEY="gsk_..."              # API key Groq
LOG_INPUT_PATH=./log_dedup.json     # ⚠️ Đổi thành đường dẫn thực tế
GROQ_MODEL=openai/gpt-oss-120b
BATCH_WINDOW_SECONDS=300            # Gom log 5 phút mỗi batch
TELEGRAM_BOT_TOKEN=...
TELEGRAM_CHAT_ID=...
INVESTIGATION_QUEUE_PATH=../threat_hunter/data/pending_investigations.jsonl
```

### Threat Hunter `.env` (d:\SOC-AI\SOC_AI\SOC_AI\threat_hunter\.env)

```env
MCP_SERVER_URL=http://10.10.10.20:9900/mcp/
HUNT_GROQ_API_KEY=gsk_...
HUNT_GROQ_MODEL=llama3-70b-8192    # ⚠️ Xem ghi chú bên dưới
HUNT_INTERVAL_SECONDS=21600        # Hunt mỗi 6 giờ
INVESTIGATION_QUEUE_PATH=./data/pending_investigations.jsonl
TELEGRAM_BOT_TOKEN=...
TELEGRAM_CHAT_ID=...
```

> ⚠️ **`llama3-70b-8192` đang bị Groq deprecated!**  
> Đổi sang: `HUNT_GROQ_MODEL=llama-3.3-70b-versatile`

---

## Bước 4: Test import trước khi chạy

```powershell
# Test Threat Hunter
cd d:\SOC-AI\SOC_AI\SOC_AI\threat_hunter
.\.venv\Scripts\Activate.ps1
python test_imports.py
```

Output mong đợi:
```
[OK] config
[OK] models
[OK] mcp_client
...
=== ALL 11 MODULES IMPORTED AND TESTED SUCCESSFULLY ===
```

---

## Bước 5: Chạy các service

### Cách A — Chạy thủ công (2 terminal riêng biệt)

**Terminal 1 — Threat Hunter** (chạy trước):
```powershell
cd d:\SOC-AI\SOC_AI\SOC_AI\threat_hunter
.\.venv\Scripts\Activate.ps1
python -m app.main
```

**Terminal 2 — AI Alert**:
```powershell
cd d:\SOC-AI\SOC_AI\SOC_AI\AI_alert
.\.venv\Scripts\Activate.ps1
python -m app.main
```

### Cách B — Chạy bằng script PowerShell (tiện lợi hơn)

Tạo file `run_all.ps1` trong thư mục gốc:
```powershell
# Terminal 1: Threat Hunter
Start-Process powershell -ArgumentList "-NoExit", "-Command", `
  "cd d:\SOC-AI\SOC_AI\SOC_AI\threat_hunter; .\.venv\Scripts\Activate.ps1; python -m app.main"

# Terminal 2: AI Alert  
Start-Process powershell -ArgumentList "-NoExit", "-Command", `
  "cd d:\SOC-AI\SOC_AI\SOC_AI\AI_alert; .\.venv\Scripts\Activate.ps1; python -m app.main"
```

---

## Bước 6: Kiểm tra hoạt động

### Log mong đợi từ Threat Hunter khi khởi động:
```
🏹 Threat Hunter starting up (dual-mode)...
   MCP Server: http://10.10.10.20:9900/mcp/
   LLM Model: llama-3.3-70b-versatile
   Scheduled hunt: every 21600s (6h lookback)
   Investigation queue: ./data/pending_investigations.jsonl (poll every 10s)
🔌 Testing MCP connection to http://10.10.10.20:9900/mcp/ ...
✅ MCP connection successful!
🔄 Entering dual-mode loop (queue watch + scheduled hunt)...
🏹 SCHEDULED THREAT HUNT SESSION STARTED: hunt_20260525_...
```

### Log mong đợi từ AI Alert:
```
Starting AI Alert service...
Watching log file: ./log_dedup.json
Waiting for logs (batch window: 300s)...
```

---

## Luồng hoạt động đầy đủ

```
1. AI Alert đọc log_dedup.json (tail, real-time)
   ↓
2. Gom log theo window 5 phút → batch
   ↓
3. Gọi Groq LLM phân tích batch → có alert không?
   ↓ (nếu có alert)
4. Gửi alert → Telegram
5. Ghi investigation request → pending_investigations.jsonl
   ↓
6. Threat Hunter poll queue (mỗi 10s) → đọc request
   ↓
7. Threat Hunter chuyển alert → HuntHypothesis
   ↓
8. HuntAnalyzer chạy ReAct loop (tối đa 3 iteration):
   - Gọi Groq LLM: "cần query gì?"
   - Execute query → MCP OpenSearch
   - Feed kết quả lại cho LLM
   - LLM kết luận: confirmed/suspicious/dismissed
   ↓
9. Lưu HuntFinding → hunt_findings.jsonl
10. Gửi báo cáo chi tiết → Telegram
```

---

## Troubleshooting

| Lỗi | Nguyên nhân | Giải pháp |
|-----|------------|-----------|
| `MCP connection failed` | OpenSearch MCP server không chạy | Kiểm tra `http://10.10.10.20:9900/mcp/` |
| `GROQ_API_KEY not configured` | Thiếu key trong `.env` | Thêm `HUNT_GROQ_API_KEY=...` vào threat_hunter/.env |
| `No logs found` | File log không tồn tại hoặc sai path | Kiểm tra `LOG_INPUT_PATH` trong AI_alert/.env |
| `ModuleNotFoundError` | Chưa cài requirements | Chạy `pip install -r requirements.txt` |
| `Investigation loop` giữ đọc lại | Bug offset (đã fix) | Pull code mới nhất |
| Model deprecated | `llama3-70b-8192` không còn | Đổi sang `llama-3.3-70b-versatile` |

---

## Output files

| File | Nội dung |
|------|---------|
| `AI_alert/data/alerts.jsonl` | Tất cả alerts do AI phát hiện |
| `threat_hunter/data/hunt_findings.jsonl` | Kết quả điều tra từ Threat Hunter |
| `threat_hunter/data/baseline.json` | Baseline lưu lịch sử volume log |
| `threat_hunter/data/pending_investigations.jsonl` | Queue bridge giữa 2 service |
| `AI_alert/data/model_usage_costs.txt` | Báo cáo chi phí Groq API |
