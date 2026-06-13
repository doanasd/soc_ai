# SOC-AI: Hệ thống phân tích log bảo mật bằng AI

## Tổng quan

SOC-AI là một pipeline xử lý log bảo mật end-to-end, biến log thô từ Wazuh SIEM thành alert có cấu trúc thông qua phân tích bằng LLM (Large Language Model). Thay vì alert từng event đơn lẻ gây nhiễu, hệ thống gom log theo cụm thời gian, tóm tắt hành vi tổng thể, rồi để AI đánh giá và quyết định có cần alert hay không.

**Luồng chính:**

```
Wazuh archives.json
    → normalize-service.py → log_normalized.json
        → dedup-service.py → log_dedup.json
            → [malicious-enricher.py → log_enriched.json] (tùy chọn)
                → AI_alert/app/main.py → alerts.jsonl / stdout / Telegram
```

---

## Kiến trúc Pipeline

### Bước 1: Chuẩn hóa log (`normalize-service.py`)

**Mục đích:** Đọc file archive của Wazuh (`/var/ossec/logs/archives/archives.json`) theo kiểu `tail -f` và chuẩn hóa mỗi event về một JSON schema thống nhất.

**Các loại log được hỗ trợ:**

| Loại log | Nhận diện bằng | Field đặc trưng |
|---|---|---|
| AWS WAF | Location prefix `/tmp/aws-waf/waf/` hoặc field `httpRequest` + `action` | `waf.*` (uri, headers, rule, ja3/ja4) |
| AWS VPC Flow | Location prefix `/tmp/aws-waf/vpc/` hoặc `type == "aws_vpc_flow"` | `flow.*` (packets, bytes, interface) |
| Windows Event | Field `win` trong `data` hoặc `full_log` | `winEvent.*` (eventID, logonType, process) |
| Linux Syslog | Location `/var/log/*`, decoder name (sshd, sudo, pam...), agent OS, rule groups | `linuxEvent.*` (program, user, ruleID, ruleGroups) |

**Schema chuẩn hóa chung:**

```json
{
  "time": "...",
  "log_type": "waf | vpc | win | linux",
  "vendor": "aws | Microsoft | Linux",
  "action": "...",
  "outcome": "allowed | blocked | unknown",
  "asset_host": "...",
  "correlation_id": "...",
  "network": {
    "source_ip": "...",
    "destination_ip": "...",
    "source_port": null,
    "destination_port": null,
    "protocol": "...",
    "method": "..."
  },
  "message": "...",
  "maliciousIP": null
}
```

**Cơ chế hoạt động:**
- Hàm `follow_file()` đọc file liên tục theo chunk 4096 bytes, chỉ yield dòng hoàn chỉnh.
- Tự phát hiện file rotation (inode thay đổi) và file truncate (size < offset hiện tại).
- Lần mở đầu tiên seek đến cuối file (chỉ xử lý log mới).

**Đầu ra:** `/var/ossec/logs/log_normalized.json` (JSON Lines)

---

### Bước 2: Gộp log trùng lặp (`dedup-service.py`)

**Mục đích:** Gom các log có cùng đặc điểm trong một khoảng thời gian (`WINDOW_SECONDS = 60s`) thành một bản ghi tổng hợp, giảm khối lượng log đáng kể.

**Cơ chế grouping key:**

- **WAF:** `waf|source_ip|destination_ip|host_header|uri|method|rule_id|action`
- **VPC:** `vpc|interface_id|source_ip|destination_ip|destination_port|protocol|action`
- **Linux:** `linux|source_ip|hostname|action|program|user|rule_id`
- **Windows:** `win|hostname|source_ip|eventID|target_user|action`

**Cơ chế hoạt động:**
- Duy trì cache in-memory (tối đa `MAX_CACHE_SIZE = 50000` entry).
- Mỗi entry trong cache lưu: count, first_seen, last_seen, sample event.
- Flush entry ra file khi `last_update_wallclock` vượt quá `WINDOW_SECONDS`.
- Nếu cache đầy → evict entry cũ nhất (ghi ra output trước khi xóa).
- Lưu offset đọc file vào `/var/ossec/logs/.dedup_offset` để resume khi restart.
- Khi nhận signal SIGINT/SIGTERM → flush toàn bộ cache rồi thoát.

**Schema đầu ra:**

```json
{
  "log_type": "waf",
  "group_key": "waf|1.2.3.4|example.com|/api|GET|rule-1|block",
  "aggregation": {
    "count": 150,
    "window_seconds": 60,
    "first_seen": 1715000000.0,
    "last_seen": 1715000059.0,
    "duration_seconds": 59.0,
    "rate_per_sec": 2.54
  },
  "sample_event": { "...normalized event..." }
}
```

**Đầu ra:** `/var/ossec/logs/log_dedup.json`

---

### Bước 3: Làm giàu thông tin IP độc hại (`malicious-enricher.py`) — Tùy chọn

**Mục đích:** So khớp `source_ip` của mỗi event với danh sách IP xấu từ AbuseIPDB, thêm `confidence_score` vào event nếu match.

**Cơ chế:**
- Đọc file `/var/script/malicious_ips.txt` (format: `IP SCORE`).
- Reload danh sách mỗi 30 giây.
- Nếu IP match → gắn `maliciousIP: { confidence_score, source: "abuseipdb" }`.
- Theo dõi file `log_dedup.json` kiểu `tail -f`, ghi ra `log_enriched.json`.

> **Lưu ý:** Bước này chưa được nối mặc định vào pipeline. `AI_alert` hiện đọc trực tiếp từ `log_dedup.json`.

---

### Bước 4: Phân tích bằng AI và sinh alert (`AI_alert/`)

Đây là phần cốt lõi của dự án. Service này hoạt động như một **SOC analyst ảo**: nhìn vào bản tóm tắt cửa sổ thời gian và quyết định có cần phát alert hay không.

---

## Chi tiết kiến trúc AI_alert

### Sơ đồ luồng xử lý

```
log_dedup.json
    ↓
[LogFollower] ─ tail -F, xử lý rotation/truncate
    ↓
[EventBatcher] ─ gom event theo time window (mặc định 300s)
    ↓
[AlertEngine]
    ├── build_window_summary() ─ tính thống kê cửa sổ
    ├── WindowCorrelationTracker ─ thêm tương quan lịch sử
    ├── ContextLoader ─ nạp context SOC từ markdown
    ├── PromptBuilder ─ dựng prompt cho LLM
    ├── GroqClient ─ gọi API Groq
    ├── parse_model_analysis() ─ parse JSON phản hồi
    └── Duplicate suppression ─ chống alert trùng theo dedup_key
    ↓
[Writers]
    ├── jsonl_writer → alerts.jsonl
    ├── stdout_writer → console
    └── telegram_writer → Telegram bot
```

### Các module chính

#### `app/main.py` — Entry point

Khởi tạo tất cả dependency và chạy main loop:
1. Đọc từng entry từ `LogFollower`.
2. Đưa vào `EventBatcher` → flush khi hết cửa sổ hoặc idle timeout.
3. Gửi batch cho `AlertEngine.process_batch()`.
4. Nếu có alert → ghi file, in console, gửi Telegram.
5. Nếu batch lỗi → đưa vào `FailedBatchQueue` để retry.
6. Định kỳ gửi status summary khi không có alert (qua Telegram).

#### `app/reader.py` — LogFollower

Theo dõi file JSONL đầu vào giống `tail -F`:
- Xử lý file chưa tồn tại (chờ file xuất hiện).
- Phát hiện log rotation (inode thay đổi).
- Phát hiện file truncate.
- Chỉ yield dòng hoàn chỉnh, không yield partial line.
- Hỗ trợ `start_position`: `beginning` (đọc từ đầu) hoặc `end` (chỉ đọc log mới).

#### `app/batching.py` — EventBatcher & Window Summary

**EventBatcher:**
- Gom event theo cửa sổ thời gian cố định (mặc định 300s = 5 phút).
- Flush khi: cửa sổ hết hạn, idle timeout, window rollover, hoặc shutdown.

**`build_window_summary()`** — Tạo bản tóm tắt cửa sổ cho LLM:

```json
{
  "window": { "start", "end", "event_count", "aggregated_record_count" },
  "dominant_log_type": "waf",
  "dominant_action": "block",
  "log_type_counts": { "waf": 150, "vpc": 20 },
  "action_counts": { "block": 120, "allow": 50 },
  "top_source_ips": [{ "ip": "1.2.3.4", "count": 80 }],
  "top_destination_ips": [{ "ip": "10.0.0.1", "count": 100 }],
  "top_groups": [ "... top 12 nhóm theo count ..." ],
  "notable_patterns": {
    "external_to_private_sensitive": [ "... IP public → IP private trên port nhạy cảm ..." ]
  }
}
```

**Port nhạy cảm được theo dõi:** 22, 2222, 3306, 5432, 6379, 9200, 10022

#### `app/window_history.py` — WindowCorrelationTracker

Theo dõi tương quan giữa các cửa sổ trong khoảng lookback (mặc định 3600s = 1 giờ):
- Đếm số cửa sổ matching.
- Tính streak liên tiếp.
- Đánh giá severity signal:
  - `isolated_single_window` — cửa sổ đơn lẻ
  - `short_recurrence` — lặp lại ngắn
  - `recurring_multi_window` — lặp lại nhiều cửa sổ
  - `sustained_multi_window` — kéo dài bền vững
  - `near_continuous_last_hour` — gần như liên tục trong 1 giờ

Kết quả correlation được chèn vào `window_summary["historical_correlation"]` để LLM đánh giá xu hướng.

#### `app/context_loader.py` — ContextLoader

Nạp các file Markdown trong thư mục `context/` làm tri thức vận hành cho LLM:

| File | Nội dung |
|---|---|
| `01_environment.md` | Mô tả hạ tầng, asset, IP authorized, baseline traffic |
| `02_detection_policy.md` | Chính sách phát hiện, ngưỡng alert |
| `03_asset_criticality.md` | Mức độ quan trọng của từng asset |
| `04_known_benign_patterns.md` | Pattern lành tính đã biết (giảm false positive) |
| `05_response_playbooks.md` | Quy trình xử lý sự cố |
| `06_output_schema.md` | Schema JSON mà LLM phải tuân theo |

**Đặc điểm:**
- Cache theo `mtime` → sửa file trên đĩa sẽ tự động áp dụng cho lần phân tích tiếp.
- Chọn doc phù hợp theo loại event (ví dụ: WAF event → ưu tiên `known_benign_patterns`).
- Giới hạn tổng ký tự context (`MAX_CONTEXT_CHARS`, mặc định 20000).

#### `app/prompt_builder.py` — Prompt Builder

Tạo prompt cho 3 tình huống:
1. **Single event analysis** — phân tích một event đơn lẻ.
2. **Window analysis** — phân tích cả cửa sổ thời gian (dùng chính).
3. **Status summary** — đánh giá khoảng thời gian không có alert.

**Quy tắc trong prompt:**
- Ưu tiên alert chất lượng cao, tránh noisy.
- Không bịa bằng chứng không có trong dữ liệu.
- Phân biệt internet noise với mối đe dọa thực.
- VPC Flow: ưu tiên destination port, không suy luận từ source port.
- WAF blocked đơn lẻ → low severity; lặp lại nhiều window → medium; DDoS-style → high.

**Hỗ trợ model đặc biệt:** Với model `openai/gpt-oss-*` → gộp system prompt vào user message, hỗ trợ strict JSON schema.

#### `app/groq_client.py` — Groq API Client

- Gọi Groq API qua `httpx` với endpoint `/chat/completions`.
- Retry với exponential backoff (mặc định 3 lần).
- Fallback từ `json_schema` sang `json_object` nếu model không hỗ trợ strict schema.
- Theo dõi token usage và chi phí qua `ModelCostTracker`.

#### `app/analyzer.py` — Analyzer (Orchestrator)

Kết nối tất cả module lại:
1. Lấy representative event từ batch.
2. Build context markdown từ ContextLoader.
3. Build window summary + historical correlation.
4. Build prompt messages.
5. Gọi Groq API.
6. Parse JSON response → `ModelAnalysis`.
7. Nếu `should_alert = true` → tạo `Alert` object.

#### `app/alert_engine.py` — AlertEngine

Thêm logic local trước khi phát alert:
- Chèn `historical_correlation` vào window summary.
- **Duplicate suppression**: suppress alert trùng theo `dedup_key` trong TTL (mặc định 300s).
- Ghi lại window vào `WindowCorrelationTracker` sau mỗi lần phân tích thành công.

#### `app/models.py` — Data Models (Pydantic)

| Model | Mô tả |
|---|---|
| `Event` | Event đầu vào, tự flatten `sample_event.network.*` |
| `ModelAnalysis` | Kết quả phân tích từ LLM (should_alert, severity, confidence, ...) |
| `Alert` | Alert hoàn chỉnh (event + analysis + usage) |
| `ModelUsage` | Thống kê token và chi phí |
| `BatchAnalysisResult` | Kết quả phân tích batch (outcome: alert/no_alert/error) |
| `GroqRequest/Response` | Schema request/response cho Groq API |

#### `app/retry_queue.py` — FailedBatchQueue

- Lưu batch phân tích lỗi vào file spool (`failed_batches.jsonl`).
- Retry theo exponential backoff.
- Tối đa `max_attempts` (mặc định 8 lần).
- Drop batch nếu vượt quá số lần retry.

#### `app/status_reporter.py` — NoAlertStatusReporter

- Theo dõi khoảng thời gian không có alert.
- Mỗi `NO_ALERT_SUMMARY_INTERVAL_SECONDS` (mặc định 3600s = 1 giờ) → tạo summary.
- Summary gồm: số batch đã xử lý, thống kê log type, LLM usage, chi phí.
- Gửi qua Telegram để SOC team biết hệ thống vẫn hoạt động.

#### `app/cost_tracker.py` — ModelCostTracker

- Ghi nhận mỗi lần gọi LLM: token usage, chi phí, status.
- Tính chi phí theo model pricing (input/cached/output per million tokens).
- Ghi log ra file `model_usage_costs.txt`.
- Cung cấp daily summary cho báo cáo.

#### `app/writers/` — Output Writers

| Writer | Chức năng |
|---|---|
| `jsonl_writer.py` | Ghi alert xuống file JSONL (`alerts.jsonl`) |
| `stdout_writer.py` | In alert rút gọn ra console |
| `telegram_writer.py` | Gửi alert và status summary qua Telegram bot |

---

## Schema Alert đầu ra

Khi LLM trả về `should_alert = true`, hệ thống tạo alert với các trường:

```json
{
  "event": { "...window_summary..." },
  "analysis": {
    "should_alert": true,
    "severity": "high",
    "confidence": 85,
    "category": "brute_force",
    "title": "Sustained SSH brute force from external IP",
    "summary": "...",
    "reasoning": "...",
    "recommended_actions": ["Block source IP", "Check auth logs"],
    "dedup_key": "ssh_brute_1.2.3.4_10.0.0.1"
  },
  "usage": { "...token & cost info..." },
  "created_at": "2026-05-11T10:00:00Z"
}
```

---

## Cấu hình

Cấu hình qua biến môi trường hoặc file `.env`:

| Biến | Mặc định | Mô tả |
|---|---|---|
| `LOG_INPUT_PATH` | `./log_dedup.json` | File đầu vào |
| `ALERT_OUTPUT_PATH` | `./data/alerts.jsonl` | File output alert |
| `CONTEXT_DIR` | `./context` | Thư mục context markdown |
| `GROQ_API_KEY` | — | API key cho Groq |
| `GROQ_MODEL` | `llama-3.1-70b-versatile` | Model LLM |
| `BATCH_WINDOW_SECONDS` | `300` | Độ dài cửa sổ batch (giây) |
| `BATCH_IDLE_TIMEOUT_SECONDS` | `120` | Flush khi idle quá lâu |
| `ALERT_SUPPRESSION_TTL_SECONDS` | `300` | TTL suppress alert trùng |
| `CORRELATION_LOOKBACK_SECONDS` | `3600` | Lookback cho tương quan lịch sử |
| `NO_ALERT_SUMMARY_INTERVAL_SECONDS` | `3600` | Chu kỳ gửi status summary |
| `MAX_CONTEXT_CHARS` | `20000` | Giới hạn context cho prompt |
| `TELEGRAM_BOT_TOKEN` | — | Token bot Telegram |
| `TELEGRAM_CHAT_ID` | — | Chat ID nhận thông báo |

---

## Cách chạy

### Chạy các service tiền xử lý (trên Wazuh server)

```bash
# Bước 1: Chuẩn hóa log
python3 normalize-service.py

# Bước 2: Dedup
python3 dedup-service.py

# Bước 3 (tùy chọn): Enrich IP
python3 malicious-enricher.py
```

### Chạy AI Alert service

```bash
cd AI_alert
python -m venv .venv
.venv\Scripts\activate        # Windows
# source .venv/bin/activate   # Linux
pip install -r requirements.txt

# Cấu hình .env
python -m app.main
```

### Chạy test

```bash
cd AI_alert
pytest
```

---

## Điểm mạnh

- **Giảm noise hiệu quả**: Batch + dedup + AI triage → chỉ alert khi thực sự cần thiết.
- **Context-driven**: Tri thức SOC nằm trong file Markdown, dễ cập nhật mà không sửa code.
- **Historical correlation**: Phát hiện hành vi kéo dài qua nhiều cửa sổ thời gian.
- **Chống alert trùng**: Duplicate suppression theo `dedup_key` + TTL.
- **Fault tolerant**: Retry queue cho batch lỗi, graceful shutdown, offset persistence.
- **Cost tracking**: Theo dõi chi phí LLM theo từng lần gọi và theo ngày.
- **Multi-output**: Hỗ trợ file, console, và Telegram cùng lúc.

## Giới hạn hiện tại

- **Chất lượng phụ thuộc context**: Alert tốt hay không phụ thuộc vào chất lượng file context và prompt.
- **Enricher chưa nối**: `malicious-enricher.py` chưa được tích hợp mặc định vào pipeline.
- **Summary có thể bỏ sót**: Batch summary chỉ giữ top groups — event hiếm nhưng nguy hiểm có thể bị bỏ qua.
- **LLM không hoàn hảo**: Vẫn có thể đánh giá sai, bỏ sót, hoặc reasoning chưa đủ chắc.
- **Dữ liệu ra ngoài**: Log được gửi qua Groq API → cần cân nhắc chính sách bảo mật dữ liệu.

## Hướng mở rộng

- Thêm nguồn log (firewall, IDS/IPS).
- Thêm context SOC cho Linux event (SSH brute-force policy, sudo abuse, user management).
- Bổ sung output (Slack, webhook, email, SOAR).
- Correlation theo asset, user, hoặc campaign.
- Thêm rule local trước LLM để giảm chi phí API.
- Nối bước enrich threat intel vào pipeline chính.
- Mở rộng dedup cho Windows event.
