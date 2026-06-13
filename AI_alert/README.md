# AI Alert

`AI_alert` là service phân tích log bảo mật theo thời gian thực bằng LLM. Dự án này không đọc log thô trực tiếp từ SIEM rồi alert ngay từng dòng, mà đi theo hướng:

1. Chuẩn hóa log từ nhiều nguồn về một schema chung.
2. Gộp các log giống nhau thành bản ghi tổng hợp.
3. Gom các bản ghi trong một cửa sổ thời gian.
4. Gửi phần tóm tắt cửa sổ đó cùng ngữ cảnh SOC cho mô hình Groq/LLM.
5. Sinh alert có cấu trúc, chống lặp, ghi file, in console và có thể gửi Telegram.

Mục tiêu của dự án là giảm nhiễu, giữ lại ngữ cảnh vận hành, và để mô hình đánh giá theo cụm hành vi thay vì từng event rời rạc.

## 1. Pipeline tổng thể của repo

Repo hiện tại gồm nhiều bước xử lý nối tiếp nhau:

### Bước 1: Chuẩn hóa log

File gốc: `normalize-service.py`

Script này tail file Wazuh archive và chuẩn hóa log về JSON thống nhất. Hiện tại có xử lý cho:

- AWS WAF
- AWS VPC Flow - tính năng cho phép lưu lại thông tin về lượng dữ liệu IP đi vào và đi ra khỏi interface mạng trong VPC.
- Windows Event
- Linux Syslog (SSH, sudo, PAM, cron, systemd, iptables/nftables, audit, user management)

Đầu ra là `log_normalized.json`.

### Bước 2: Dedup / aggregate

File gốc: `dedup-service.py`

Script này đọc `log_normalized.json`, gom các log giống nhau trong một khoảng thời gian ngắn và ghi ra `log_dedup.json`. Mỗi dòng output không còn là một event đơn nữa mà là:

- `group_key`: khóa nhóm
- `aggregation`: số lượng, thời gian đầu/cuối, tốc độ
- `sample_event`: một event đại diện

Điểm quan trọng:

- Bước dedup build key cho `waf`, `vpc`, `linux` và `win`.
- Tất cả các loại log đã normalize đều được chuyển tiếp qua `log_dedup.json`.

### Bước 3: Enrich IP độc hại

File gốc: `malicious-enricher.py`

Script này là bước bổ sung tùy chọn. Nó đọc `log_dedup.json`, so khớp IP nguồn với danh sách IP xấu và ghi ra `log_enriched.json`.

Hiện tại `AI_alert` mặc định đọc `log_dedup.json`, nên bước enrich chưa được nối mặc định vào luồng chính.

### Bước 4: Phân tích bằng LLM và sinh alert

Thư mục chính: `AI_alert/`

Service trong `AI_alert` theo dõi file JSONL đầu vào, gom event theo cửa sổ thời gian, tạo summary, nạp tài liệu ngữ cảnh trong `context/`, gọi Groq API và xuất alert có cấu trúc.

## 2. `AI_alert` làm gì

`AI_alert` là tầng phân tích thông minh ở cuối pipeline. Thay vì đánh giá từng event, service này:

- tail file đầu vào kiểu `tail -F`
- gom nhiều event thành một `WindowBatch`
- tính thống kê như:
  - loại log chiếm ưu thế
  - action phổ biến
  - top source IP / destination IP
  - nhóm hành vi nổi bật
  - pattern đáng chú ý như external -> private trên cổng nhạy cảm
- thêm tương quan lịch sử giữa các cửa sổ gần nhau
- dựng prompt với policy và playbook SOC
- yêu cầu LLM trả về JSON đúng schema
- quyết định có alert hay không

Như một SOC analyst ảo -> nhìn vào bản tóm tắt và quyết định xem có alert hay không.

Nếu model trả về `should_alert = true`, hệ thống tạo alert với các trường như:

- `severity`
- `confidence`
- `category`
- `title`
- `summary`
- `reasoning`
- `recommended_actions`
- `dedup_key`

## 3. Kiến trúc thư mục `AI_alert`

### `app/main.py`

Entry point của service. File này khởi tạo toàn bộ dependency và chạy loop chính:

- đọc log
- batch event
- gọi analyzer
- suppress alert trùng
- retry batch lỗi
- gửi status định kỳ khi không có alert

### `app/config.py`

Nạp cấu hình từ biến môi trường hoặc `.env`.

### `app/reader.py`

`LogFollower` theo dõi file JSONL giống `tail -F`, có xử lý:

- file chưa tồn tại
- log rotation
- file bị truncate
- partial line

### `app/batching.py`

Đây là phần rất quan trọng của dự án.

Module này:

- gom event theo `batch_window_seconds`
- flush khi hết cửa sổ
- flush khi idle quá lâu
- tạo `window_summary` dùng làm input cho LLM

Summary không chỉ đếm số event mà còn tính `aggregated_record_count`, tức tổng số bản ghi thật phía sau các event đã dedup.

### `app/window_history.py`

Theo dõi tương quan giữa nhiều cửa sổ trước đó để phát hiện hành vi lặp lại hoặc kéo dài. Kết quả correlation được chèn vào prompt để model đánh giá theo xu hướng thay vì nhìn một cửa sổ đơn lẻ.

### `app/context_loader.py`

Nạp các file Markdown trong `context/` và chọn tài liệu phù hợp với từng event hoặc từng cửa sổ:

- môi trường hệ thống
- detection policy
- asset criticality
- benign pattern
- response playbook
- output schema

Các file này được cache theo `mtime`, nên sửa file context trên đĩa sẽ được áp dụng tự động cho những lần phân tích tiếp theo.

### `app/prompt_builder.py`

Tạo prompt hệ thống và prompt người dùng cho hai tình huống:

- phân tích batch/window
- phân tích status summary khi không có alert

Mục tiêu là ép model trả JSON đúng schema và không bịa thêm bằng chứng.

### `app/groq_client.py`

Client gọi Groq API bằng `httpx`, có timeout, retry, thống kê token và chi phí.

### `app/analyzer.py`

Là tầng orchestration:

- build context
- build prompt
- gọi model
- parse JSON trả về
- chuyển kết quả sang `BatchAnalysisResult` hoặc `Alert`

### `app/alert_engine.py`

Áp dụng logic local trước khi phát alert:

- thêm `historical_correlation` vào summary
- suppress alert trùng theo `dedup_key` trong TTL

### `app/retry_queue.py`

Lưu các batch phân tích lỗi vào file spool và retry lại theo exponential backoff.

### `app/status_reporter.py`

Theo dõi khoảng thời gian không có alert và tạo bản tóm tắt định kỳ. Nếu Telegram được bật, service có thể gửi:

- alert thực sự
- hoặc báo cáo "không có alert quan trọng" nhưng vẫn kèm số liệu xử lý và chi phí LLM

### `app/writers/`

Các output hiện có:

- `jsonl_writer.py`: ghi alert xuống file JSONL
- `stdout_writer.py`: in alert rút gọn ra console
- `telegram_writer.py`: gửi alert và status qua Telegram

## 4. Định dạng dữ liệu đầu vào

`AI_alert` đọc JSON Lines. Mỗi dòng được parse thành `Event`.

Schema `Event` hỗ trợ:

- event đã chuẩn hóa trực tiếp
- hoặc event kiểu aggregate có `sample_event`

Model sẽ tự flatten một số field lồng nhau như:

- `sample_event.network.source_ip`
- `sample_event.network.destination_ip`
- `sample_event.action`
- `sample_event.message`

Điều này giúp service đọc được cả log đơn lẻ lẫn output từ bước dedup.

## 5. Context SOC

Thư mục `context/` là nơi đặt tri thức vận hành để LLM dựa vào. Các file hiện có:

- `01_environment.md`
- `02_detection_policy.md`
- `03_asset_criticality.md`
- `04_known_benign_patterns.md`
- `05_response_playbooks.md`
- `06_output_schema.md`

Đây là phần quyết định chất lượng alert nhiều hơn cả prompt chung. Nếu muốn giảm false positive, nên tập trung cập nhật các file này trước.

## 6. Cấu hình chính

Một số biến môi trường quan trọng:

- `LOG_INPUT_PATH`: file đầu vào, mặc định `./log_dedup.json`
- `ALERT_OUTPUT_PATH`: file output alert, mặc định `./data/alerts.jsonl`
- `CONTEXT_DIR`: thư mục Markdown context
- `GROQ_API_KEY`: khóa API
- `GROQ_MODEL`: tên model dùng để phân tích
- `BATCH_WINDOW_SECONDS`: độ dài mỗi cửa sổ batch
- `BATCH_IDLE_TIMEOUT_SECONDS`: flush khi im lặng quá lâu
- `ALERT_SUPPRESSION_TTL_SECONDS`: thời gian suppress alert trùng
- `CORRELATION_LOOKBACK_SECONDS`: cửa sổ nhìn lại để tính tương quan lịch sử
- `NO_ALERT_SUMMARY_INTERVAL_SECONDS`: chu kỳ gửi status khi không có alert
- `RETRY_FAILED_BATCHES`: bật/tắt retry batch lỗi
- `MAX_CONTEXT_CHARS`: giới hạn context nạp vào prompt
- `LOG_START_POSITION`: `beginning` hoặc `end`

## 7. Cách chạy

Từ thư mục `AI_alert`:

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

Tạo file `.env` rồi cấu hình tối thiểu:

```env
GROQ_API_KEY=your_key
LOG_INPUT_PATH=./log_dedup.json
ALERT_OUTPUT_PATH=./data/alerts.jsonl
CONTEXT_DIR=./context
GROQ_MODEL=openai/gpt-oss-120b
```

Chạy service:

```bash
python -m app.main
```

## 8. Kiểm thử

Trong `AI_alert/tests/test_models_and_analyzer.py` hiện đã có test cho:

- parse event
- context loader
- prompt builder
- batcher
- correlation giữa nhiều window
- duplicate suppression
- retry queue
- formatter Telegram
- status reporter
- Groq payload/schema

Chạy test:

```bash
pytest
```

## 9. Điểm mạnh của thiết kế hiện tại

- Không phụ thuộc hoàn toàn vào từng log đơn lẻ.
- Có lớp context Markdown nên dễ tinh chỉnh nghiệp vụ SOC.
- Có batch summary và historical correlation nên phù hợp với hành vi kéo dài.
- Có suppress alert trùng để giảm spam.
- Có retry queue cho batch lỗi.
- Có theo dõi usage và chi phí LLM.

## 10. Giới hạn hiện tại

- Chất lượng alert phụ thuộc mạnh vào chất lượng context và prompt.
- `malicious-enricher.py` chưa được nối mặc định vào `AI_alert`.
- Chưa có context SOC riêng cho Linux event (SSH brute-force policy, sudo abuse, user management).
- LLM vẫn có thể đánh giá sai, bỏ sót hoặc tạo reasoning chưa đủ chắc chắn.
- Dữ liệu được gửi ra ngoài qua Groq API, nên cần cân nhắc chính sách bảo mật.

## 11. Khi nào nên mở rộng thêm

Nên mở rộng dự án nếu bạn muốn:

- thêm nguồn log khác ngoài WAF, VPC, Windows, Linux (firewall, IDS/IPS)
- thêm context SOC cho Linux event (SSH brute-force policy, sudo abuse policy)
- bổ sung output như Slack, webhook, email
- cho phép correlation theo asset, user hoặc campaign
- thêm rule local trước khi gọi LLM để giảm chi phí
- nối bước enrich threat intel trực tiếp vào pipeline chính

## 12. Tóm tắt ngắn

Đây là một pipeline SOC dùng AI để triage log theo cụm thời gian. Phần `AI_alert` là tầng cuối chịu trách nhiệm gom log đã được chuẩn hóa, lấy context nghiệp vụ, gọi LLM, rồi xuất alert có cấu trúc và chống trùng lặp. Nếu xem toàn repo như một hệ thống, luồng chính hiện tại là:

`archives.json -> normalize-service.py -> log_normalized.json -> dedup-service.py -> log_dedup.json -> AI_alert/app/main.py -> alerts.jsonl / stdout / Telegram`
