import json

raw_file_path = "raw_sample.json"
normalized_file_path = "log_normalized.json"

# 1. Đọc file raw theo từng dòng JSON
raw_data = []
with open(raw_file_path, "r", encoding="utf-8") as f:
    for line_num, line in enumerate(f, start=1):
        line = line.strip()
        if line:  # Bỏ qua dòng trống
            try:
                raw_data.append(json.loads(line))
            except json.JSONDecodeError as e:
                print(f"❌ Dòng {line_num} ở file RAW không phải định dạng JSON hợp lệ: {e}")

# 2. Đọc file đã normalize theo từng dòng JSON
normalized_messages = set()
with open(normalized_file_path, "r", encoding="utf-8") as f:
    for line in f:
        line = line.strip()
        if line:
            try:
                log_obj = json.loads(line)
                # Lấy trường log gốc bạn đã lưu (ví dụ: 'raw_message' hoặc 'message')
                # Nếu bạn không lưu text gốc, hãy đổi 'raw_text' thành trường đặc trưng duy nhất (như log_id)
                if "raw_text" in log_obj:
                    normalized_messages.add(log_obj["raw_text"])
                elif "id" in log_obj:
                    normalized_messages.add(log_obj["id"])
            except json.JSONDecodeError:
                continue

# 3. So sánh tìm dòng bị thiếu
print("\n--- BẮT ĐẦU KIỂM TRA DÒNG BỊ MISS ---")
miss_count = 0

for idx, raw_log in enumerate(raw_data, start=1):
    # CHÚ Ý: Chỉnh sửa logic kiểm tra ở đây cho khớp với cách bạn lưu dữ liệu ở bước 2
    # Nếu file normalize lưu text gốc:
    # (Nếu không lưu, ta có thể chuyển sang chạy test trực tiếp hàm normalize tại đây)
    
    # Giả định kiểm tra qua ID hoặc message
    log_id = raw_log.get("id") 
    
    # Nếu không tìm thấy dấu vết của raw_log này trong tập hợp đã normalize
    if log_id not in normalized_messages:
        miss_count += 1
        print(f"\n[MISS #{miss_count}] Dòng {idx} trong file raw_log.json không có trong đầu ra!")
        print(json.dumps(raw_log, indent=2, ensure_ascii=False))
        print("-" * 50)

print(f"\n=> Quét xong. Tìm thấy {miss_count} dòng bị thiếu.")
