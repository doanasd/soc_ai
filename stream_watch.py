import json
import time
import os

# Đường dẫn cấu hình file
INPUT_RAW_FILE = "log.json"      # File log thô gốc của bạn (174 dòng)
OUTPUT_SAMPLE_FILE = "raw_sample.json"  # File mồi từng dòng để test

def stream_logs():
    # Kiểm tra file đầu vào
    if not os.path.exists(INPUT_RAW_FILE):
        print(f"❌ Không tìm thấy file {INPUT_RAW_FILE}!")
        return

    # Đọc toàn bộ các dòng hợp lệ từ file gốc
    with open(INPUT_RAW_FILE, "r", encoding="utf-8") as f:
        lines = [line.strip() for line in f if line.strip()]

    total_lines = len(lines)
    print(f"🚀 Bắt đầu quá trình Echo log. Tổng số dòng: {total_lines}")
    print("Mẹo: Bạn có thể mở 1 terminal khác chạy lệnh: tail -f log_normalized.json")
    print("-" * 60)

    # Xóa file cũ nếu có để làm sạch môi trường test
    if os.path.exists(OUTPUT_SAMPLE_FILE):
        os.remove(OUTPUT_SAMPLE_FILE)

    # Chế độ chạy: 1 - Nhấn Enter từng dòng, 2 - Tự động chạy theo giây
    mode = input("Chọn chế độ (1: Nhấn Enter thủ công | 2: Chạy tự động sau 0.5s): ").strip()

    for idx, line in enumerate(lines, start=1):
        # Ghi đè hoặc append vào file raw_sample.json (ở đây dùng append để mô phỏng log sinh ra liên tục)
        with open(OUTPUT_SAMPLE_FILE, "a", encoding="utf-8") as out_f:
            out_f.write(line + "\n")

        print(f"👉 [Dòng {idx}/{total_lines}] Đã chuyển 1 log sang {OUTPUT_SAMPLE_FILE}")
        
        # In trước một phần nội dung log để bạn nhận diện loại log (Win, CloudTrail, Linux, Cisco,...)
        print(f"   Nội dung: {line[:120]}...")

        # Điều khiển luồng dừng
        if mode == "1":
            input("   ⌨️ Nhấn [ENTER] để đẩy tiếp dòng tiếp theo...")
        else:
            time.sleep(0.5)  # Chờ nửa giây giữa các dòng

    print("\n Complete! Đã đẩy toàn bộ log thành công.")

if __name__ == "__main__":
    stream_logs()
