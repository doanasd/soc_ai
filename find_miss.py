# Đọc toàn bộ các dòng của file log gốc (raw)
with open("raw_sample.json", "r", encoding="utf-8") as f:
    raw_lines = [line.strip() for line in f if line.strip()]

# Đọc toàn bộ file đã normalize dưới dạng text thuần
with open("log_normalized.json", "r", encoding="utf-8") as f:
    normalized_content = f.read()

print(f"Tổng số dòng file raw: {len(raw_lines)}")
print("--- BẮT ĐẦU TÌM DÒNG BỊ MISS ---")

miss_count = 0
for idx, line in enumerate(raw_lines, start=1):
    # Lấy thử một đoạn text đặc trưng từ dòng log gốc (bỏ bớt các ký tự nhiễu nếu có)
    # Hoặc tìm kiếm trực tiếp xem toàn bộ nội dung dòng gốc có được lưu trong trường 'fullLog' hay 'message' không
    
    # Ở đây chúng ta kiểm tra xem chuỗi thô của dòng log có xuất hiện trong file kết quả không
    # (Nếu bạn chỉ lưu một phần chuỗi lỗi, ta lấy 50 ký tự đầu của log để tìm kiếm)
    search_keyword = line[:60] 
    
    if search_keyword not in normalized_content:
        miss_count += 1
        print(f"\n❌ [MISS #{miss_count}] Phát hiện dòng thứ {idx} trong file raw bị bỏ sót:")
        print(f"Nội dung dòng: {line}")
        print("-" * 60)

if miss_count == 0:
    print("\n Không tìm thấy dòng hụt bằng cách quét chuỗi nhanh. Có thể dòng bị miss là do một dòng trống hoặc dòng bị trùng lặp!")
