# Một số điểm cần lưu ý

Project gom nhiều event thành một `time windows` - nghĩa là gom log trong 5 phút rồi mới gửi cho AI phân tích.

Ưu điểm:

- Batch rất hợp lý cho SOC nếu mục tiêu là giảm noise.
- Nếu gửi từng log lên AI sẽ tốn token và dễ tạo alert trùng Batch sẽ giúp AI nhìn được bức tranh tổng thể.

Nhược điểm:

- Batch có thể không chính xác vì summary là bản rút gọn, không phải toàn bộ log. Trong code thì `build_window_summary()` chỉ giữ các thông tin chính như:

```
top_source_ips
top_destination_ips
top_groups
external_to_private_sensitive
log_type_counts
action_counts
sample_message
```

Nếu một event nguy hiểm nhưng chỉ xuất hiện 1 lần, không nằm trong top group, không thuộc pattern `external_to_private_sensitive`, thì AI có thể không thấy nó. Ví dụ như event Windows đặc biệt như tạo user admin, event PowerShell

- Summary chưa đầy đủ các field như:

```
maliciousIP
Windows event_id
username
hostname
process name
command line
parent process
rule level / severity
```
