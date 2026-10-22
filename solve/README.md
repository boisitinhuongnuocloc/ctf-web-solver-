# Solve Artifacts Directory

Thư mục này chứa toàn bộ kết quả phân tích và khai thác được hệ thống sinh ra tự động, hoàn toàn tách biệt để giữ sạch thư mục gốc:

Mỗi bài giải sẽ có thư mục riêng: `solve/<tên_bài>/`
- `analysis.json`: Báo cáo quét tĩnh về tech stack, sinks, routes, docker configs
- `exploit.py`: Script khai thác Python hoàn chỉnh do AI hoặc bộ sinh payload tạo ra
- `run.log`: Toàn bộ nhật ký thực thi chi tiết
- `flag.txt`: Flag bắt được từ hệ thống
