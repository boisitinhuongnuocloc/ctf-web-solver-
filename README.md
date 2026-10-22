# Autonomous Multi-Target Web CTF Solver

Hệ thống tự động hóa giải CTF Web tích hợp đa backend AI:
- **OpenCode + lingling** (`big-pickle`, `deepseek-v4.1`, v.v.): Vô hạn token, xoay vòng Tor exit nodes, không bị security censorship / filter kiểm duyệt (Mặc định).
- **Ollama** (`qwen2.5:7b`): Chạy offline cục bộ trên GPU NVIDIA RTX 5050 (8GB VRAM).

---

## 1. Cấu Trúc Thư Mục Chuẩn (Giữ Thư Mục Gốc Luôn Gọn Gàng)

```text
ctf/
│
├── solve.py                   # CLI trung tâm điều khiển toàn bộ quá trình giải
├── README.md                  # Tài liệu hướng dẫn sử dụng
│
├── src/                       # Mã nguồn hệ thống (Engine, AI Agent, Fingerprint)
│   ├── config.py              # Cấu hình Ollama host, model, timeouts
│   ├── fingerprint.py         # Static code analysis (quét Dockerfile, sinks, routes)
│   ├── flag_engine.py         # Nhận diện định dạng flag động (picoCTF, cscv2026, regex)
│   ├── ai_agent.py            # Kết nối Ollama, prompt engineering, sinh exploit
│   ├── builtins.py            # Bộ giải nhanh các dạng bài kinh điển (picoCTF quick-wins)
│   ├── executor.py            # Chạy thử nghiệm exploit trong sandbox & bắt flag
│   └── orchestrator.py        # Điều phối giải đơn lẻ hoặc giải hàng loạt (Batch)
│
├── challenges/                # [NƠI BẠN ĐẶT CÁC BÀI CTF]
│   ├── <tên_bài_1>/           # Thư mục chứa source code bài 1 (hoặc ném file .zip vào đây)
│   │   ├── target.txt         # (Tùy chọn) Ghi link instance web vào đây (http://...)
│   │   └── flag_format.txt    # (Tùy chọn) Ghi prefix flag (ví dụ: picoCTF hoặc cscv2026)
│   └── <tên_bài_2>/
│
└── solve/                     # [NƠI LƯU KẾT QUẢ GIẢI - HOÀN TOÀN TÁCH BIỆT]
    └── <tên_bài_1>/
        ├── analysis.json      # Báo cáo phân tích stack, sinks, routes
        ├── exploit.py         # Mã script khai thác do AI sinh ra
        ├── run.log            # Nhật ký chạy và tự sửa lỗi (Self-healing)
        └── flag.txt           # Flag bắt được
```

---

## 2. Hướng Dẫn Sử Dụng Nhanh

### Cài đặt
```powershell
python -m pip install -r requirements.txt
```

### Cách 1: Giải 1 bài cụ thể
Nếu bạn tải file bài về thư mục `challenges/pico_cookies` và ban tổ chức cấp instance:
```powershell
python solve.py -t challenges/pico_cookies -u http://saturn.picoctf.net:54321 -p picoCTF
```

*Nếu bạn ném thẳng file `pico_cookies.zip` vào `challenges/`: tool sẽ tự động giải nén và xử lý.*

### Cách 2: Giải hàng loạt nhiều bài cùng lúc (Batch Solve)
Bạn tải về 3-5 bài CTF và ném vào thư mục `challenges/`:
*   Mỗi thư mục con chỉ cần có 1 file `target.txt` chứa link instance (hoặc chạy test local).
*   Chạy 1 lệnh duy nhất:
```powershell
python solve.py --all
```
Tool sẽ tự động duyệt qua từng bài, phân tích source, gọi AI sinh exploit, bắt flag và in ra bảng tổng kết đẹp mắt.

Khi description có `workspace/org`, `email`, `PIN` hoặc `username/password`, solver sẽ thử đăng nhập trước khi recon các API được bảo vệ. Với instance mới, ưu tiên truyền URL trực tiếp bằng `-u`.

### Cách 3: Chạy chẩn đoán hệ thống (Self-Test)
Kiểm tra kết nối Ollama, card đồ họa và mô hình `qwen2.5:7b`:
```powershell
python solve.py --test
```

### Cách 4: Dọn sạch lịch sử kết quả giải
```powershell
python solve.py --clean
```

---

## 3. Các Tham Số CLI (Options)

| Tham số | Ý nghĩa | Ví dụ |
| :--- | :--- | :--- |
| `-t, --target` | Đường dẫn tới folder hoặc file `.zip` của bài | `-t challenges/web_gauntlet` |
| `-u, --url` | Link instance web của đề bài | `-u http://127.0.0.1:5000` |
| `-p, --flag-prefix` | Tiền tố flag nếu biết trước | `-p picoCTF` hoặc `-p cscv2026` |
| `-r, --flag-regex` | Regex tùy chỉnh bắt flag | `-r "FLAG\{[a-z0-9]+\}"` |
| `-a, --all` | Tự động quét và giải TẤT CẢ các bài trong `challenges/` | `python solve.py --all` |
| `--provider` | Backend AI (`opencode` hoặc `ollama`, mặc định: `opencode`) | `--provider opencode` |
| `-m, --model` | Chọn model AI (Mặc định: `big-pickle` cho OpenCode, `qwen2.5:7b` cho Ollama) | `-m deepseek-v4.1-flash-free` |
| `--test` | Chạy bộ test chẩn đoán mẫu | `python solve.py --test` |
| `--clean` | Dọn dẹp thư mục `solve/` | `python solve.py --clean` |

---

## 4. Cơ Chế Nhận Diện & Khai Thác Độc Quyền

1.  **Nhận diện Tech Stack & Lỗ hổng tĩnh (AST/Regex):**
    *   Tự động đọc `Dockerfile`, `docker-compose.yml`, `requirements.txt`, `package.json`.
    *   Truy vết các hàm nguy hiểm: SSTI (`render_template_string`), Insecure Deserialization (`pickle`, `unserialize`), SQLi thô, Path Traversal (`open`, `file_get_contents`), Command Injection (`os.system`, `child_process`).
2.  **Bộ giải nhanh kinh điển (Built-in Heuristics):**
    *   Quét nhanh HTML Comments, `robots.txt`, `/.git/`, kiểm tra HTTP methods (HEAD/OPTIONS như bài *GET aHEAD*), và cookie manipulation. Nếu bài dạng cơ bản, tool nhặt flag ngay trong 1 giây mà không cần gọi AI.
3.  **Bộ điều khiển AI Agent với vòng lặp tự chữa lỗi (Self-Healing Loop):**
    *   Prompt được tối ưu hóa đặc biệt với cheat sheet khai thác CTF.
    *   Nếu lần chạy đầu tiên bị lỗi (HTTP 500 hoặc cú pháp sai), agent đọc thông báo lỗi từ terminal, phân tích nguyên nhân và sinh lại exploit script mới (tối đa 3 lần).
4.  **Cơ chế bắt flag động:**
    *   Tự động tìm kiếm flag mẫu trong Dockerfile để trích xuất tiền tố tổ chức (`picoCTF{...}`, `cscv2026{...}`).
    *   Bộ lọc thông minh loại trừ flag giả/dummy flag (`flag{fake_flag}`) để đảm bảo chỉ lưu flag thật.
