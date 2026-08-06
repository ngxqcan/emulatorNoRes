## Techno Verse - Vanguard Gateway Emulator
Techno Verse là một công cụ giao tiếp mạng (Network Interceptor & Session Manager) được thiết kế để hoạt động cùng với VALORANT. Nó hoạt động như một lớp trung gian (Man-in-the-middle) can thiệp vào luồng giao tiếp giữa Game Client và các dịch vụ xác thực, giúp duy trì trạng thái đăng nhập và kết nối trong môi trường cụ thể.

(Lưu ý: Đây là một công cụ kỹ thuật số. Việc sử dụng công cụ này để can thiệp vào phần mềm của bên thứ ba có thể vi phạm Điều khoản Dịch vụ. Người dùng chịu hoàn toàn trách nhiệm về việc sử dụng phần mềm này.)

🚀 Tính năng nổi bật
Interceptor qua Named Pipe: Tự động phát hiện và bắt giữ các thông tin xác thực (JWT, Entitlement, PUUID) ngay khi game khởi động.

Spoofing & Session Management: Duy trì phiên làm việc (Session) liên tục mà không cần sự can thiệp của driver cốt lõi.

Heartbeat & Van 102 Prevention: Hệ thống quản lý Heartbeat thông minh, tự động phát hiện và reset khi gặp tình trạng lag mạng (giảm thiểu lỗi Van 102).

Giao thức Bảo mật: Sử dụng bảo mật SSL/TLS (Schannel) để giao tiếp với Gateway, mã hóa dữ liệu trao đổi.

GUI Trực quan: Cung cấp giao diện đồ họa (ImGui/DirectX) hiển thị trạng thái kết nối, logs và hỗ trợ phím tắt.

Tự động hóa: Hỗ trợ tự động làm mới Session sau mỗi trận đấu.

📋 Yêu cầu hệ thống
Hệ điều hành: Windows 10 / 11 (64-bit).

Visual Studio: Visual Studio 2019 hoặc 2022 (C++ Desktop Development).

Thư viện yêu cầu: WinHTTP, BCrypt, Schannel (đã có sẵn trong Windows SDK).

Python (Để tạo dữ liệu): Python 3.10+ (dùng để chạy script gen.py).

🛠️ Hướng dẫn cài đặt và xây dựng (Build)
1. Chuẩn bị môi trường
Mở file test.vcxproj (hoặc file solution của bạn) bằng Visual Studio.

Đảm bảo project đang để chế độ build Release và x64.

Tải và giải nén thư viện Dear ImGui (phiên bản 1.90+) vào thư mục imgui trong project.

Đảm bảo đường dẫn: YourProject/imgui/imgui.cpp, YourProject/imgui/backends/imgui_impl_dx11.cpp, v.v.

2. Tạo file dữ liệu HWID (output.txt)
Dự án yêu cầu một file dữ liệu chứa các chuỗi Machine ID giả mạo để hoạt động.

Mở Command Prompt (CMD) tại thư mục project.

Chạy lệnh sau để tạo dữ liệu:

bash
python gen.py 100000
File output.txt sẽ được tạo ra. Bạn cần đặt file này cùng thư mục với file .exe sau khi build.

3. Build Project
Nhấn tổ hợp phím Ctrl + Shift + B hoặc chọn Build > Build Solution trong Visual Studio.

File thực thi (ProjectName.exe) sẽ được tạo ra tại thư mục x64\Release.

⚙️ Cách sử dụng (User Guide)
Bước 1: Khởi động
Chạy file .exe đã build. Giao diện GUI (Techno Verse Dashboard) sẽ hiện lên. Bạn có thể thấy trạng thái "WAITING FOR VALORANT".

Bước 2: Bắt đầu game
Mở VALORANT và đăng nhập vào tài khoản (đến màn hình Lobby/Sảnh).
Ứng dụng sẽ tự động phát hiện tiến trình game (VALORANT-Win64-Shipping.exe) và trạng thái trên GUI sẽ chuyển thành "VALORANT DETECTED".

Bước 3: Kích hoạt Session (Phím F2)
Đây là bước quan trọng nhất.
Tại màn hình Lobby, đợi khoảng 3-5 giây để ứng dụng bắt được JWT từ game. Sau đó, nhấn phím F2 (hoặc nút [F2] Refresh Session trên GUI) để kích hoạt kết nối Gateway.

Quan trọng: Không bấm Play (Tìm trận) ngay lập tức sau khi ấn F2.

Hãy theo dõi cửa sổ "LIVE SYSTEM LOGS".

Chỉ khi xuất hiện dòng log màu xanh lục: [GW] gateway mint success (auto) hoặc [GW] re-auth OK, bạn mới bấm nút Play.

Bước 4: Trong và sau khi chơi
Trong mỗi trận đấu, ứng dụng tự động duy trì Heartbeat.

Sau khi kết thúc mỗi trận, bạn cần đợi 5 giây (khi quay lại Lobby), sau đó nhấn F2 lại lần nữa để tự động làm mới Session cho trận tiếp theo.

(Gợi ý nâng cao: Bạn có thể thêm script hoặc sử dụng logic "Tự động F2" trong vgk_manager.cpp để tối ưu hóa bước này)

🔧 Cấu hình nâng cao (Config)
Một số hằng số có thể điều chỉnh trong config.h để thay đổi hành vi:

GATEWAY_REAUTH_INTERVAL_SEC: Tần suất tự động gửi re-auth (Mặc định: 45 phút).

HB_INTERVAL_MS: Tần suất gửi Heartbeat (Mặc định: 25000ms - 25 giây).

SERVER_HOST / AUTH_KEY: Địa chỉ server local và khóa xác thực của project (nếu sử dụng mô hình client-server riêng).

📂 Cấu trúc thư mục (Technical Overview)
vgk_manager.h/cpp: Quản lý phiên làm việc, xử lý Heartbeat và IOCTL.

pipe_server.cpp: Thiết lập Named Pipe, bắt và parse dữ liệu từ Game Client.

vanguard_gateaway.h: Xây dựng và gửi gói tin xác thực Protobuf đến Gateway (mã hóa AES-GCM + RSA).

hwid_spoof.cpp: Tạo và quản lý Hardware ID giả mạo (dựa trên output.txt).

tls_socket.cpp: Quản lý kết nối TLS (Schannel) và gửi/nhận dữ liệu mạng.

gui_app.cpp: Giao diện người dùng dùng ImGui + DirectX 11.

gen.py: Python script sinh dữ liệu output.txt.

⚠️ Khắc phục sự cố phổ biến
1. Lỗi "Empty body" hoặc "re-auth FAILED" khi bấm F2:

Nguyên nhân: Riot Gateway đã cập nhật giao thức và yêu cầu thêm trường dữ liệu Entitlement. Code cũ chưa gửi dữ liệu này.

Khắc phục: Cập nhật 2 file pipe_server.cpp (để parse Entitlement) và vanguard_gateaway.h (để thêm field 16 vào gói tin). Build lại project.

2. Lỗi Van 102 khi đang chơi:

Nguyên nhân: Heartbeat bị trễ do mạng lag, hoặc giá trị HB_INTERVAL_MS quá cao.

Khắc phục: Giảm HB_INTERVAL_MS xuống 15000 (15 giây). Đảm bảo code đã có logic retry khi gửi Heartbeat thất bại.

3. Không tìm thấy file output.txt:

Khắc phục: Chạy script python gen.py 100000, sau đó copy file output.txt vào thư mục chứa file .exe.

📜 Thông tin pháp lý và Tuyên bố miễn trừ trách nhiệm
Phần mềm này được phát triển cho mục đích nghiên cứu kỹ thuật và giáo dục.

Việc sử dụng phần mềm này trên phiên bản thương mại của VALORANT có thể vi phạm Điều khoản Dịch vụ của Riot Games.

Tác giả không chịu trách nhiệm về bất kỳ thiệt hại, tổn thất, hoặc hành động khóa tài khoản nào phát sinh từ việc sử dụng phần mềm này. Người dùng hoàn toàn chịu trách nhiệm về việc sử dụng của mình.

🤝 Đóng góp & Phát triển
Các cải tiến về hiệu suất, cập nhật giao thức (khi Riot thay đổi) hoặc tối ưu hóa giao diện luôn được hoan nghênh. Bạn có thể tự điều chỉnh code dựa trên các file nguồn đã cung cấp."# emulatorNoRes" 
"# emulatorNoRes" 
