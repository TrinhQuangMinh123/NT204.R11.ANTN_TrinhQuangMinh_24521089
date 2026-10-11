# NOTES — quyết định đã sửa, hạn chế đã biết

Tệp này ghi những quyết định **sai** đã nhận ra sau khi code chạy, và lý do sửa. Mỗi mục ghi: sai ở
đâu, vì sao sai, sửa thành gì, và đánh đổi phải chấp nhận. Mục đích là để khi vấn đáp trả lời được
"vì sao lúc đầu làm thế" chứ không phải để che đi.

## 2026-10-11 — Dừng đọc header HTTP tại dòng sai là một đường né luật

**Quyết định cũ (bài 1).** Phần đọc yêu cầu/trả lời HTTP, khi gặp một dòng header sai cú pháp — có
byte không đọc được thành chữ ASCII, thiếu dấu hai chấm, hoặc tên trường có khoảng trắng — thì ghi lý
do lỗi rồi **dừng hẳn**, không đọc tiếp các dòng phía dưới. Lý lẽ lúc đó: "đọc tiếp là tự đoán bên
nhận hiểu dòng rác ấy thế nào", và yêu cầu REQ-7.5 chỉ đòi ghi lỗi + không làm chương trình chết.

**Vì sao sai.** Cái bị bỏ qua là **bên nhận thật vẫn đọc tiếp**. Chuẩn HTTP (RFC 9110 §5.5) coi byte
lớn hơn 0x7F trong phần giá trị của header là loại đã bỏ đi, *không khuyến khích* nhưng **không bắt
từ chối** — nên nhiều máy chủ web vẫn nhận nguyên yêu cầu đó. Khi ấy kẻ tấn công chỉ cần nhồi một
byte rác vào một dòng sớm là mọi dòng phía dưới **biến mất khỏi event**, trong khi máy chủ đích vẫn
xử lý chúng. Thiết bị giám sát thấy ít hơn bên nhận — đó đúng là định nghĩa của một đường né luật
(evasion), và nó là loại lỗi nặng nhất đối với một IDS vì nó gây **bỏ sót**, không chỉ báo sai.

Hai điều vẫn đúng ở quyết định cũ, và được giữ: (1) đòi hỏi ASCII nghiêm ngặt thay vì âm thầm thay
byte rác bằng dấu hỏi — có thế mới còn lỗi để ghi và chuỗi trong event mới đúng thứ có trên dây;
(2) không ghép dòng sai vào danh sách header, vì ta không đoán hộ bên nhận.

**Sửa thành.** Dòng sai thì ghi lý do rồi **bỏ qua đúng dòng đó và đọc tiếp**. Nhiều dòng sai thì mọi
lý do đều được ghi, nối bằng dấu `;` trong cùng một mục lỗi của tầng HTTP. Bytes nguyên văn của cả
payload vẫn được giữ như trước, nên luật quét byte thô soi lại được dòng bị bỏ.

**Đánh đổi chấp nhận.** Sau khi sửa, rủi ro đổi chiều: ta có thể thấy **nhiều hơn** bên nhận (nếu máy
chủ đích từ chối cả yêu cầu, ta vẫn bóc được các header dưới dòng rác). Hướng đó chỉ sinh báo động
thừa, không sinh bỏ sót — với một IDS đó là đánh đổi đúng chiều.

**Kiểm chứng.** Ba test mới trong `tests/test_http.py`: dòng sau dòng rác vẫn được đọc; mọi dòng sai
đều được báo; ca né luật cụ thể là `Host` thật bị giấu dưới một dòng rác. Bộ test đầy đủ: 792 pass.

**Bằng chứng test cũ không đổi.** Trong gói HTTP hỏng của bài 1 (`TEST/TC-12_malformed-packet/`),
dòng chứa byte rác tình cờ là dòng header **cuối cùng**, nên không có dòng nào phía dưới để đọc tiếp
— kết quả của gói đó giữ nguyên từng ký tự. Ca né luật vì vậy chỉ được kiểm bằng test đơn vị, chưa có
PCAP riêng.

**Vì sao sửa được mà không phạm luật "không viết lại lịch sử".** Bài 1 chưa nộp bản cuối; thầy theo
dõi tiến độ qua lịch sử commit trên GitHub. Sửa bằng một commit **mới** kèm ghi chú này, không chỉnh
commit cũ.
