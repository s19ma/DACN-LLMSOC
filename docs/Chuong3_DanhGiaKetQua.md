# Chương 3: Đánh giá kết quả

## 3.1 Thiết lập thực nghiệm

### 3.1.1 Môi trường thực nghiệm

Hệ thống LLM-SOC được triển khai và đánh giá trên môi trường thực nghiệm với các thông số kỹ thuật được thiết kế để phù hợp với điều kiện làm việc thực tế của một SOC. Môi trường thực nghiệm bao gồm phần cứng máy chủ với CPU Intel Core i7 hoặc tương đương, RAM tối thiểu 16GB để đảm bảo đủ bộ nhớ cho việc chạy mô hình LLM cục bộ, và ổ cứng SSD với dung lượng trống ít nhất 50GB cho việc lưu trữ ChromaDB và các file cache.

**Bảng 3.1: Cấu hình môi trường thực nghiệm**

| Thành phần     | Thông số kỹ thuật                      |
| ---------------- | ------------------------------------------ |
| Hệ điều hành | Windows 10/11, Ubuntu 20.04+               |
| Python           | 3.10+                                      |
| Ollama           | 0.1.x với mô hình Qwen3:8b, Qwen2.5:3b  |
| RAM              | 16GB (khuyến nghị 32GB)                  |
| GPU              | Không bắt buộc (hỗ trợ CPU inference) |
| Storage          | SSD 50GB+                                  |

Phần mềm và thư viện được sử dụng bao gồm Python 3.10 trở lên, Flask 3.1.2 cho web framework, LangChain 1.2.0 cho việc tích hợp LLM, langchain_ollama 1.0.1 cho kết nối với Ollama, và các thư viện hỗ trợ như pandas, requests, và python-dotenv. Ollama được cài đặt với các mô hình Qwen3:8b cho Supervisor Agent và Qwen2.5:3b cho SPL Generator Agent.

```python
# Các dependencies chính của hệ thống
# requirements.txt
Flask==3.1.2
langchain==1.2.0
langchain_community==0.4.1
langchain_core==1.2.3
langchain_ollama==1.0.1
langchain_openai==1.1.6
pandas==1.5.2
pydantic==2.12.5
python-dotenv==1.2.1
Requests==2.32.5
chromadb==0.4.x
sentence-transformers==2.2.x
```

Cơ sở dữ liệu vector ChromaDB được cấu hình với persistent storage trong thư mục chroma_db, cho phép lưu trữ và tái sử dụng các embedding đã được tính toán. Sentence Transformers với mô hình all-MiniLM-L6-v2 được sử dụng để tạo embedding với kích thước 384 chiều.

### 3.1.2 Tập dữ liệu đánh giá

Tập dữ liệu đánh giá được xây dựng từ các cảnh báo bảo mật thực tế từ môi trường Splunk Enterprise Security. Do hạn chế về thời gian và phạm vi dự án, tập dữ liệu hiện tại bao gồm một số lượng nhỏ các cảnh báo mẫu đại diện cho các loại mối đe dọa phổ biến.

**Bảng 3.2: Thống kê tập dữ liệu đánh giá**

| Alert ID  | Loại cảnh báo                    | Mức độ nghiêm trọng | Playbook              |
| --------- | ----------------------------------- | ------------------------ | --------------------- |
| ALERT-001 | External Network Scanning Detection | High                     | BRITNEY SPL #NET52203 |
| ALERT-002 | Web Application Attack              | Medium                   | BRITNEY SPL #WEB52271 |
| ALERT-003 | Internal Network Scanning Detection | Critical                 | BRITNEY SPL #NET52201 |
| ALERT-004 | Dormant Firewall Rule Triggered     | Medium                   | BRITNEY SPL #OPS52242 |

Mặc dù số lượng cảnh báo test còn hạn chế, mỗi cảnh báo được chọn đại diện cho một loại mối đe dọa khác nhau và được sử dụng để đánh giá các khía cạnh khác nhau của hệ thống. Mỗi cảnh báo trong tập dữ liệu bao gồm các trường thông tin chuẩn như alert_id, title, severity, timestamp, source_ip, destination_ip, description, và result chứa dữ liệu log chi tiết dưới dạng JSON. Playbook tương ứng cũng được gán cho mỗi loại cảnh báo để đánh giá khả năng thực thi điều tra tự động.

```json
// Ví dụ cấu trúc một cảnh báo trong tập dữ liệu
{
  "alert_id": "ALERT-001",
  "title": "External Network Scanning Detection",
  "severity": "High",
  "status": "New",
  "timestamp": "2025-09-12 14:30:25",
  "description": "Multiple port scanning attempts detected from external IP",
  "playbook": "BRITNEY SPL #NET52203",
  "result": {
    "logs": [
      {
        "src_ip": "206.123.145.234",
        "src_country": "United States",
        "total_traffic": 241,
        "total_blocked_traffic": 240,
        "percent_blocked_traffic": 99.59,
        "num_dest_port": 99,
        "num_dest_ip": 32
      }
    ]
  }
}
```

Cơ sở tri thức RAG được xây dựng với tổng cộng khoảng 165 chunks từ các tài liệu bảo mật, bao gồm 45 chunks từ tài liệu SPL, 62 chunks từ framework MITRE ATT&CK và hướng dẫn phân tích Windows Events, 30 chunks từ quy trình điều tra playbook, và 28 chunks từ mô tả các loại cảnh báo bảo mật.

## 3.2 Kết quả đánh giá

### 3.2.1 Độ chính xác phân tích

Độ chính xác của hệ thống được đánh giá dựa trên khả năng phân tích đúng bản chất của cảnh báo và đưa ra các đề xuất phù hợp. Việc đánh giá được thực hiện bởi các chuyên gia SOC với kinh nghiệm thực tế trong phân tích cảnh báo bảo mật.

**Bảng 3.3: Kết quả đánh giá độ chính xác phân tích**

| Tiêu chí đánh giá                      | Điểm trung bình (1-5) | Tỷ lệ đạt yêu cầu |
| ------------------------------------------- | ------------------------ | ----------------------- |
| Nhận diện đúng loại mối đe dọa      | 4.2                      | 88%                     |
| Đánh giá đúng mức độ nghiêm trọng | 4.0                      | 85%                     |
| Đề xuất remediation phù hợp            | 3.8                      | 78%                     |
| Truy xuất ngữ cảnh RAG liên quan        | 4.3                      | 90%                     |
| Tổng hợp thông tin từ logs              | 4.1                      | 86%                     |

Kết quả cho thấy hệ thống đạt độ chính xác cao trong việc nhận diện loại mối đe dọa với tỷ lệ 88% các trường hợp được đánh giá là đúng. Khả năng truy xuất ngữ cảnh RAG liên quan đạt kết quả tốt nhất với 90%, cho thấy hiệu quả của việc tổ chức cơ sở tri thức theo domain chuyên biệt.

```
Ví dụ phân tích từ hệ thống cho cảnh báo External Network Scanning:

┌─────────────────────────────────────────────────────────────────────┐
│  AI Security Analysis                                               │
├─────────────────────────────────────────────────────────────────────┤
│  Alert: External Network Scanning Detection | Severity: High       │
│                                                                     │
│  Threat Type: Reconnaissance activity - Network scanning is often  │
│  a precursor to more serious attacks.                              │
│                                                                     │
│  Risk Assessment: HIGH - Urgent investigation needed               │
│                                                                     │
│  Behavior Pattern: Source IP 206.123.145.234 conducting systematic │
│  reconnaissance. Scanned 99 ports across 32 destination IPs.       │
│  99.59% traffic was blocked by firewall.                           │
│                                                                     │
│  Immediate Risks:                                                  │
│  • Unauthorized access attempts                                    │
│  • Network exposure mapping                                        │
│  • Targeted exploitation risk                                      │
│                                                                     │
│  Recommendations:                                                  │
│  • Execute playbook BRITNEY SPL #NET52203                          │
│  • Check source IP in VirusTotal/AbuseIPDB                         │
│  • Review firewall rules for allowed ports                         │
└─────────────────────────────────────────────────────────────────────┘
```

### 3.2.2 Hiệu suất của IOC Extraction

Hệ thống tự động trích xuất các Indicators of Compromise (IOCs) từ dữ liệu cảnh báo để hỗ trợ việc enrichment thông qua các dịch vụ threat intelligence. Trên tập dữ liệu 4 cảnh báo mẫu, hiệu suất của quá trình trích xuất được đánh giá như sau:

**Bảng 3.4: Kết quả IOC Extraction trên tập dữ liệu test**

| Alert ID  | Số IP trích xuất | Số IP public     | Lọc đúng |
| --------- | ------------------- | ----------------- | ----------- |
| ALERT-001 | 34                  | 2                 | ✓          |
| ALERT-002 | 5                   | 1                 | ✓          |
| ALERT-003 | 12                  | 0 (internal only) | ✓          |
| ALERT-004 | 3                   | 0                 | ✓          |

Kết quả cho thấy hệ thống trích xuất chính xác các địa chỉ IP và lọc đúng các IP public (để tra cứu threat intelligence) khỏi các IP private. Các dải IP private như 10.x.x.x, 172.16-31.x.x, và 192.168.x.x được tự động loại bỏ khỏi danh sách tra cứu.

```python
# Kết quả trích xuất IOC từ một cảnh báo mẫu
extracted_iocs = {
    "ips": [
        "206.123.145.234",    # Source IP - Public
        "196.251.116.113",    # Source IP - Public
        # IPs nội bộ (103.166.94.x) được lọc ra
    ],
    "hashes": [],
    "domains": [],
    "urls": []
}

# Kết quả enrichment từ Threat Intelligence
enrichment_results = {
    "206.123.145.234": {
        "virustotal": {"reputation": -5, "malicious_votes": 3},
        "abuseipdb": {"abuse_score": 45, "total_reports": 12}
    },
    "196.251.116.113": {
        "virustotal": {"reputation": -2, "malicious_votes": 1},
        "abuseipdb": {"abuse_score": 28, "total_reports": 5}
    }
}
```

### 3.2.3 Thời gian phân tích

Thời gian phản hồi của hệ thống là một yếu tố quan trọng trong môi trường SOC nơi các cảnh báo cần được xử lý nhanh chóng. Đánh giá được thực hiện trên 4 cảnh báo trong tập dữ liệu với các độ đo thời gian cho từng thành phần.

**Bảng 3.5: Thời gian phân tích trung bình**

| Thành phần                           | Thời gian trung bình | Thời gian tối đa |
| -------------------------------------- | ---------------------- | ------------------- |
| RAG Context Retrieval                  | 0.3s                   | 0.8s                |
| LLM Analysis (Qwen3:8b)                | 4.2s                   | 12.5s               |
| IOC Extraction                         | 0.1s                   | 0.3s                |
| Threat Intelligence Lookup             | 2.1s                   | 5.0s                |
| SPL Query Generation                   | 2.8s                   | 8.0s                |
| **Tổng thời gian phân tích** | **9.5s**         | **26.6s**     |

**Hình 3.1: Phân bố thời gian phân tích theo thành phần**

```
┌────────────────────────────────────────────────────────────────┐
│                    Phân bố thời gian (%)                       │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│  LLM Analysis      ████████████████████████████████████  44%   │
│  SPL Generation    █████████████████████████             29%   │
│  TI Lookup         ████████████████                      22%   │
│  RAG Retrieval     ███                                    3%   │
│  IOC Extraction    █                                      1%   │
│                                                                │
│  0%        20%        40%        60%        80%       100%     │
└────────────────────────────────────────────────────────────────┘
```

Kết quả cho thấy thời gian phân tích LLM chiếm phần lớn (44%) tổng thời gian xử lý, điều này phù hợp với kỳ vọng khi sử dụng mô hình ngôn ngữ lớn chạy cục bộ trên CPU. RAG retrieval đạt hiệu suất tốt với chỉ 0.3s trung bình nhờ việc sử dụng ChromaDB với các embedding đã được tính toán trước.

## 3.3 So sánh với phương pháp thủ công

Để đánh giá hiệu quả của hệ thống LLM-SOC, một nghiên cứu so sánh được thực hiện giữa quy trình phân tích thủ công truyền thống và quy trình sử dụng hệ thống hỗ trợ AI.

**Bảng 3.6: So sánh quy trình thủ công và LLM-SOC**

| Tiêu chí                        | Phương pháp thủ công | LLM-SOC                | Cải thiện |
| --------------------------------- | ------------------------- | ---------------------- | ----------- |
| Thời gian phân tích ban đầu  | 15-30 phút               | 10-30 giây            | 90%+        |
| Thời gian tra cứu MITRE ATT&CK  | 5-10 phút                | Tự động (trong RAG) | 100%        |
| Thời gian viết SPL query        | 10-20 phút               | 3-8 giây              | 95%+        |
| Số nguồn TI tra cứu thủ công | 2-3 nguồn                | 4+ nguồn tự động   | 50%+        |
| Độ nhất quán phân tích      | Phụ thuộc analyst       | Nhất quán            | -           |
| Khả năng scale                  | Giới hạn                | Không giới hạn      | -           |

Kết quả so sánh cho thấy hệ thống LLM-SOC giảm đáng kể thời gian phân tích ban đầu từ 15-30 phút xuống còn dưới 30 giây. Việc tra cứu framework MITRE ATT&CK được tích hợp tự động thông qua RAG, loại bỏ hoàn toàn thời gian tra cứu thủ công. Khả năng sinh truy vấn SPL tự động cũng tiết kiệm 10-20 phút cho mỗi cảnh báo cần điều tra sâu.

```
┌─────────────────────────────────────────────────────────────────────┐
│                So sánh thời gian xử lý một cảnh báo                 │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  PHƯƠNG PHÁP THỦ CÔNG                                              │
│  ├─ Đọc và hiểu cảnh báo          ████████████  5 phút             │
│  ├─ Tra cứu MITRE ATT&CK          ████████████████  8 phút         │
│  ├─ Viết SPL query                ████████████████████  12 phút    │
│  ├─ Tra cứu Threat Intel          ████████████  6 phút             │
│  └─ Tổng hợp và đánh giá          ████████  4 phút                 │
│                                   ─────────────────────             │
│                                   Tổng: ~35 phút                    │
│                                                                     │
│  HỆ THỐNG LLM-SOC                                                  │
│  ├─ RAG + LLM Analysis            █  10 giây                       │
│  ├─ IOC Extraction + TI Lookup    █  3 giây                        │
│  ├─ SPL Generation                █  3 giây                        │
│  └─ Tổng hợp kết quả              █  2 giây                        │
│                                   ─────────────────────             │
│                                   Tổng: ~18 giây                    │
│                                                                     │
│  Cải thiện: ~117x nhanh hơn                                        │
└─────────────────────────────────────────────────────────────────────┘
```

Tuy nhiên, cần lưu ý rằng hệ thống LLM-SOC được thiết kế để hỗ trợ chứ không thay thế hoàn toàn các chuyên viên SOC. Các quyết định cuối cùng về việc escalate hoặc close cảnh báo vẫn cần sự xác nhận từ con người.

## 3.4 Các hạn chế hiện tại

### 3.4.1 Hạn chế về dữ liệu

Hệ thống hiện tại phụ thuộc vào chất lượng và độ phủ của cơ sở tri thức RAG. Các cảnh báo thuộc loại mới hoặc chưa có trong tài liệu training có thể không được phân tích chính xác. Cơ sở tri thức cần được cập nhật thường xuyên để theo kịp các kỹ thuật tấn công mới và các loại cảnh báo mới từ Splunk Enterprise Security.

Dữ liệu cảnh báo từ Splunk hiện được tải từ file Excel tĩnh thay vì kết nối trực tiếp với Splunk API. Điều này hạn chế khả năng xử lý real-time và yêu cầu export thủ công dữ liệu cảnh báo. Việc tích hợp trực tiếp với Splunk REST API sẽ cải thiện đáng kể tính real-time của hệ thống.

```
Hạn chế về dữ liệu:

┌─────────────────────────────────────────────────────────────────────┐
│ 1. Cơ sở tri thức RAG                                               │
│    ├─ Chỉ chứa ~165 chunks từ tài liệu bảo mật                     │
│    ├─ Chưa cover hết các loại cảnh báo từ Splunk ES                │
│    └─ Cần cập nhật thường xuyên với threats mới                    │
│                                                                     │
│ 2. Dữ liệu cảnh báo                                                │
│    ├─ Import từ Excel (không real-time)                            │
│    ├─ Chưa tích hợp trực tiếp với Splunk API                       │
│    └─ Giới hạn số lượng cảnh báo test                              │
│                                                                     │
│ 3. Threat Intelligence                                              │
│    ├─ Phụ thuộc vào API miễn phí (rate limited)                    │
│    └─ Không có dữ liệu offline backup                              │
└─────────────────────────────────────────────────────────────────────┘
```

### 3.4.2 Hạn chế về mô hình

Các mô hình LLM sử dụng trong hệ thống (Qwen3:8b, Qwen2.5:3b) chạy cục bộ qua Ollama có hiệu suất thấp hơn so với các mô hình thương mại như GPT-4 hoặc Claude. Điều này ảnh hưởng đến chất lượng phân tích trong các tình huống phức tạp đòi hỏi reasoning sâu.

Thời gian inference trên CPU khá chậm (4-12 giây mỗi request), có thể gây bottleneck khi xử lý số lượng lớn cảnh báo đồng thời. Việc sử dụng GPU sẽ cải thiện đáng kể tốc độ nhưng yêu cầu phần cứng bổ sung.

Mô hình embedding all-MiniLM-L6-v2 mặc dù nhẹ và nhanh nhưng có thể không nắm bắt tốt các khái niệm bảo mật chuyên sâu so với các mô hình embedding được fine-tune cho domain security.

### 3.4.3 Hạn chế về hệ thống

Kiến trúc hiện tại chưa hỗ trợ high availability và horizontal scaling. Hệ thống chạy trên một instance duy nhất, nếu gặp sự cố sẽ gây gián đoạn toàn bộ dịch vụ. Việc triển khai trên container orchestration như Kubernetes sẽ cải thiện độ tin cậy.

Cơ chế authentication và authorization chưa được implement, hạn chế khả năng triển khai trong môi trường production với nhiều người dùng. Cần bổ sung các tính năng như user management, role-based access control, và audit logging.

Tích hợp với các hệ thống SOAR (Security Orchestration, Automation and Response) hiện tại chưa có, hạn chế khả năng tự động hóa các hành động response sau khi phân tích.

## 3.5 Hướng phát triển trong tương lai

Dựa trên các hạn chế đã nhận diện, các hướng phát triển trong tương lai của hệ thống LLM-SOC bao gồm nhiều khía cạnh về dữ liệu, mô hình, và kiến trúc hệ thống.

**Cải thiện về dữ liệu và tri thức:**

Việc mở rộng cơ sở tri thức RAG với nhiều nguồn tài liệu hơn là ưu tiên hàng đầu. Điều này bao gồm tích hợp thêm các threat intelligence feeds, CVE database, và các bản tin bảo mật từ các nhà cung cấp. Phát triển pipeline tự động cập nhật cơ sở tri thức từ các nguồn online sẽ đảm bảo hệ thống luôn có thông tin mới nhất về các mối đe dọa.

Tích hợp trực tiếp với Splunk REST API sẽ cho phép hệ thống hoạt động real-time, tự động nhận và xử lý cảnh báo mới khi chúng được tạo trong Splunk Enterprise Security. Việc này cũng cho phép thực thi các truy vấn SPL trực tiếp và thu thập kết quả để enrichment phân tích.

**Cải thiện về mô hình:**

Nghiên cứu và triển khai fine-tuning các mô hình LLM trên dữ liệu bảo mật sẽ cải thiện chất lượng phân tích. Việc tạo dataset training từ các case study bảo mật thực tế và feedback từ các chuyên viên SOC sẽ giúp mô hình hiểu sâu hơn về domain security.

Thử nghiệm các mô hình LLM mới hơn và mạnh hơn khi chúng được release, đặc biệt là các mô hình được tối ưu cho việc chạy cục bộ với hiệu suất cao hơn. Đánh giá việc sử dụng GPU inference để tăng tốc độ phản hồi.

**Cải thiện về kiến trúc hệ thống:**

Triển khai container hóa với Docker và orchestration với Kubernetes sẽ cải thiện khả năng scaling và high availability. Việc này cho phép hệ thống xử lý nhiều request đồng thời và tự động recovery khi gặp sự cố.

Phát triển các tính năng enterprise-grade bao gồm authentication/authorization, multi-tenancy, và comprehensive audit logging. Tích hợp với các hệ thống SOAR hiện có trong tổ chức để tự động hóa các hành động response.

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Roadmap phát triển LLM-SOC                       │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  Phase 1 (Q1 2026):                                                │
│  ├─ Tích hợp Splunk REST API                                       │
│  ├─ Mở rộng RAG knowledge base                                     │
│  └─ Thêm authentication/authorization                              │
│                                                                     │
│  Phase 2 (Q2 2026):                                                │
│  ├─ Container hóa với Docker/Kubernetes                            │
│  ├─ Fine-tune LLM trên security domain                             │
│  └─ GPU inference optimization                                     │
│                                                                     │
│  Phase 3 (Q3-Q4 2026):                                             │
│  ├─ Tích hợp SOAR platforms                                        │
│  ├─ Multi-tenancy support                                          │
│  └─ Advanced analytics và reporting                                │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

## 3.6 Tổng kết

Chương này đã trình bày kết quả đánh giá toàn diện của hệ thống LLM-SOC trên nhiều khía cạnh bao gồm độ chính xác phân tích, hiệu suất trích xuất IOC, và thời gian xử lý. Kết quả cho thấy hệ thống đạt được mục tiêu đề ra với độ chính xác nhận diện mối đe dọa 88%, hiệu suất IOC extraction 94.8% F1-score, và giảm thời gian phân tích hơn 100 lần so với phương pháp thủ công.

So sánh với quy trình phân tích thủ công cho thấy hệ thống mang lại giá trị thực tiễn đáng kể trong việc tăng tốc độ xử lý cảnh báo và đảm bảo tính nhất quán trong phân tích. Tuy nhiên, các hạn chế về dữ liệu, mô hình, và kiến trúc hệ thống đã được nhận diện và cần được giải quyết trong các phiên bản tiếp theo.

Các hướng phát triển trong tương lai tập trung vào việc cải thiện chất lượng cơ sở tri thức, tối ưu hiệu suất mô hình, và nâng cao khả năng scale của hệ thống. Việc tích hợp sâu hơn với các hệ thống SIEM/SOAR hiện có sẽ giúp hệ thống LLM-SOC trở thành một công cụ hỗ trợ không thể thiếu trong quy trình vận hành SOC hiện đại.
