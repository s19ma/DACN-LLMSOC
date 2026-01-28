# Chương 2: Tiếp cận, thực nghiệm

## 2.1 Hệ thống đề xuất

Hệ thống LLM-SOC (Large Language Model - Security Operations Center) được đề xuất là một giải pháp tích hợp trí tuệ nhân tạo vào quy trình phân tích và điều tra cảnh báo an ninh mạng. Hệ thống kết hợp mô hình ngôn ngữ lớn (LLM) với kỹ thuật Retrieval-Augmented Generation (RAG) để hỗ trợ các chuyên viên phân tích SOC trong việc xử lý cảnh báo bảo mật một cách hiệu quả và chính xác hơn.

### 2.1.1 Kiến trúc tổng quan hệ thống

Kiến trúc hệ thống LLM-SOC được thiết kế theo mô hình multi-agent, trong đó mỗi agent đảm nhận một vai trò chuyên biệt trong quy trình điều tra bảo mật. Hệ thống bao gồm ba thành phần chính: Supervisor Agent đóng vai trò điều phối và phân tích tổng thể, SPL Generator Agent chuyên tạo truy vấn Splunk, và Playbook Runner Agent thực thi các bước điều tra theo playbook đã định sẵn.

**Hình 2.1: Kiến trúc tổng quan hệ thống LLM-SOC**

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              Flask Web Application                           │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
│  │  Dashboard  │  │Alert Detail │  │  Chat API   │  │  Investigation API  │ │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └──────────┬──────────┘ │
└─────────┼────────────────┼────────────────┼────────────────────┼────────────┘
          │                │                │                    │
          ▼                ▼                ▼                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                              Agent Layer                                     │
│  ┌───────────────────┐  ┌───────────────────┐  ┌───────────────────────┐    │
│  │  Supervisor Agent │  │ SPL Generator     │  │  Playbook Runner      │    │
│  │  ┌─────────────┐  │  │  Agent            │  │  Agent                │    │
│  │  │   Ollama    │  │  │  ┌─────────────┐  │  │  ┌─────────────────┐  │    │
│  │  │  Qwen3:8b   │  │  │  │   Ollama    │  │  │  │  API Call Tool  │  │    │
│  │  └─────────────┘  │  │  │ Qwen2.5:3b  │  │  │  └─────────────────┘  │    │
│  │  ┌─────────────┐  │  │  └─────────────┘  │  │  ┌─────────────────┐  │    │
│  │  │ RAG Context │  │  │  ┌─────────────┐  │  │  │ Playbook Parser │  │    │
│  │  └─────────────┘  │  │  │ RAG Context │  │  │  └─────────────────┘  │    │
│  └───────────────────┘  │  └─────────────┘  │  └───────────────────────┘    │
│                         └───────────────────┘                                │
└─────────────────────────────────────────────────────────────────────────────┘
          │                        │                         │
          ▼                        ▼                         ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                              RAG System (ChromaDB)                           │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────────────────┐  │
│  │ supervisor_     │  │ spl_knowledge   │  │ playbook_knowledge          │  │
│  │ knowledge       │  │                 │  │                             │  │
│  │ ┌─────────────┐ │  │ ┌─────────────┐ │  │ ┌─────────────────────────┐ │  │
│  │ │MITRE ATT&CK │ │  │ │SPL Commands │ │  │ │Threat Intel Enrichment  │ │  │
│  │ │Windows Event│ │  │ │Brute Force  │ │  │ │API Guidelines           │ │  │
│  │ └─────────────┘ │  │ │Detection    │ │  │ └─────────────────────────┘ │  │
│  └─────────────────┘  │ └─────────────┘ │  └─────────────────────────────┘  │
│                       └─────────────────┘                                    │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                        alert_research                                │    │
│  │  ┌─────────────────────────────────────────────────────────────┐    │    │
│  │  │ Splunk Research Alert Descriptions (Linux, Windows, etc.)   │    │    │
│  │  └─────────────────────────────────────────────────────────────┘    │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────────────┘
          │
          ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         External Services                                    │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
│  │ VirusTotal  │  │ AbuseIPDB   │  │   Shodan    │  │   AlienVault OTX    │ │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────────┘
```

Supervisor Agent là thành phần trung tâm của hệ thống, chịu trách nhiệm phân tích ngữ cảnh cảnh báo, đưa ra đánh giá mức độ nghiêm trọng và hướng dẫn các bước điều tra tiếp theo. Agent này được tích hợp với hệ thống RAG để truy xuất kiến thức liên quan từ cơ sở tri thức bảo mật, bao gồm framework MITRE ATT&CK, mô tả các loại cảnh báo từ Splunk Research, và các hướng dẫn phân tích sự kiện Windows. Khi nhận được một cảnh báo mới, Supervisor Agent sẽ trích xuất các Indicators of Compromise (IOCs) bao gồm địa chỉ IP, hash file, URL và domain, sau đó kết hợp với ngữ cảnh từ RAG để đưa ra phân tích toàn diện về mối đe dọa.

```python
# Khởi tạo Supervisor Agent với RAG
class SupervisorAgent:
    def __init__(self):
        self.ollama = OllamaClient(model="qwen3:8b")
        self.rag_manager = get_rag_manager()
        self.rag_enabled = self.rag_manager.enabled

        self.system_prompts = {
            "alert_analysis": """You are a cybersecurity SOC analyst.
            Provide concise threat assessment and actionable recommendations.""",
            "qa_response": """You are a cybersecurity SOC analyst.
            Answer questions concisely with technical accuracy."""
        }

    def _build_rag_context(self, query: str, k: int = 2) -> str:
        """Truy xuất ngữ cảnh từ RAG cho phân tích"""
        contexts = []
        for collection in ("alert_research", "supervisor_knowledge"):
            ctx = self.rag_manager.get_relevant_context(
                query, collection_name=collection, k=k
            )
            if ctx and "No relevant context" not in ctx:
                contexts.append(f"{collection.upper()}\n{ctx}")
        return "\n\n".join(contexts)
```

SPL Generator Agent được thiết kế chuyên biệt cho việc tạo truy vấn SPL (Search Processing Language) phục vụ threat hunting và điều tra sự cố. Agent này tải và sử dụng cơ sở tri thức bao gồm danh sách các Splunk indexes, sources, sourcetypes, và các use case bảo mật đã được định nghĩa sẵn. Hệ thống RAG của SPL Generator Agent được huấn luyện trên tài liệu tham khảo về các lệnh SPL, các mẫu truy vấn phát hiện tấn công brute force, và các kỹ thuật tìm kiếm log nâng cao. Điều này cho phép agent sinh ra các truy vấn SPL tối ưu và phù hợp với cấu trúc dữ liệu của tổ chức.

Playbook Runner Agent thực thi các playbook điều tra theo từng bước, thực hiện các lời gọi API đến các hệ thống bên ngoài khi cần thiết để thu thập thông tin và thực hiện các hành động bảo mật. Agent này hỗ trợ tích hợp với các dịch vụ threat intelligence như VirusTotal và AbuseIPDB để enrichment thông tin về các IOCs được trích xuất từ cảnh báo.

### 2.1.2 Retrieval-Augmented Generation (RAG)

RAG là kỹ thuật cốt lõi giúp tăng cường độ chính xác và tính liên quan của các phản hồi từ mô hình ngôn ngữ lớn. Thay vì hoàn toàn phụ thuộc vào kiến thức được huấn luyện sẵn trong mô hình, RAG cho phép truy xuất các tài liệu liên quan từ cơ sở tri thức riêng biệt và đưa chúng vào ngữ cảnh của prompt trước khi sinh phản hồi.

Hệ thống RAG trong LLM-SOC sử dụng ChromaDB làm vector database để lưu trữ và tìm kiếm các embedding. Quá trình embedding được thực hiện bằng mô hình sentence-transformers/all-MiniLM-L6-v2, một mô hình nhẹ có thể chạy cục bộ mà không cần gọi API bên ngoài. Mô hình này tạo ra các vector 384 chiều, đủ để nắm bắt ngữ nghĩa của các đoạn văn bản về bảo mật.

RAG Manager là thành phần quản lý toàn bộ hệ thống RAG, cung cấp các chức năng tải tài liệu, tạo embedding, và tìm kiếm ngữ nghĩa. Mỗi agent có collection riêng trong ChromaDB với kiến thức chuyên biệt: spl_knowledge chứa tài liệu về lệnh SPL và các mẫu truy vấn, playbook_knowledge chứa quy trình điều tra và hướng dẫn sử dụng API threat intelligence, supervisor_knowledge chứa framework MITRE ATT&CK và hướng dẫn phân tích sự kiện Windows, và alert_research chứa mô tả chi tiết về các loại cảnh báo bảo mật.

Quy trình hoạt động của RAG bắt đầu bằng việc nhận câu hỏi hoặc ngữ cảnh cảnh báo từ người dùng. Hệ thống sẽ tạo embedding cho truy vấn này và thực hiện tìm kiếm tương đồng (similarity search) trong các collection phù hợp. Các tài liệu có độ tương đồng cao nhất sẽ được truy xuất và ghép vào prompt dưới dạng ngữ cảnh bổ sung. Cuối cùng, mô hình ngôn ngữ lớn sẽ sinh phản hồi dựa trên cả ngữ cảnh RAG và kiến thức nội tại.

**Hình 2.2: Luồng xử lý Retrieval-Augmented Generation**

```
┌──────────────────┐
│   User Query     │     "How to detect brute force attack?"
│   hoặc Alert     │
└────────┬─────────┘
         │
         ▼
┌──────────────────────────────────────────────────────────────┐
│                    Embedding Model                            │
│              (all-MiniLM-L6-v2, 384 dimensions)              │
└────────┬─────────────────────────────────────────────────────┘
         │
         ▼  Query Vector: [0.12, -0.45, 0.78, ...]
┌──────────────────────────────────────────────────────────────┐
│                    ChromaDB Vector Store                      │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │              Similarity Search (cosine)                  │ │
│  │                                                          │ │
│  │  Doc1: [0.11, -0.43, 0.80, ...] → similarity: 0.95      │ │
│  │  Doc2: [0.15, -0.40, 0.75, ...] → similarity: 0.89      │ │
│  │  Doc3: [0.08, -0.50, 0.82, ...] → similarity: 0.87      │ │
│  └─────────────────────────────────────────────────────────┘ │
└────────┬─────────────────────────────────────────────────────┘
         │
         ▼  Top-K Documents (k=3)
┌──────────────────────────────────────────────────────────────┐
│                    Context Assembly                           │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │ RAG CONTEXT:                                             │ │
│  │ **Reference 1** (from brute_force_detection.md):         │ │
│  │ Brute force detection using failed login threshold...   │ │
│  │                                                          │ │
│  │ **Reference 2** (from mitre_attack_framework.md):        │ │
│  │ T1110 - Brute Force: Adversaries may use techniques...  │ │
│  └─────────────────────────────────────────────────────────┘ │
└────────┬─────────────────────────────────────────────────────┘
         │
         ▼
┌──────────────────────────────────────────────────────────────┐
│                    LLM (Qwen3:8b via Ollama)                  │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │ System Prompt + RAG Context + User Query                 │ │
│  │                          ↓                               │ │
│  │              Generate Response                           │ │
│  └─────────────────────────────────────────────────────────┘ │
└────────┬─────────────────────────────────────────────────────┘
         │
         ▼
┌──────────────────┐
│  AI Response     │     "To detect brute force attacks, monitor
│  with Context    │      Windows Event ID 4625 for failed logins..."
└──────────────────┘
```

RecursiveCharacterTextSplitter được sử dụng để chia nhỏ các tài liệu dài thành các chunk có kích thước 1000 ký tự với độ overlap 200 ký tự. Việc chia nhỏ này đảm bảo mỗi chunk chứa đủ ngữ cảnh để có ý nghĩa, đồng thời cho phép truy xuất chính xác các phần liên quan nhất của tài liệu.

```python
# Cấu hình RAG Manager với ChromaDB và Sentence Transformers
class RAGManager:
    def __init__(self, persist_directory: str = "./chroma_db"):
        self.persist_directory = persist_directory

        # Khởi tạo embedding model chạy cục bộ
        self.embeddings = HuggingFaceEmbeddings(
            model_name="sentence-transformers/all-MiniLM-L6-v2",
            model_kwargs={'device': 'cpu'},
            encode_kwargs={'normalize_embeddings': True}
        )

        # Cấu hình text splitter
        self.text_splitter = RecursiveCharacterTextSplitter(
            chunk_size=1000,      # Kích thước mỗi chunk
            chunk_overlap=200,    # Độ overlap giữa các chunk
            separators=["\n\n", "\n", ". ", " ", ""]
        )

        self.vectorstores = {}  # Lưu trữ các vector store
```

### 2.1.3 Luồng xử lý Smart Investigation

Smart Investigation là tính năng tự động enrichment các IOCs từ cảnh báo bằng cách gọi các dịch vụ threat intelligence thông qua Model Context Protocol (MCP). Luồng xử lý bắt đầu từ việc nhận cảnh báo dưới dạng JSON, sau đó hệ thống trích xuất các IOCs bao gồm địa chỉ IP công cộng, hash file, URL và domain.

**Hình 2.3: Luồng xử lý Smart Investigation**

```
┌─────────────────┐
│   Alert JSON    │
│  {              │
│   "src_ip":     │
│   "8.8.8.8",    │
│   "hash":       │
│   "a1b2c3..."   │
│  }              │
└────────┬────────┘
         │
         ▼
┌─────────────────────────────────────┐
│      IOC Extraction                  │
│  ┌─────────────────────────────────┐│
│  │ • Filter Public IPs             ││
│  │ • Extract File Hashes           ││
│  │ • Parse URLs and Domains        ││
│  └─────────────────────────────────┘│
└────────┬────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────────────────────────┐
│              Threat Intelligence Enrichment                  │
│                                                              │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │ VirusTotal  │  │ AbuseIPDB   │  │ Shodan (Optional)   │  │
│  ├─────────────┤  ├─────────────┤  ├─────────────────────┤  │
│  │• IP Reputa- │  │• Abuse Score│  │• Open Ports         │  │
│  │  tion       │  │• Report     │  │• Services           │  │
│  │• Hash Scan  │  │  History    │  │• Banners            │  │
│  │• URL Check  │  │• ISP/Geo    │  │                     │  │
│  └──────┬──────┘  └──────┬──────┘  └──────────┬──────────┘  │
│         │                │                    │              │
└─────────┼────────────────┼────────────────────┼──────────────┘
          │                │                    │
          └────────────────┼────────────────────┘
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                    Result Aggregation                        │
│  ┌─────────────────────────────────────────────────────────┐│
│  │ {                                                        ││
│  │   "risk_score": 85,                                     ││
│  │   "verdict": "High Risk",                               ││
│  │   "iocs": {                                             ││
│  │     "8.8.8.8": {"vt_score": 0, "abuse_score": 0},       ││
│  │     "malware.exe": {"vt_detections": 45}                ││
│  │   }                                                      ││
│  │ }                                                        ││
│  └─────────────────────────────────────────────────────────┘│
└────────┬────────────────────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────┐
│   Supervisor Agent Analysis          │
│   + RAG Context                      │
│              ↓                       │
│   Final Investigation Report         │
└─────────────────────────────────────┘
```

Đối với mỗi IOC được trích xuất, hệ thống gọi đến các dịch vụ threat intelligence để thu thập thông tin. VirusTotal cung cấp điểm reputation cho IP, phát hiện malware qua hash file, kiểm tra độ an toàn của URL, và tổng hợp đánh giá từ cộng đồng. AbuseIPDB cung cấp điểm confidence về mức độ lạm dụng của IP, lịch sử các báo cáo về IP đó, thông tin ISP và vị trí địa lý. Các dịch vụ tùy chọn như Shodan có thể cung cấp thông tin về các cổng mở và dịch vụ đang chạy trên IP, trong khi AlienVault OTX cung cấp thông tin về các pulse threat intelligence và mẫu malware.

Sau khi thu thập đầy đủ thông tin từ các nguồn, hệ thống tổng hợp và tính toán điểm rủi ro (risk score) cho cảnh báo. Điểm rủi ro này kết hợp với phân tích từ Supervisor Agent để đưa ra verdict cuối cùng về mức độ nghiêm trọng của cảnh báo và các bước điều tra tiếp theo cần thực hiện.

## 2.2 Xây dựng tập dữ liệu

### 2.2.1 Công nghệ sử dụng

Hệ thống được xây dựng trên nền tảng Flask, một micro-framework Python phù hợp cho việc phát triển nhanh các ứng dụng web. Flask cung cấp sự linh hoạt trong việc tổ chức mã nguồn và dễ dàng tích hợp với các thư viện AI và machine learning.

LangChain được sử dụng làm framework chính cho việc tích hợp và điều phối các mô hình ngôn ngữ lớn. LangChain cung cấp các abstraction layer cho việc giao tiếp với nhiều loại LLM khác nhau, quản lý prompt, và xây dựng các pipeline xử lý phức tạp. Trong hệ thống LLM-SOC, LangChain được sử dụng để tích hợp với Ollama thông qua langchain_ollama.ChatOllama, cho phép sử dụng các mô hình như Qwen3:8b và Qwen2.5:3b chạy cục bộ.

ChromaDB là vector database mã nguồn mở được chọn để lưu trữ và truy vấn các embedding. ChromaDB có ưu điểm là nhẹ, dễ triển khai, và hỗ trợ persistent storage để lưu trữ các collection giữa các lần khởi động. Việc sử dụng ChromaDB cho phép hệ thống thực hiện các truy vấn similarity search hiệu quả trên các cơ sở tri thức lớn.

Sentence Transformers cung cấp các mô hình embedding đã được pre-trained, cho phép chuyển đổi văn bản thành vector số học. Mô hình all-MiniLM-L6-v2 được chọn vì cân bằng giữa hiệu suất và chất lượng embedding, có thể chạy hoàn toàn trên CPU mà không cần GPU.

Ollama là nền tảng chạy các mô hình ngôn ngữ lớn cục bộ, cho phép triển khai LLM mà không cần kết nối internet hoặc API key từ các nhà cung cấp dịch vụ đám mây. Điều này đặc biệt quan trọng trong môi trường SOC nơi dữ liệu cảnh báo có thể chứa thông tin nhạy cảm.

### 2.2.2 Triển khai thu thập dữ liệu

Dữ liệu cảnh báo được thu thập từ Splunk thông qua file Excel (alerts_database.xlsx) chứa các trường thông tin cơ bản như alert_id, title, severity, source_ip, destination_ip, timestamp, và description. AlertManager là lớp quản lý việc tải và truy cập dữ liệu cảnh báo, hỗ trợ các thao tác như lọc theo ID, cập nhật trạng thái, và truy vấn toàn bộ danh sách cảnh báo.

Cơ sở tri thức được tổ chức trong thư mục knowledge với cấu trúc phân cấp theo từng loại agent như thể hiện trong Hình 2.5.

**Hình 2.5: Cấu trúc thư mục cơ sở tri thức**

```
knowledge/
├── rag_spl/                          # Tri thức cho SPL Generator Agent
│   ├── splunk_commands_reference.md  # Tham khảo lệnh SPL (search, stats, where...)
│   └── brute_force_detection.md      # Mẫu truy vấn phát hiện brute force
│
├── rag_supervisor/                   # Tri thức cho Supervisor Agent
│   ├── mitre_attack_framework.md     # MITRE ATT&CK tactics và techniques
│   └── windows_event_analysis.md     # Phân tích Windows Event ID
│
├── rag_playbook/                     # Tri thức cho Playbook Runner Agent
│   └── threat_intel_enrichment.md    # Hướng dẫn sử dụng API threat intel
│
├── data_model/                       # Splunk CIM Data Models
│   ├── Authentication.json
│   ├── Network_Traffic.json
│   ├── Endpoint.json
│   ├── Intrusion_Detection.json
│   └── ... (29 data models)
│
├── sources.txt                       # Danh sách Splunk sources
├── sourcetypes.txt                   # Danh sách Splunk sourcetypes
└── splunk_indexes.json               # Cấu hình Splunk indexes

rag_knowledge/                        # Tri thức bổ sung
└── alert_research_descriptions.md    # Mô tả chi tiết các loại cảnh báo
```

Thư mục rag_spl chứa tài liệu về lệnh SPL bao gồm splunk_commands_reference.md với hướng dẫn chi tiết về các lệnh search, where, stats, timechart và các lệnh phân tích khác, cùng với brute_force_detection.md chứa các mẫu truy vấn phát hiện tấn công brute force. Thư mục rag_supervisor chứa mitre_attack_framework.md với mapping đầy đủ các tactics và techniques của MITRE ATT&CK framework kèm theo các truy vấn Splunk mẫu cho từng technique, và windows_event_analysis.md với hướng dẫn phân tích các Windows Event ID phổ biến trong điều tra bảo mật. Thư mục rag_playbook chứa threat_intel_enrichment.md với hướng dẫn sử dụng các API threat intelligence.

Ngoài ra, thư mục rag_knowledge chứa alert_research_descriptions.md với mô tả chi tiết về các loại cảnh báo bảo mật theo phong cách Splunk Research. Mỗi mô tả bao gồm tên cảnh báo, giải thích kỹ thuật về hành vi được phát hiện, ý nghĩa đối với SOC, và hậu quả tiềm tàng nếu hoạt động thực sự là độc hại. Ví dụ, cảnh báo "Linux Docker Privilege Escalation" mô tả việc phát hiện các nỗ lực leo thang đặc quyền sử dụng Docker, kỹ thuật phát hiện dựa trên telemetry từ EDR, và nguy cơ attacker có thể sửa đổi file /etc/passwd để tạo superuser.

Thư mục knowledge/data_model chứa các file JSON định nghĩa các data model của Splunk Common Information Model (CIM) bao gồm Authentication.json, Network_Traffic.json, Endpoint.json, Intrusion_Detection.json, Malware.json, và nhiều data model khác. Các file này cung cấp mapping giữa các trường dữ liệu raw và các trường chuẩn hóa, giúp SPL Generator Agent tạo ra các truy vấn tương thích với cấu trúc dữ liệu của tổ chức.

## 2.3 Xử lý dữ liệu

### 2.3.1 Xử lý dữ liệu cảnh báo

Dữ liệu cảnh báo từ Splunk được xử lý qua nhiều bước để chuẩn bị cho việc phân tích. Đầu tiên, AlertManager tải dữ liệu từ file Excel và chuẩn hóa các trường để đảm bảo tính nhất quán. Các trường tùy chọn như source_ip, dest_ip được ánh xạ từ các tên trường khác nhau có thể xuất hiện trong dữ liệu gốc (src_ip, source_address, dest_address).

Trường result chứa dữ liệu JSON với thông tin log chi tiết được parse và trích xuất các trường quan trọng. Hệ thống sử dụng field_mappings linh hoạt để xử lý các loại cảnh báo khác nhau, trong đó mỗi trường logic (như src_ip, user, host) có thể ánh xạ đến nhiều tên trường thực tế khác nhau trong dữ liệu gốc. Điều này cho phép hệ thống xử lý nhất quán các cảnh báo từ nhiều nguồn khác nhau mà không cần cấu hình riêng cho từng loại.

```python
# Ánh xạ trường linh hoạt cho nhiều loại cảnh báo
field_mappings = {
    'src_ip': ['src_ip', 'source_ip', 'source_address'],
    'dest_ip': ['dest_ip', 'destination_ip', 'dest_address'],
    'user': ['user', 'username', 'account', 'user_name'],
    'host': ['host', 'hostname', 'computer', 'device'],
    'action': ['action', 'event_action', 'activity'],
    'process': ['process', 'process_name', 'program'],
    'risk_score': ['risk_score', 'score', 'severity_score']
}

# Trích xuất động các trường từ log
for key, possible_names in field_mappings.items():
    for name in possible_names:
        if name in first_log:
            alert_summary[key] = first_log[name]
            break
```

Việc trích xuất IOCs được thực hiện tự động từ các trường IP address, hash, URL và domain. Địa chỉ IP được lọc để chỉ giữ lại các IP công cộng (loại bỏ các dải IP riêng như 10.x.x.x, 192.168.x.x, 172.16-31.x.x) vì chỉ IP công cộng mới có thể được tra cứu trên các dịch vụ threat intelligence.

### 2.3.2 Xử lý dữ liệu tri thức cho RAG

Quá trình xử lý dữ liệu tri thức cho RAG bao gồm ba giai đoạn chính: tải tài liệu, chia nhỏ, và tạo embedding.

Trong giai đoạn tải tài liệu, RAGManager quét các thư mục tri thức và tải tất cả các file có đuôi .md, .txt, và .json. Đối với file JSON, dữ liệu được chuyển đổi sang định dạng text có cấu trúc thông qua phương thức \_json_to_text(), đệ quy duyệt qua các key và value để tạo ra biểu diễn văn bản dễ đọc. Metadata bao gồm đường dẫn nguồn, tên file, và loại định dạng được lưu kèm với mỗi tài liệu.

Giai đoạn chia nhỏ sử dụng RecursiveCharacterTextSplitter với các separator theo thứ tự ưu tiên từ paragraph (double newline), sentence (single newline), word (period and space), đến character (single space). Kích thước chunk 1000 ký tự được chọn để đảm bảo mỗi chunk đủ ngữ cảnh để có ý nghĩa độc lập nhưng không quá dài gây nhiễu khi truy xuất. Độ overlap 200 ký tự giúp duy trì tính liên tục của thông tin giữa các chunk liền kề.

**Hình 2.4: Quá trình Text Splitting với Overlap**

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         Original Document (3000 chars)                       │
│  "MITRE ATT&CK T1110 - Brute Force: Adversaries may use brute force         │
│   techniques to gain access to accounts when passwords are unknown or       │
│   when password hashes are obtained... [continued text about detection      │
│   strategies, Splunk queries, and remediation steps]"                       │
└─────────────────────────────────────────────────────────────────────────────┘
                                     │
                    RecursiveCharacterTextSplitter
                    chunk_size=1000, overlap=200
                                     │
                                     ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                                                                              │
│  ┌────────────────────────────────────────────┐                             │
│  │            Chunk 1 (1000 chars)            │                             │
│  │  "MITRE ATT&CK T1110 - Brute Force:        │                             │
│  │   Adversaries may use brute force          │                             │
│  │   techniques to gain access...             │                             │
│  │   ...detection using failed login counts"  │                             │
│  └────────────────────────────────────────────┘                             │
│                    │←── 200 chars overlap ──→│                              │
│                    ┌────────────────────────────────────────────┐           │
│                    │            Chunk 2 (1000 chars)            │           │
│                    │  "...detection using failed login counts   │           │
│                    │   Monitor Windows Event ID 4625 for        │           │
│                    │   failed authentication attempts...        │           │
│                    │   ...Splunk query examples"                │           │
│                    └────────────────────────────────────────────┘           │
│                                  │←── 200 chars overlap ──→│               │
│                                  ┌────────────────────────────────────────┐ │
│                                  │         Chunk 3 (800 chars)           │ │
│                                  │  "...Splunk query examples:           │ │
│                                  │   index=windows EventCode=4625        │ │
│                                  │   | stats count by user, src_ip       │ │
│                                  │   | where count > 5"                  │ │
│                                  └────────────────────────────────────────┘ │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

Giai đoạn tạo embedding sử dụng mô hình all-MiniLM-L6-v2 để chuyển đổi mỗi chunk thành vector 384 chiều. Các embedding được chuẩn hóa (normalize) để sử dụng cosine similarity khi tìm kiếm. ChromaDB lưu trữ các embedding cùng với nội dung gốc và metadata, cho phép truy xuất nhanh chóng khi cần.

## 2.4 Mô hình và kỹ thuật sử dụng

### 2.4.1 Mô hình ngôn ngữ lớn (LLM)

Hệ thống sử dụng các mô hình từ họ Qwen chạy thông qua Ollama. Qwen3:8b được sử dụng cho Supervisor Agent với khả năng phân tích phức tạp và sinh văn bản dài. Qwen2.5:3b được sử dụng cho SPL Generator Agent với ưu tiên tốc độ phản hồi nhanh cho việc sinh truy vấn.

Các tham số được tối ưu cho môi trường production bao gồm temperature=0.1 để đảm bảo tính nhất quán và độ chính xác cao trong các phản hồi liên quan đến bảo mật, num_ctx giảm xuống 1024-2048 token để tăng tốc độ xử lý, và timeout được thiết lập để đảm bảo độ ổn định của hệ thống.

OllamaClient là lớp wrapper cung cấp interface thống nhất cho việc giao tiếp với Ollama. Phương thức generate_response() xử lý việc ghép system prompt và user prompt, gọi mô hình, và trích xuất nội dung từ response object. Lớp này cũng quản lý trạng thái available để graceful degradation khi Ollama không khả dụng.

```python
class OllamaClient:
    """Client wrapper cho Ollama LLM"""

    def __init__(self, model="qwen3:8b", base_url="http://localhost:11434"):
        self.model = ChatOllama(
            model=model,
            base_url=base_url,
            timeout=60,
            num_ctx=1024,      # Context window size
            temperature=0.1    # Độ sáng tạo thấp cho độ chính xác cao
        )
        self.available = True

    def generate_response(self, prompt: str, system_prompt: str = None) -> str:
        """Sinh phản hồi từ Ollama"""
        full_prompt = (
            f"{system_prompt}\n\nUser Prompt:\n{prompt}"
            if system_prompt else prompt
        )

        response = self.model.invoke(full_prompt)
        return response.content.strip()
```

### 2.4.2 Retrieval-Augmented Generation (RAG)

Kiến trúc RAG trong hệ thống LLM-SOC được thiết kế với nguyên tắc tách biệt collections theo từng agent. Điều này cho phép mỗi agent có cơ sở tri thức chuyên biệt và tránh nhiễu từ thông tin không liên quan.

Quá trình tìm kiếm trong RAG sử dụng similarity search với số lượng kết quả k=3 cho việc tìm kiếm thông thường và k=2 cho việc tìm kiếm nhanh trong các tình huống cần tốc độ. Phương thức \_build_rag_context() của SupervisorAgent thực hiện tìm kiếm song song trên nhiều collection (alert_research và supervisor_knowledge) và ghép kết quả thành một ngữ cảnh thống nhất.

Ngữ cảnh RAG được đưa vào prompt theo format chuẩn với tiền tố "RAG CONTEXT:" theo sau là nội dung từ các reference được đánh số. Mỗi reference bao gồm tên file nguồn để tăng tính minh bạch và cho phép người dùng tra cứu thêm nếu cần.

```python
def get_relevant_context(self, query: str, collection_name: str, k: int = 3) -> str:
    """Truy xuất ngữ cảnh liên quan từ vector store"""
    results = self.search(query, collection_name, k=k)

    if not results:
        return "No relevant context found in knowledge base."

    context_parts = []
    for i, result in enumerate(results, 1):
        filename = result['metadata'].get('filename', 'unknown')
        context_parts.append(f"**Reference {i}** (from {filename}):")
        context_parts.append(result['content'])
        context_parts.append("")  # Empty line separator

    return "\n".join(context_parts)

# Ví dụ output:
# **Reference 1** (from brute_force_detection.md):
# To detect brute force attacks, monitor failed login attempts...
#
# **Reference 2** (from mitre_attack_framework.md):
# T1110 - Brute Force: Adversaries may attempt to...
```

### 2.4.3 Embedding Model

Mô hình all-MiniLM-L6-v2 được chọn dựa trên các tiêu chí: kích thước nhỏ (80MB) cho phép triển khai dễ dàng, hiệu suất tốt trên các benchmark semantic similarity, và khả năng chạy hoàn toàn trên CPU. Mô hình này được huấn luyện trên hơn 1 tỷ cặp câu và thể hiện khả năng nắm bắt ngữ nghĩa tốt cho văn bản kỹ thuật.

```python
from langchain_community.embeddings import HuggingFaceEmbeddings

# Khởi tạo Embedding Model
embeddings = HuggingFaceEmbeddings(
    model_name="sentence-transformers/all-MiniLM-L6-v2",
    model_kwargs={
        'device': 'cpu'  # Chạy trên CPU, không cần GPU
    },
    encode_kwargs={
        'normalize_embeddings': True  # Chuẩn hóa để dùng cosine similarity
    }
)

# Ví dụ tạo embedding cho văn bản
text = "Detect brute force attack using failed login threshold"
vector = embeddings.embed_query(text)
# Output: vector có 384 dimensions
# [0.0234, -0.0891, 0.1567, ..., 0.0423]  # 384 giá trị float

# Embedding cho nhiều documents cùng lúc
documents = [
    "Monitor Windows Event ID 4625 for failed logins",
    "MITRE ATT&CK T1110 Brute Force technique",
    "Splunk query for authentication failures"
]
vectors = embeddings.embed_documents(documents)
# Output: list of 3 vectors, mỗi vector 384 dimensions
```

HuggingFaceEmbeddings wrapper được cấu hình với device='cpu' để đảm bảo tương thích với các môi trường không có GPU và normalize_embeddings=True để sử dụng cosine similarity hiệu quả. Việc chuẩn hóa embedding giúp đơn giản hóa phép tính similarity thành dot product, tăng tốc độ tìm kiếm.

### 2.4.4 Vector Database

ChromaDB được chọn làm vector database vì tính đơn giản trong triển khai và khả năng persistent storage. Thư mục chroma_db chứa dữ liệu được serialize, cho phép khôi phục các collection mà không cần rebuild lại embedding từ đầu.

```python
from langchain_community.vectorstores import Chroma

class RAGManager:
    def __init__(self, persist_directory: str = "./chroma_db"):
        self.persist_directory = persist_directory
        self.vectorstores = {}  # Lưu trữ các collection

    def get_vectorstore(self, collection_name: str):
        """Lấy hoặc tạo vector store cho collection"""
        if collection_name not in self.vectorstores:
            self.vectorstores[collection_name] = Chroma(
                collection_name=collection_name,
                embedding_function=self.embeddings,
                persist_directory=self.persist_directory
            )
        return self.vectorstores[collection_name]

    def search(self, query: str, collection_name: str, k: int = 5):
        """Tìm kiếm documents tương tự trong collection"""
        vectorstore = self.get_vectorstore(collection_name)
        results = vectorstore.similarity_search(query, k=k)

        return [{
            'content': doc.page_content,
            'metadata': doc.metadata,
            'source': doc.metadata.get('source', 'unknown')
        } for doc in results]

# Ví dụ sử dụng
rag = RAGManager()
results = rag.search(
    query="How to detect brute force attacks?",
    collection_name="spl_knowledge",
    k=3
)
# Output: 3 documents liên quan nhất từ collection spl_knowledge
```

**Bảng 2.1: Các Collection trong ChromaDB**

| Collection Name      | Mô tả                           | Số Documents |
| -------------------- | ------------------------------- | ------------ |
| spl_knowledge        | Lệnh SPL, mẫu truy vấn Splunk   | ~45 chunks   |
| supervisor_knowledge | MITRE ATT&CK, Windows Events    | ~62 chunks   |
| playbook_knowledge   | Quy trình điều tra, API guides  | ~30 chunks   |
| alert_research       | Mô tả các loại cảnh báo bảo mật | ~28 chunks   |

Mỗi collection trong ChromaDB tương ứng với một domain tri thức: spl_knowledge cho các tài liệu về Splunk SPL, playbook_knowledge cho các quy trình điều tra, supervisor_knowledge cho framework và hướng dẫn phân tích, và alert_research cho mô tả các loại cảnh báo. Việc tách biệt collection giúp tối ưu độ chính xác của tìm kiếm bằng cách giới hạn không gian tìm kiếm vào domain liên quan.

## 2.5 Huấn luyện và đánh giá

### 2.5.1 Khởi tạo hệ thống RAG

Quá trình khởi tạo hệ thống RAG được thực hiện thông qua phương thức initialize_all_collections() của RAGManager. Hệ thống hỗ trợ hai chế độ khởi tạo: auto-init thông qua biến môi trường RAG_AUTO_INIT=true để tự động tải tất cả collections khi khởi động, hoặc lazy loading để chỉ tải collection khi được yêu cầu lần đầu.

Để tránh reload không cần thiết, RAGManager duy trì set loaded_collections để theo dõi các collection đã được tải. Khi nhận yêu cầu tải một collection đã có trong set này, hệ thống sẽ bỏ qua việc reload và sử dụng dữ liệu đã có trong ChromaDB.

```python
def initialize_all_collections(self, knowledge_base_dir: str = "./knowledge"):
    """Khởi tạo tất cả collections từ thư mục tri thức"""
    results = {}

    # SPL Generator knowledge
    spl_dir = os.path.join(knowledge_base_dir, "rag_spl")
    if os.path.exists(spl_dir):
        count = self.load_documents_from_directory(spl_dir, "spl_knowledge")
        results["spl_knowledge"] = count

    # Supervisor knowledge
    supervisor_dir = os.path.join(knowledge_base_dir, "rag_supervisor")
    if os.path.exists(supervisor_dir):
        count = self.load_documents_from_directory(supervisor_dir, "supervisor_knowledge")
        results["supervisor_knowledge"] = count

    # Alert research knowledge
    alert_research_dir = "./rag_knowledge"
    if os.path.exists(alert_research_dir):
        count = self.load_documents_from_directory(alert_research_dir, "alert_research")
        results["alert_research"] = count

    logger.info(f"Initialized {len(results)} collections: {results}")
    return results
    # Output: Initialized 3 collections: {'spl_knowledge': 45, 'supervisor_knowledge': 62, 'alert_research': 28}
```

### 2.5.2 Lựa chọn siêu tham số

Các siêu tham số quan trọng của hệ thống bao gồm tham số cho text splitting với chunk_size=1000 và chunk_overlap=200 được chọn dựa trên thực nghiệm để cân bằng giữa ngữ cảnh đầy đủ và độ chính xác truy xuất. Tham số tìm kiếm k=3 là số lượng mặc định các document được truy xuất cho mỗi query, với k=2 cho các tình huống cần tốc độ cao. Tham số LLM temperature=0.1 đảm bảo tính nhất quán trong các phản hồi về bảo mật, num_ctx được giảm xuống 1024-2048 để tối ưu tốc độ.

### 2.5.3 Đánh giá chất lượng hệ thống

Chất lượng hệ thống được đánh giá trên nhiều khía cạnh. Đối với RAG retrieval, các tiêu chí đánh giá bao gồm độ liên quan của documents được truy xuất so với query, độ phủ của ngữ cảnh cần thiết để trả lời câu hỏi, và thời gian tìm kiếm. Đối với LLM response, các tiêu chí bao gồm độ chính xác kỹ thuật của phân tích bảo mật, tính khả thi của các đề xuất remediation, và độ phù hợp với ngữ cảnh cảnh báo cụ thể.

Hệ thống cũng được đánh giá về khả năng xử lý các tình huống edge case như cảnh báo với thông tin không đầy đủ, các loại cảnh báo chưa có trong cơ sở tri thức, và các câu hỏi nằm ngoài phạm vi bảo mật. Response caching được sử dụng để tránh gọi LLM lặp lại cho các câu hỏi giống nhau về cùng một cảnh báo.

## 2.6 Tích hợp và triển khai

### 2.6.1 Kiến trúc ứng dụng web

Ứng dụng Flask cung cấp giao diện web để tương tác với hệ thống LLM-SOC. Các endpoint chính bao gồm dashboard hiển thị danh sách cảnh báo với các thông tin cơ bản và trạng thái xử lý, trang chi tiết cảnh báo với phân tích AI và các công cụ điều tra, endpoint API cho việc tạo truy vấn SPL và thực thi playbook, và giao diện chat cho việc hỏi đáp tự do về cảnh báo.

```python
# Cấu trúc Flask Application với các endpoint chính
from flask import Flask, request, jsonify, render_template

app = Flask(__name__)

# Global state
supervisor = None  # Lazy initialization
alert_manager = None
investigations = {}  # In-memory storage

@app.route('/')
def dashboard():
    """Hiển thị dashboard danh sách cảnh báo"""
    alerts = alert_manager.load_all_alerts()
    return render_template('alert_dashboard.html', alerts=alerts)

@app.route('/alert/<alert_id>')
def alert_detail(alert_id):
    """Trang chi tiết cảnh báo với phân tích AI"""
    alert = alert_manager.get_alert_by_id(alert_id)
    return render_template('alert_detail.html', alert=alert)

@app.route('/api/analyze', methods=['POST'])
def analyze_alert():
    """API phân tích cảnh báo với AI"""
    global supervisor
    if supervisor is None:
        supervisor = SupervisorAgent()  # Lazy init

    alert_data = request.json
    analysis = supervisor.explain_alert_status(alert_data)
    return jsonify({'analysis': analysis})

@app.route('/api/chat', methods=['POST'])
def chat_with_alert():
    """API hỏi đáp về cảnh báo"""
    question = request.json.get('question')
    alert_data = request.json.get('alert')
    response = supervisor.answer_alert_question(question, alert_data)
    return jsonify({'response': response})
```

Hệ thống sử dụng lazy initialization cho các AI agents để giảm thời gian khởi động. AlertManager được khởi tạo ngay lập tức để hiển thị dữ liệu cảnh báo, trong khi Supervisor Agent và các agent khác chỉ được khởi tạo khi người dùng thực sự cần chức năng AI.

### 2.6.2 Quản lý trạng thái và persistence

Investigations được lưu trữ trong thư mục investigation_data dưới dạng file JSON để đảm bảo không mất dữ liệu khi khởi động lại ứng dụng. Mỗi investigation có unique ID được sinh bằng UUID và chứa đầy đủ lịch sử các bước điều tra, kết quả phân tích, và audit trail.

```python
import json
import uuid
from datetime import datetime, timezone

INVESTIGATION_DATA_DIR = 'investigation_data'
CACHE_DATA_DIR = 'cache_data'

def save_investigation_state(investigation_id: str):
    """Lưu trạng thái investigation ra file JSON"""
    if investigation_id in investigations:
        filepath = f"{INVESTIGATION_DATA_DIR}/{investigation_id}.json"
        with open(filepath, 'w') as f:
            json.dump(investigations[investigation_id], f, indent=2)

def add_audit_entry(investigation_id: str, action: str, details: str):
    """Thêm audit entry vào lịch sử điều tra"""
    audit_entry = {
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'action': action,
        'details': details,
        'investigation_id': investigation_id
    }

    if investigation_id in investigations:
        if 'audit_trail' not in investigations[investigation_id]:
            investigations[investigation_id]['audit_trail'] = []
        investigations[investigation_id]['audit_trail'].append(audit_entry)
        save_investigation_state(investigation_id)

# Ví dụ cấu trúc investigation JSON:
# {
#   "id": "2c42b4cc-5dc8-4e8b-82cc-0abe2218461c",
#   "alert_id": "ALERT-001",
#   "status": "in_progress",
#   "steps": [...],
#   "audit_trail": [
#     {"timestamp": "2026-01-03T10:30:00Z", "action": "created", ...}
#   ]
# }
```

Cache được sử dụng ở nhiều cấp độ bao gồm response_cache trong SupervisorAgent để cache các phản hồi AI cho câu hỏi trùng lặp, cached_questions để cache danh sách câu hỏi điều tra được sinh tự động cho từng loại cảnh báo, và cached_investigation_queries để cache các truy vấn SPL được sinh tự động. Dữ liệu cache được lưu trong thư mục cache_data và được tải lại khi khởi động.

```python
# Cấu trúc cache data
cached_questions = {}       # {alert_type: [question1, question2, ...]}
cached_investigation_queries = {}  # {alert_type: {query_type: spl_query}}
response_cache = {}         # {"qa::alert_id::question": response}

def get_cached_response(alert_id: str, question: str) -> str:
    """Lấy response từ cache nếu có"""
    cache_key = f"qa::{alert_id}::{question.strip()}"
    return response_cache.get(cache_key)

def cache_response(alert_id: str, question: str, response: str):
    """Lưu response vào cache"""
    cache_key = f"qa::{alert_id}::{question.strip()}"
    response_cache[cache_key] = response
```

### 2.6.3 Threat Intelligence Integration

Smart Investigation tích hợp với các dịch vụ threat intelligence thông qua MCP (Model Context Protocol). Các API key được quản lý thông qua file .env và bao gồm VIRUSTOTAL_API_KEY cho tra cứu IP reputation, file hash malware detection, và URL safety check, ABUSEIPDB_API_KEY cho tra cứu IP abuse confidence score và lịch sử báo cáo, cùng các key tùy chọn cho Shodan và AlienVault OTX.

```python
# Cấu hình Threat Intelligence APIs trong .env
# VIRUSTOTAL_API_KEY=abc123...  # Free: 4 requests/minute
# ABUSEIPDB_API_KEY=def456...   # Free: 1000 requests/day
# SHODAN_API_KEY=ghi789...      # Optional
# OTX_API_KEY=jkl012...         # Optional

import os
import requests

class ThreatIntelClient:
    """Client cho các dịch vụ Threat Intelligence"""

    def __init__(self):
        self.vt_api_key = os.getenv('VIRUSTOTAL_API_KEY')
        self.abuse_api_key = os.getenv('ABUSEIPDB_API_KEY')
        self.cache = {}  # Cache kết quả tra cứu

    def check_ip_virustotal(self, ip: str) -> dict:
        """Tra cứu IP reputation trên VirusTotal"""
        if ip in self.cache:
            return self.cache[ip]

        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {"x-apikey": self.vt_api_key}

        try:
            response = requests.get(url, headers=headers, timeout=10)
            result = response.json()
            self.cache[ip] = result  # Cache kết quả
            return result
        except Exception as e:
            return {"error": str(e)}

    def check_ip_abuseipdb(self, ip: str) -> dict:
        """Tra cứu IP abuse score trên AbuseIPDB"""
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": self.abuse_api_key, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": 90}

        try:
            response = requests.get(url, headers=headers, params=params)
            return response.json()
        except Exception as e:
            return {"error": str(e)}

    def enrich_iocs(self, iocs: dict) -> dict:
        """Enrichment tất cả IOCs từ alert"""
        enriched = {}

        for ip in iocs.get('ips', []):
            enriched[ip] = {
                'virustotal': self.check_ip_virustotal(ip),
                'abuseipdb': self.check_ip_abuseipdb(ip)
            }

        return enriched
```

Hệ thống xử lý rate limiting của các API miễn phí bằng cách cache kết quả tra cứu và giới hạn số lượng request đồng thời. Graceful degradation được thực hiện khi API không khả dụng, cho phép hệ thống tiếp tục hoạt động với các chức năng cục bộ.

**Hình 2.6: Luồng Threat Intelligence Enrichment**

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   Alert Data    │     │  IOC Extractor  │     │   TI Client     │
│  src_ip, hash   │────▶│  Filter Public  │────▶│  VirusTotal     │
│  url, domain    │     │  IPs only       │     │  AbuseIPDB      │
└─────────────────┘     └─────────────────┘     └────────┬────────┘
                                                    │
                    ┌─────────────────────────────────┘
                    ▼
┌───────────────────────────────────────────────────┐
│              Enriched IOC Result                  │
│  {                                                │
│    "8.8.8.8": {                                  │
│      "virustotal": {"reputation": 0, "votes": 0},│
│      "abuseipdb": {"score": 0, "reports": 0}     │
│    },                                             │
│    "malware.exe": {                              │
│      "virustotal": {"detections": 45, "total": 70}│
│    }                                              │
│  }                                                │
└───────────────────────────────────────────────────┘
```

## 2.7 Tổng kết

Chương này đã trình bày chi tiết về cách tiếp cận và phương pháp thực nghiệm cho hệ thống LLM-SOC. Kiến trúc multi-agent kết hợp với RAG cho phép hệ thống tận dụng cả sức mạnh của mô hình ngôn ngữ lớn và kiến thức chuyên ngành về bảo mật. Việc sử dụng các công nghệ mã nguồn mở như Ollama, ChromaDB, và Sentence Transformers đảm bảo khả năng triển khai cục bộ mà không phụ thuộc vào các dịch vụ đám mây, điều đặc biệt quan trọng trong môi trường SOC với các yêu cầu nghiêm ngặt về bảo mật dữ liệu.

Hệ thống RAG với các collection chuyên biệt cho từng agent đã chứng minh khả năng nâng cao độ chính xác và tính liên quan của các phân tích bảo mật. Việc tổ chức cơ sở tri thức theo cấu trúc rõ ràng và sử dụng các kỹ thuật text splitting phù hợp góp phần quan trọng vào hiệu quả truy xuất thông tin. Tích hợp với các dịch vụ threat intelligence bổ sung thêm ngữ cảnh bên ngoài, giúp đưa ra đánh giá toàn diện hơn về các mối đe dọa được phát hiện.
