"""
RAG Utilities for SOC AI Assistant
===================================

This module provides RAG (Retrieval-Augmented Generation) capabilities for all agents.
Uses ChromaDB for vector storage and sentence-transformers for embeddings.
"""

import os
import json
import logging
from typing import List, Dict, Any, Optional
from pathlib import Path

try:
    from langchain_community.vectorstores import Chroma
    from langchain_community.embeddings import HuggingFaceEmbeddings
    from langchain.text_splitter import RecursiveCharacterTextSplitter
    from langchain.docstore.document import Document
    CHROMADB_AVAILABLE = True
except ImportError:
    CHROMADB_AVAILABLE = False
    logging.warning("ChromaDB not available. RAG features will be disabled.")

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class RAGManager:
    """
    Manages RAG (Retrieval-Augmented Generation) for different agent types.
    
    Each agent has its own collection in ChromaDB with specialized knowledge:
    - SPL Generator: SPL patterns, Splunk commands, security use cases
    - Playbook Runner: Investigation procedures, threat intel, API guides
    - Supervisor: Security knowledge, MITRE ATT&CK, Q&A examples
    """
    
    def __init__(self, persist_directory: str = "./chroma_db"):
        """
        Initialize RAG Manager with embeddings and vector stores.
        
        Args:
            persist_directory: Directory to persist ChromaDB data
        """
        if not CHROMADB_AVAILABLE:
            logger.warning("RAG Manager initialized but ChromaDB not available")
            self.enabled = False
            return
        
        self.enabled = True
        self.persist_directory = persist_directory
        self.loaded_collections = set()
        
        # Initialize embeddings (local, no API key needed)
        logger.info("🔧 Initializing embeddings model...")
        self.embeddings = HuggingFaceEmbeddings(
            model_name="sentence-transformers/all-MiniLM-L6-v2",
            model_kwargs={'device': 'cpu'},
            encode_kwargs={'normalize_embeddings': True}
        )
        
        # Text splitter for chunking documents
        self.text_splitter = RecursiveCharacterTextSplitter(
            chunk_size=1000,
            chunk_overlap=200,
            length_function=len,
            separators=["\n\n", "\n", ". ", " ", ""]
        )
        
        # Initialize vector stores for each agent
        self.vectorstores = {}
        logger.info("✅ RAG Manager initialized successfully")

        # Optionally auto-load default knowledge bases (including rag_knowledge)
        auto_init = os.getenv("RAG_AUTO_INIT", "true").lower() == "true"
        if auto_init:
            try:
                self.initialize_all_collections()
            except Exception as e:
                logger.warning(f"Auto-initialize RAG collections failed: {e}")
    
    def get_vectorstore(self, collection_name: str) -> Optional[Any]:
        """
        Get or create a vector store for a specific collection.
        
        Args:
            collection_name: Name of the collection (e.g., "spl_knowledge")
            
        Returns:
            ChromaDB vector store instance or None
        """
        if not self.enabled:
            return None
        
        if collection_name not in self.vectorstores:
            try:
                self.vectorstores[collection_name] = Chroma(
                    collection_name=collection_name,
                    embedding_function=self.embeddings,
                    persist_directory=self.persist_directory
                )
                logger.info(f"📚 Vector store '{collection_name}' loaded/created")
            except Exception as e:
                logger.error(f"Error creating vector store '{collection_name}': {e}")
                return None
        
        return self.vectorstores[collection_name]
    
    def load_documents_from_directory(
        self, 
        directory: str, 
        collection_name: str,
        file_extensions: List[str] = ['.md', '.txt', '.json']
    ) -> int:
        """
        Load all documents from a directory into a vector store.
        
        Args:
            directory: Path to directory containing documents
            collection_name: ChromaDB collection name
            file_extensions: List of file extensions to process
            
        Returns:
            Number of documents loaded
        """
        if not self.enabled:
            logger.warning("RAG not enabled, skipping document loading")
            return 0

        if collection_name in self.loaded_collections:
            logger.info(f"Collection '{collection_name}' already loaded; skipping reload")
            return 0
        
        documents = []
        directory_path = Path(directory)
        
        if not directory_path.exists():
            logger.warning(f"Directory not found: {directory}")
            return 0
        
        # Load all files
        for ext in file_extensions:
            for file_path in directory_path.rglob(f"*{ext}"):
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                    
                    # Create metadata
                    metadata = {
                        'source': str(file_path),
                        'filename': file_path.name,
                        'type': ext[1:]  # Remove leading dot
                    }
                    
                    # Handle JSON files specially
                    if ext == '.json':
                        try:
                            json_data = json.loads(content)
                            # Convert JSON to readable text
                            content = self._json_to_text(json_data)
                            metadata['original_format'] = 'json'
                        except json.JSONDecodeError:
                            logger.warning(f"Invalid JSON in {file_path}")
                            continue
                    
                    # Create document
                    doc = Document(page_content=content, metadata=metadata)
                    documents.append(doc)
                    
                except Exception as e:
                    logger.error(f"Error loading {file_path}: {e}")
        
        if not documents:
            logger.warning(f"No documents found in {directory}")
            return 0
        
        # Split documents into chunks
        logger.info(f"📄 Splitting {len(documents)} documents into chunks...")
        chunks = self.text_splitter.split_documents(documents)
        logger.info(f"📄 Created {len(chunks)} chunks")
        
        # Add to vector store
        vectorstore = self.get_vectorstore(collection_name)
        if vectorstore:
            try:
                vectorstore.add_documents(chunks)
                logger.info(f"✅ Loaded {len(chunks)} chunks into '{collection_name}'")
                self.loaded_collections.add(collection_name)
                return len(chunks)
            except Exception as e:
                logger.error(f"Error adding documents to vector store: {e}")
                return 0
        
        return 0
    
    def _json_to_text(self, json_data: Any, prefix: str = "") -> str:
        """
        Convert JSON data to readable text format for embedding.
        
        Args:
            json_data: JSON data to convert
            prefix: Prefix for nested keys
            
        Returns:
            Readable text representation
        """
        lines = []
        
        if isinstance(json_data, dict):
            for key, value in json_data.items():
                full_key = f"{prefix}.{key}" if prefix else key
                
                if isinstance(value, (dict, list)):
                    lines.append(f"{full_key}:")
                    lines.append(self._json_to_text(value, full_key))
                else:
                    lines.append(f"{full_key}: {value}")
        
        elif isinstance(json_data, list):
            for i, item in enumerate(json_data):
                if isinstance(item, (dict, list)):
                    lines.append(self._json_to_text(item, f"{prefix}[{i}]"))
                else:
                    lines.append(f"{prefix}[{i}]: {item}")
        
        else:
            lines.append(str(json_data))
        
        return "\n".join(lines)
    
    def search(
        self, 
        query: str, 
        collection_name: str, 
        k: int = 5,
        filter_dict: Optional[Dict] = None
    ) -> List[Dict[str, Any]]:
        """
        Search for relevant documents in a collection.
        
        Args:
            query: Search query
            collection_name: Name of the collection to search
            k: Number of results to return
            filter_dict: Optional metadata filters
            
        Returns:
            List of relevant documents with content and metadata
        """
        if not self.enabled:
            logger.debug("RAG not enabled, returning empty results")
            return []
        
        vectorstore = self.get_vectorstore(collection_name)
        if not vectorstore:
            return []
        
        try:
            # Perform similarity search
            if filter_dict:
                results = vectorstore.similarity_search(
                    query, 
                    k=k,
                    filter=filter_dict
                )
            else:
                results = vectorstore.similarity_search(query, k=k)
            
            # Format results
            formatted_results = []
            for doc in results:
                formatted_results.append({
                    'content': doc.page_content,
                    'metadata': doc.metadata,
                    'source': doc.metadata.get('source', 'unknown')
                })
            
            logger.debug(f"🔍 Found {len(formatted_results)} relevant documents")
            return formatted_results
            
        except Exception as e:
            logger.error(f"Error searching vector store: {e}")
            return []
    
    def get_relevant_context(
        self, 
        query: str, 
        collection_name: str, 
        k: int = 3
    ) -> str:
        """
        Get relevant context as a formatted string for prompt injection.
        
        Args:
            query: Search query
            collection_name: Collection to search
            k: Number of results
            
        Returns:
            Formatted context string
        """
        results = self.search(query, collection_name, k=k)
        
        if not results:
            return "No relevant context found in knowledge base."
        
        context_parts = []
        for i, result in enumerate(results, 1):
            context_parts.append(f"**Reference {i}** (from {result['metadata'].get('filename', 'unknown')}):")
            context_parts.append(result['content'])
            context_parts.append("")  # Empty line
        
        return "\n".join(context_parts)
    
    def initialize_all_collections(self, knowledge_base_dir: str = "./knowledge") -> Dict[str, int]:
        """
        Initialize all agent collections by loading documents from knowledge base.
        
        Args:
            knowledge_base_dir: Root directory of knowledge base
            
        Returns:
            Dictionary with collection names and document counts
        """
        if not self.enabled:
            logger.warning("RAG not enabled, skipping initialization")
            return {}
        
        results = {}
        project_root = Path(__file__).resolve().parent.parent
        
        # SPL Generator knowledge
        spl_dir = os.path.join(knowledge_base_dir, "rag_spl")
        if os.path.exists(spl_dir):
            count = self.load_documents_from_directory(spl_dir, "spl_knowledge")
            results["spl_knowledge"] = count
        
        # Playbook Runner knowledge
        playbook_dir = os.path.join(knowledge_base_dir, "rag_playbook")
        if os.path.exists(playbook_dir):
            count = self.load_documents_from_directory(playbook_dir, "playbook_knowledge")
            results["playbook_knowledge"] = count
        
        # Supervisor knowledge
        supervisor_dir = os.path.join(knowledge_base_dir, "rag_supervisor")
        if os.path.exists(supervisor_dir):
            count = self.load_documents_from_directory(supervisor_dir, "supervisor_knowledge")
            results["supervisor_knowledge"] = count

        # Alert research knowledge (Splunk research-style descriptions)
        alert_research_dir = project_root / "rag_knowledge"
        if alert_research_dir.exists():
            count = self.load_documents_from_directory(str(alert_research_dir), "alert_research", file_extensions=['.md', '.txt'])
            results["alert_research"] = count
        
        logger.info(f"✅ Initialized {len(results)} collections: {results}")
        return results


# Global RAG manager instance (singleton)
_rag_manager = None

def get_rag_manager() -> RAGManager:
    """
    Get global RAG manager instance (singleton pattern).
    
    Returns:
        RAG manager instance
    """
    global _rag_manager
    if _rag_manager is None:
        _rag_manager = RAGManager()
    return _rag_manager


if __name__ == "__main__":
    # Test RAG manager
    print("Testing RAG Manager...")
    
    rag = get_rag_manager()
    
    if rag.enabled:
        # Initialize collections
        print("\nInitializing collections...")
        results = rag.initialize_all_collections()
        print(f"Loaded: {results}")
        
        # Test search
        print("\nTesting search...")
        test_query = "How to detect brute force attacks in Splunk?"
        results = rag.search(test_query, "spl_knowledge", k=3)
        print(f"Found {len(results)} results for query: '{test_query}'")
        
        if results:
            print("\nTop result:")
            print(results[0]['content'][:300] + "...")
    else:
        print("RAG not available. Install dependencies: pip install chromadb langchain sentence-transformers")
