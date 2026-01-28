from langchain_ollama import ChatOllama


llm = ChatOllama(
    model="mistral:7b",
    base_url="http://localhost:11434",  # chỉ định rõ endpoint
    timeout=15
)

print(llm.invoke("who are you?"))