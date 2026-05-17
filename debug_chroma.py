import chromadb
from secagent.config import Settings

settings = Settings()
client = chromadb.PersistentClient(path=str(settings.chroma_path))
collection = client.get_collection(name=settings.collection_name)

# Проверяем сколько всего
count = collection.count()
print(f"Всего чанков в БД: {count}\n")

# Проверяем первые 5
results = collection.get(limit=5, include=["documents", "metadatas"])
print("Первые 5 чанков:\n")
for i, (doc, meta) in enumerate(zip(results["documents"], results["metadatas"]), 1):
    print(f"[{i}]")
    print(f"  CWE: {meta.get('cwe_id')}")
    print(f"  Source: {meta.get('source')}")
    print(f"  Languages (type={type(meta.get('languages')).__name__}): {meta.get('languages')}")
    print(f"  Text: {doc[:80]}...\n")
