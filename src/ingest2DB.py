from langchain_chroma import Chroma
from langchain_ollama import OllamaEmbeddings
from langchain_core.documents import Document
from langchain.text_splitter import RecursiveCharacterTextSplitter # Added import
from uuid import uuid4
import logging # Added import

logger = logging.getLogger(__name__) # Added logger

# --- Existing Code ---
embeddings = OllamaEmbeddings(model = "nomic-embed-text")

vector_store = Chroma(
    collection_name="documents",
    embedding_function=embeddings,
    persist_directory="../db/chroma_langchain_db"
)

async def ingest2DB(text: str, metadata: str):
    """
    Ingests a SINGLE block of text as one document into the vector store.
    DEPRECATED in favor of chunk_and_ingest for better retrieval.
    """
    metadataObject = {
        "source": metadata
    }
    textChunk = Document(
        page_content = text,
        metadata = metadataObject
    )
    try:
        uniqueID = str(uuid4())
        result = vector_store.add_documents(documents = [textChunk], ids = [uniqueID])
        logger.info(f"Successfully ingested single document {uniqueID} from source: {metadata}")
        return str(result)
    except Exception as error:
        logger.error(f"Error ingesting single document from source {metadata}: {error}", exc_info=True)
        return {'error': str(error)}

# --- New Function ---
async def chunk_and_ingest(
    full_text: str,
    source_metadata: str,
    chunk_size: int = 1000,
    chunk_overlap: int = 150
):
    """
    Chunks the input text using RecursiveCharacterTextSplitter and ingests
    all chunks into the Chroma vector store.

    Args:
        full_text: The entire text content to be chunked and ingested.
        source_metadata: A string describing the source of the text (e.g., URL, filename, tool name).
                         This will be added to the metadata of each chunk.
        chunk_size: The target size for each text chunk (in characters).
        chunk_overlap: The number of characters to overlap between consecutive chunks.

    Returns:
        A dictionary containing the list of generated chunk IDs or an error message.
    """

    # Recommended separators for general text
    separators=["\n\n", "\n", ". ", " ", ""]

    text_splitter = RecursiveCharacterTextSplitter(
        chunk_size=chunk_size,
        chunk_overlap=chunk_overlap,
        length_function=len,
        is_separator_regex=False,
        separators=separators
    )

    # Create chunks from the full text
    split_texts = text_splitter.split_text(full_text)

    if not split_texts:
        logger.warning(f"No text chunks were generated from source: {source_metadata}")
        return {"chunk_ids": [], "message": "No text chunks generated."}

    documents_to_add = []
    chunk_ids = []

    # Prepare Document objects for each chunk
    for i, chunk_text in enumerate(split_texts):
        chunk_id = str(uuid4())
        chunk_metadata = {
            "source": source_metadata,
            "chunk_index": i + 1, # Add chunk index for potential ordering/context
            "total_chunks": len(split_texts)
        }
        doc = Document(
            page_content=chunk_text,
            metadata=chunk_metadata
        )
        documents_to_add.append(doc)
        chunk_ids.append(chunk_id)

    # Ingest all documents into Chroma
    try:
        vector_store.add_documents(documents=documents_to_add, ids=chunk_ids)
        logger.info(f"Successfully ingested {len(documents_to_add)} chunks from source: {source_metadata}")
        return {"chunk_ids": chunk_ids}
    except Exception as error:
        logger.error(f"Error ingesting chunks from source {source_metadata}: {error}", exc_info=True)
        return {'error': str(error), "source": source_metadata}
