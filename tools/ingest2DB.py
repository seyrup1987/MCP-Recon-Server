import logging
import os
import json
from uuid import uuid4
from typing import List, Dict, Any, Optional
import numpy as np
import faiss
from langchain_ollama import OllamaEmbeddings
from langchain_core.documents import Document
from langchain.text_splitter import RecursiveCharacterTextSplitter
from datetime import datetime

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

# --- Configuration (Keep as is) ---
DB_PERSIST_DIR = os.path.join("..","/db/faiss_db")
FALLBACK_DIR = os.path.join(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'logs')), 'failed_ingestions')
os.makedirs(DB_PERSIST_DIR, exist_ok=True)
os.makedirs(FALLBACK_DIR, exist_ok=True)

try:
    SHARED_EMBEDDINGS = OllamaEmbeddings(model="nomic-embed-text")
    logger.info("Initialized OllamaEmbeddings.")
except Exception as e:
    logger.critical(f"Failed to initialize OllamaEmbeddings: {e}", exc_info=True)
    raise RuntimeError("Embedding initialization failed")

DEFAULT_COLLECTION_NAME = "documents"
RECON_COLLECTION_NAME = "Reconnaissance"

# --- FAISS Store Class ---
class FAISSStore:
    """Manages a FAISS index with associated metadata for a collection."""

    def __init__(self, collection_name: str, dimension: int = 768):
        self.collection_name = collection_name
        self.dimension = dimension
        self.index = None
        self.metadata = [] # List of (id, Document) tuples
        self.index_path = os.path.join(DB_PERSIST_DIR, f"{collection_name}_index.faiss")
        self.metadata_path = os.path.join(DB_PERSIST_DIR, f"{collection_name}_metadata.json")
        self.reset_index()
        logger.info(f"Initialized FAISSStore for collection '{collection_name}'")

    def reset_index(self):
        """Initialize a new FAISS index or load from disk."""
        try:
            if os.path.exists(self.index_path):
                self.index = faiss.read_index(self.index_path)
                logger.info(f"Loaded FAISS index from {self.index_path} with {self.index.ntotal} vectors")
                if self.index.ntotal > 0 and os.path.exists(self.metadata_path):
                    with open(self.metadata_path, 'r', encoding='utf-8') as f:
                        metadata_raw = json.load(f)
                        self.metadata = []
                        for item in metadata_raw:
                            # --- MODIFICATION: Ensure structured_data is parsed correctly ---
                            meta_content = item.get('metadata', {})
                            # If structured_data was accidentally stored as a string, try parsing it
                            if isinstance(meta_content.get("structured_data"), str):
                                try:
                                    meta_content["structured_data"] = json.loads(meta_content["structured_data"])
                                except json.JSONDecodeError:
                                     logger.warning(f"Could not decode stored structured_data string for id {item.get('id')} in {self.collection_name}")
                                     # Keep it as string or set to None/Error dict? Let's keep it to avoid losing data.
                            # --- END MODIFICATION ---
                            self.metadata.append(
                                (item['id'], Document(page_content=item['page_content'], metadata=meta_content))
                            )

                        logger.info(f"Loaded {len(self.metadata)} metadata entries from {self.metadata_path}")
                        if len(self.metadata) != self.index.ntotal:
                            logger.warning(f"Metadata count ({len(self.metadata)}) mismatches index count ({self.index.ntotal}) in {self.collection_name}. Resetting index/metadata.")
                            # If mismatch, it's safer to start fresh to avoid indexing errors
                            self.metadata = []
                            self.index = faiss.IndexFlatL2(self.dimension)
                # If index exists but metadata doesn't, or index is empty, create new index
                elif self.index.ntotal == 0 or not os.path.exists(self.metadata_path):
                    self.index = faiss.IndexFlatL2(self.dimension)
                    self.metadata = [] # Ensure metadata is also empty
                    logger.debug(f"Index loaded but empty or metadata missing for '{self.collection_name}', reset index/metadata.")

            else:
                self.index = faiss.IndexFlatL2(self.dimension)
                self.metadata = []
                logger.debug(f"Created new FAISS index for '{self.collection_name}'")
        except Exception as e:
            logger.error(f"Failed to load FAISS index/metadata for '{self.collection_name}': {e}", exc_info=True)
            self.index = faiss.IndexFlatL2(self.dimension)
            self.metadata = []

    def save(self):
        """Save FAISS index and metadata to disk."""
        try:
            faiss.write_index(self.index, self.index_path)
            logger.debug(f"Saved FAISS index to {self.index_path} with {self.index.ntotal} vectors")
            metadata_raw = []
            for id_, doc in self.metadata:
                 # Ensure structured_data is serializable (should be if it was a dict)
                 serializable_meta = doc.metadata.copy()
                 if "structured_data" in serializable_meta and not isinstance(serializable_meta["structured_data"], (dict, list, str, int, float, bool, type(None))):
                      logger.warning(f"Non-serializable type {type(serializable_meta['structured_data'])} found in metadata for ID {id_} in {self.collection_name}. Converting to string.")
                      serializable_meta["structured_data"] = str(serializable_meta["structured_data"])

                 metadata_raw.append({
                     'id': id_,
                     'page_content': doc.page_content, # Save the summary content
                     'metadata': serializable_meta      # Save the full metadata including structured_data dict
                 })

            with open(self.metadata_path, 'w', encoding='utf-8') as f:
                json.dump(metadata_raw, f, indent=2, ensure_ascii=False)
            logger.debug(f"Saved {len(self.metadata)} metadata entries to {self.metadata_path}")
        except Exception as e:
            logger.error(f"Failed to save FAISS index/metadata for '{self.collection_name}': {e}", exc_info=True)

    def add_documents(self, documents: List[Document], ids: List[str]):
        """Add documents (using page_content for embedding) to the FAISS index."""
        try:
            if not documents:
                logger.warning(f"No documents provided to add to '{self.collection_name}'")
                return

            # Embed the page_content (summary string)
            texts = [doc.page_content for doc in documents]
            embeddings = SHARED_EMBEDDINGS.embed_documents(texts)
            embeddings_np = np.array(embeddings, dtype='float32')

            if embeddings_np.shape[0] != len(documents) or embeddings_np.shape[1] != self.dimension:
                 raise ValueError(f"Embedding shape {embeddings_np.shape} does not match expected ({len(documents)}, {self.dimension})")
            if np.any(np.isnan(embeddings_np)) or np.any(np.isinf(embeddings_np)):
                 raise ValueError("Embeddings contain NaN or infinite values")
            # Allow all zeros? Might happen for empty summaries, though check Document creation.
            # if np.all(embeddings_np == 0):
            #     raise ValueError("Embeddings are all zeros")

            self.index.add(embeddings_np)
            # Store the mapping of internal index ID to our (external_id, Document) tuple
            # The Document object now contains the full structured data in its metadata
            self.metadata.extend(zip(ids, documents))
            self.save()
            logger.info(f"Added {len(documents)} documents to FAISS index '{self.collection_name}' (total: {self.index.ntotal})")
        except Exception as e:
            logger.error(f"Failed to add documents to FAISS index '{self.collection_name}': {e}", exc_info=True)
            raise # Re-raise to be caught by caller

    def query(self, query_texts: List[str], n_results: int = 5) -> Dict[str, Any]:
        """
        Query the FAISS index with text inputs.
        Returns structured data from metadata if available.
        """
        try:
            if not query_texts:
                logger.warning(f"No query texts provided for '{self.collection_name}'")
                return {'ids': [], 'documents': [], 'metadatas': [], 'distances': []}

            if self.index.ntotal == 0:
                logger.warning(f"FAISS index '{self.collection_name}' is empty. No results available.")
                return {'ids': [], 'documents': [], 'metadatas': [], 'distances': []}

            # Embed the query text
            query_embedding = SHARED_EMBEDDINGS.embed_query(query_texts[0])
            query_np = np.array([query_embedding], dtype='float32')

            if query_np.shape[1] != self.dimension or np.any(np.isnan(query_np)) or np.any(np.isinf(query_np)):
                logger.error(f"Invalid query embedding shape {query_np.shape} or contains NaN/inf for '{self.collection_name}'")
                return {'ids': [], 'documents': [], 'metadatas': [], 'distances': []}

            # Search index using the query embedding
            n_results = min(n_results, self.index.ntotal)
            distances, indices = self.index.search(query_np, n_results)

            # --- MODIFICATION START: Retrieve structured data ---
            results = {
                'ids': [],
                'documents': [],  # This will hold the structured data dicts
                'metadatas': [],  # This will hold the rest of the metadata
                'distances': distances[0].tolist()
            }

            for idx in indices[0]:
                if idx >= 0 and idx < len(self.metadata):
                    id_, doc = self.metadata[idx]
                    results['ids'].append(id_)

                    # Extract structured data if present, otherwise use page_content as fallback
                    structured_data = doc.metadata.get("structured_data")
                    if structured_data is not None:
                        # Ensure it's a dict/list (should be, based on storage logic)
                         if isinstance(structured_data, (dict, list)):
                             logger.debug(f"Retrieved structured_data (type: {type(structured_data)}) for ID {id_} from metadata in {self.collection_name}")
                             results['documents'].append(structured_data) # Add the dict/list directly
                         else:
                              logger.warning(f"Expected dict/list for structured_data in metadata for ID {id_}, found {type(structured_data)}. Using page_content.")
                              results['documents'].append(doc.page_content) # Fallback to summary string
                    else:
                        logger.debug(f"No 'structured_data' key found in metadata for ID {id_}. Using page_content.")
                        results['documents'].append(doc.page_content) # Fallback to summary string

                    # Add the rest of the metadata (excluding the structured_data we just moved)
                    other_metadata = {k: v for k, v in doc.metadata.items() if k != "structured_data"}
                    results['metadatas'].append(other_metadata)

                else:
                    logger.warning(f"Invalid index {idx} returned by FAISS search in '{self.collection_name}'")
            # --- MODIFICATION END ---

            logger.info(f"Query in '{self.collection_name}' returned {len(results['ids'])} valid results")
            return results
        except Exception as e:
            logger.error(f"Failed to query FAISS index '{self.collection_name}': {e}", exc_info=True)
            # Return empty structure on error
            return {'ids': [], 'documents': [], 'metadatas': [], 'distances': []}

# --- FAISS Client Getter (Keep as is) ---
def get_faiss_client(collection_name: str) -> Optional[FAISSStore]:
    """Initialize and return a FAISSStore instance for the specified collection."""
    logger.debug(f"Initializing FAISS client for collection: '{collection_name}'")
    try:
        # Ensure dimension matches embedding model output (nomic-embed-text is 768)
        client = FAISSStore(collection_name=collection_name, dimension=768)
        return client
    except Exception as e:
        logger.error(f"Failed to initialize FAISS client for '{collection_name}': {e}", exc_info=True)
        return None

# --- Fallback Save Function (Keep as is) ---
def save_to_fallback_file(text: str, metadata: str) -> Dict[str, str]:
    """Save text and metadata to a fallback file if ingestion fails."""
    logger.info(f"Saving data to fallback file for source: '{metadata}'")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    safe_metadata = metadata.replace('/', '_').replace('\\', '_').replace(':', '_')
    fallback_filename = f"failed_ingest_{safe_metadata}_{timestamp}.json"
    fallback_path = os.path.join(FALLBACK_DIR, fallback_filename)
    try:
        # If text is already JSON string, try loading and re-dumping for pretty print
        try:
            data_obj = json.loads(text)
            content_to_save = json.dumps({"source": metadata, "timestamp": datetime.utcnow().isoformat(), "data": data_obj}, indent=2)
        except json.JSONDecodeError:
            # If text wasn't JSON, save it as is
            content_to_save = json.dumps({"source": metadata, "timestamp": datetime.utcnow().isoformat(), "text": text}, indent=2)

        with open(fallback_path, 'w', encoding='utf-8') as f:
            f.write(content_to_save)
        logger.info(f"Successfully saved fallback file: {fallback_path}")
        return {"status": "success", "fallback_path": fallback_path}
    except Exception as e:
        logger.error(f"Failed to save fallback file '{fallback_path}': {e}", exc_info=True)
        return {"status": "failed", "error": f"Failed to save fallback file: {str(e)}"}


# --- Ingest Single Document (Keep as is, uses default collection logic) ---
async def ingest2DB(text: str, metadata: str):
    # ... (no changes needed here as it doesn't use Recon collection)
    logger.warning(f"Using deprecated ingest2DB (single chunk) for metadata: {metadata}")
    vector_store = get_faiss_client(DEFAULT_COLLECTION_NAME)
    if not vector_store:
        logger.error(f"Failed to get FAISS client for '{DEFAULT_COLLECTION_NAME}'. Cannot ingest.")
        fallback_result = save_to_fallback_file(text, metadata)
        return {'error': 'FAISS initialization failed.', 'fallback': fallback_result}

    metadata_object = {"source": metadata}
    # Store original text in metadata for potential future use, embed text directly
    metadata_object["original_text"] = text
    text_chunk = Document(page_content=text, metadata=metadata_object)
    unique_id = str(uuid4())

    try:
        vector_store.add_documents(documents=[text_chunk], ids=[unique_id])
        logger.info(f"Successfully ingested document {unique_id} into '{DEFAULT_COLLECTION_NAME}' from source: {metadata}")
        return unique_id # Return ID on success
    except Exception as error:
        logger.error(f"Error ingesting document into '{DEFAULT_COLLECTION_NAME}' from source {metadata}: {error}", exc_info=True)
        fallback_result = save_to_fallback_file(text, metadata)
        return {'error': str(error), 'fallback': fallback_result}


# --- Chunk and Ingest Documents (Keep as is, uses default collection logic) ---
async def chunk_and_ingest(
    full_text: str,
    source_metadata: str,
    chunk_size: int = 1000,
    chunk_overlap: int = 150
):
    # ... (no changes needed here as it doesn't use Recon collection)
    vector_store = get_faiss_client(DEFAULT_COLLECTION_NAME)
    if not vector_store:
        logger.error(f"Failed to get FAISS client for '{DEFAULT_COLLECTION_NAME}'. Cannot ingest chunks.")
        fallback_result = save_to_fallback_file(full_text, source_metadata)
        return {'error': 'FAISS initialization failed.', 'fallback': fallback_result}

    separators = ["\n\n", "\n", ". ", " ", ""]
    text_splitter = RecursiveCharacterTextSplitter(
        chunk_size=chunk_size,
        chunk_overlap=chunk_overlap,
        length_function=len,
        is_separator_regex=False,
        separators=separators
    )
    split_texts = text_splitter.split_text(full_text)

    if not split_texts:
        logger.warning(f"No text chunks were generated from source: {source_metadata}")
        return {"chunk_ids": [], "message": "No text chunks generated."}

    documents_to_add = []
    chunk_ids = []
    for i, chunk_text in enumerate(split_texts):
        chunk_id = str(uuid4())
        chunk_metadata = {
            "source": source_metadata,
            "chunk_index": i + 1,
            "total_chunks": len(split_texts),
             # Store original chunk in metadata too? Optional.
            # "original_chunk_text": chunk_text
        }
        doc = Document(page_content=chunk_text, metadata=chunk_metadata)
        documents_to_add.append(doc)
        chunk_ids.append(chunk_id)

    try:
        vector_store.add_documents(documents=documents_to_add, ids=chunk_ids)
        logger.info(f"Successfully ingested {len(documents_to_add)} chunks into '{DEFAULT_COLLECTION_NAME}' from source: {source_metadata}")
        return {"chunk_ids": chunk_ids} # Return list of IDs on success
    except Exception as error:
        logger.error(f"Error ingesting chunks into '{DEFAULT_COLLECTION_NAME}' from source {source_metadata}: {error}", exc_info=True)
        fallback_result = save_to_fallback_file(full_text, source_metadata)
        return {'error': str(error), 'source': source_metadata, 'fallback': fallback_result}


# --- Query FAISS Index ---
async def queryDB(
    query_texts: List[str],
    n_results: int = 5,
    collection_name: str = DEFAULT_COLLECTION_NAME,
    where: Optional[Dict[str, Any]] = None,
    where_document: Optional[Dict[str, Any]] = None # FAISS doesn't use where_document
) -> Optional[Dict[str, Any]]:
    """
    Queries a FAISS index for the specified collection.
    Returns structured data from metadata if available in the 'documents' field.
    Note: FAISS doesn't natively support 'where' filters; filtering is applied post-query.
    """
    logger.info(f"Initiating query in collection '{collection_name}' with {len(query_texts)} query texts, n_results={n_results}.")
    logger.debug(f"Query texts: {query_texts}, where filter: {where}")

    vector_store = get_faiss_client(collection_name)
    if not vector_store:
        logger.error(f"Failed to get FAISS client for '{collection_name}'. Cannot query.")
        return None # Return None to indicate client failure

    try:
        # FAISSStore.query now returns the structured data in 'documents'
        results = vector_store.query(query_texts=query_texts, n_results=n_results)

        # --- MODIFICATION: Simplify post-query filtering ---
        # Apply post-query filtering based on the METADATA if 'where' is provided
        if where:
            logger.debug(f"Applying post-query 'where' filtering on metadata for '{collection_name}': {where}")
            filtered_results = {
                'ids': [],
                'documents': [], # Holds structured data
                'metadatas': [], # Holds other metadata
                'distances': []
            }
            # Iterate using the METADATAS field which contains the filterable info
            for id_val, doc_data, meta_data, dist_val in zip(
                results['ids'], results['documents'], results['metadatas'], results['distances']
            ):
                # Check if all key-value pairs in 'where' exist in the current item's metadata
                if all(meta_data.get(k) == v for k, v in where.items()):
                    filtered_results['ids'].append(id_val)
                    filtered_results['documents'].append(doc_data) # Keep structured data
                    filtered_results['metadatas'].append(meta_data) # Keep other metadata
                    filtered_results['distances'].append(dist_val)
                else:
                     logger.debug(f"Item ID {id_val} filtered out by 'where' clause. Metadata: {meta_data}")

            results = filtered_results
            logger.info(f"Query in '{collection_name}' returned {len(results['ids'])} results after 'where' filtering")
        # --- END MODIFICATION ---
        else:
             logger.info(f"Query in '{collection_name}' returned {len(results['ids'])} results (no 'where' filter applied)")

        # --- MODIFICATION: Adapt return structure to be closer to ChromaDB ---
        # The client code might expect `documents` and `metadatas` to be lists of lists.
        # Let's wrap each item in a list to mimic that structure.
        final_results = {
            'ids': results['ids'],
            'documents': [[doc] for doc in results['documents']], # Wrap each document dict/str in a list
            'metadatas': [[meta] for meta in results['metadatas']], # Wrap each metadata dict in a list
            'distances': results['distances']
        }
        # --- END MODIFICATION ---

        return final_results # Return the potentially filtered and restructured results
    except Exception as e:
        logger.error(f"Error during FAISS query or filtering in '{collection_name}': {e}", exc_info=True)
        return None # Return None on error


# --- END OF FILE ingest2DB.py ---