import json
import time
import logging
import os
from uuid import uuid4
from datetime import datetime
from langchain_core.documents import Document
import asyncio
from tools.ingest2DB import get_faiss_client, RECON_COLLECTION_NAME, save_to_fallback_file

logger = logging.getLogger(__name__)

async def ingest_results_to_db(json_data: dict[str, any], source_metadata: str):
    """
    Ingests structured JSON data into the Reconnaissance FAISS collection.
    Stores a summary as page_content for embedding and the full data in metadata.

    Args:
        json_data: The dictionary containing the structured results.
        source_metadata: A string describing the source of the data.

    Returns:
        A dictionary indicating success or failure, including fallback info on error.
    """
    max_retries = 3
    vector_store_recon = None
    logger.info(f"Attempting to ingest results for source: '{source_metadata}' into collection '{RECON_COLLECTION_NAME}'")

    # Attempt to get FAISS client with retries (Keep as is)
    for attempt in range(max_retries):
        logger.debug(f"Attempt {attempt + 1}/{max_retries} to get FAISS client for '{RECON_COLLECTION_NAME}'")
        vector_store_recon = get_faiss_client(RECON_COLLECTION_NAME)
        if vector_store_recon:
            logger.debug(f"Successfully obtained FAISS client for '{RECON_COLLECTION_NAME}'")
            break
        logger.warning(f"Attempt {attempt + 1}/{max_retries} failed to get FAISS client for '{RECON_COLLECTION_NAME}', retrying...")
        await asyncio.sleep(2 ** attempt)

    if not vector_store_recon:
        logger.error(f"FAISS client initialization failed for '{RECON_COLLECTION_NAME}' after {max_retries} attempts.")
        try:
            fallback_content = json.dumps(json_data, indent=2) # Still try to dump original for fallback
        except Exception as dump_err:
            logger.error(f"Failed to dump json_data to string for fallback: {dump_err}")
            fallback_content = f"Error dumping JSON: {dump_err}. Original data type: {type(json_data)}"
        fallback_result = save_to_fallback_file(fallback_content, source_metadata)
        return {'error': f'FAISS initialization failed for {RECON_COLLECTION_NAME}.', 'fallback': fallback_result}

    # --- MODIFICATION START ---
    # Create a simple page_content for embedding (e.g., source and main keys)
    # This helps FAISS find relevant documents without embedding huge JSON strings.
    try:
        # Create a summary string for embedding. Adjust as needed.
        # Example: Include source and top-level keys or a short description.
        summary_keys = list(json_data.keys())
        page_content_summary = f"Reconnaissance results from source: {source_metadata}. Contains data for keys: {summary_keys}"
        logger.debug(f"Generated page_content summary for embedding: '{page_content_summary[:200]}...'")

        # Prepare metadata, including the ORIGINAL structured data
        doc_metadata = {
            "source": source_metadata,
            "ingest_type": "structured_result",
            "ingest_timestamp": datetime.utcnow().isoformat(),
            "structured_data": json_data  # <-- STORE THE ORIGINAL DICTIONARY HERE
        }

        # Create the Langchain Document object
        recon_document = Document(page_content=page_content_summary, metadata=doc_metadata)
        unique_id = str(uuid4()) # Generate a unique ID for the document

    except Exception as e:
        logger.error(f"Failed to prepare Document object for source '{source_metadata}': {e}", exc_info=True)
        try:
            fallback_content = json.dumps(json_data, indent=2)
        except Exception as dump_err:
             fallback_content = f"Error dumping JSON: {dump_err}. Original data type: {type(json_data)}"
        fallback_result = save_to_fallback_file(fallback_content, source_metadata) # Save original data on error
        return {'error': f'Failed to prepare Document: {str(e)}', 'source': source_metadata, 'fallback': fallback_result}
    # --- MODIFICATION END ---

    try:
        logger.debug(f"Adding document {unique_id} (using summary embedding) to FAISS collection '{RECON_COLLECTION_NAME}'...")
        vector_store_recon.add_documents(documents=[recon_document], ids=[unique_id])
        logger.info(f"Successfully ingested document {unique_id} for source '{source_metadata}' into '{RECON_COLLECTION_NAME}'.")
        return {"status": "success", "id": unique_id, "source": source_metadata}
    except Exception as error:
        logger.error(f"FAISS add_documents failed for document {unique_id} (source: '{source_metadata}'): {error}", exc_info=True)
        # Save the original structured data to fallback if add fails
        try:
             fallback_content = json.dumps(json_data, indent=2)
        except Exception as dump_err:
             fallback_content = f"Error dumping JSON: {dump_err}. Original data type: {type(json_data)}"
        fallback_result = save_to_fallback_file(fallback_content, source_metadata)
        return {'error': f'FAISS add_documents failed: {str(error)}', 'source': source_metadata, 'fallback': fallback_result}

# --- END OF FILE ingestResults2DB.py ---