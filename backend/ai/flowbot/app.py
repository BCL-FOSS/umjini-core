import os
import logging
from quart import Quart, request, jsonify
from quart_rate_limiter import RateLimiter, rate_limit
import asyncio
from datetime import datetime
import json
from typing import Dict, Any, List

from init_app import app
from RAGEngine import RAGEngine
from NetworkToolParser import NetworkToolParser
from utils.RedisDB import RedisDB

logging.basicConfig(level=logging.INFO)
logging.getLogger('passlib').setLevel(logging.ERROR)
logger = logging.getLogger(__name__)

# Initialize rate limiter
rate_limiter = RateLimiter(app)

# Initialize Redis for metadata storage
metadata_db = RedisDB(
    hostname=os.environ.get('METADATA_DB', 'redis'),
    port=os.environ.get('METADATA_DB_PORT', '6379')
)

# Initialize RAG Engine
rag_engine = RAGEngine(
    collection_name=os.environ.get('COLLECTION_NAME', 'network_analysis'),
    embedding_model=os.environ.get('EMBEDDING_MODEL', 'all-MiniLM-L6-v2'),
    ollama_model=os.environ.get('OLLAMA_MODEL', 'qwen2.5:7b'),
    chromadb_path=os.environ.get('CHROMADB_PATH', './chromadb_data'),
    mcp_server_url=os.environ.get('MCP_SERVER_URL')
)

# Initialize parser
parser = NetworkToolParser()


@app.before_serving
async def startup():
    """Initialize connections on startup"""
    logger.info("Starting RAG Network Analysis Agent...")
    await metadata_db.connect_db()
    logger.info("RAG Engine initialized")
    logger.info(f"Collection stats: {rag_engine.get_collection_stats()}")


@app.route('/health', methods=['GET'])
async def health_check():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy",
        "service": "rag-network-agent",
        "timestamp": datetime.utcnow().isoformat()
    }), 200


@app.route('/stats', methods=['GET'])
@rate_limit(10, timedelta=60)
async def get_stats():
    """Get RAG engine statistics"""
    try:
        stats = rag_engine.get_collection_stats()
        return jsonify({
            "success": True,
            "stats": stats
        }), 200
    except Exception as e:
        logger.error(f"Error getting stats: {e}", exc_info=True)
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


@app.route('/ingest', methods=['POST'])
@rate_limit(30, timedelta=60)
async def ingest_tool_output():
    """
    Ingest network tool output
    
    Body:
    {
        "tool_type": "nmap|tcpdump|traceroute|iperf|tshark|pcap",
        "output": "raw tool output",
        "metadata": {
            "probe": "probe-01",
            "target": "192.168.1.1",
            "timestamp": "2026-02-05T12:00:00Z"
        }
    }
    """
    try:
        data = await request.get_json()
        
        tool_type = data.get('tool_type')
        output = data.get('output')
        metadata = data.get('metadata', {})
        
        if not tool_type or not output:
            return jsonify({
                "success": False,
                "error": "Missing required fields: tool_type, output"
            }), 400
        
        # Add timestamp if not provided
        if 'timestamp' not in metadata:
            metadata['timestamp'] = datetime.utcnow().isoformat()
        
        metadata['tool_type'] = tool_type
        
        # Parse the tool output
        parsed = parser.parse_tool_output(tool_type, output)
        
        # Create document ID
        doc_id = f"{tool_type}_{metadata.get('timestamp')}_{metadata.get('probe', 'default')}"
        
        # Prepare content for embedding (combine parsed data)
        content = f"Tool: {tool_type}\n"
        content += f"Timestamp: {metadata.get('timestamp')}\n"
        content += f"Probe: {metadata.get('probe', 'N/A')}\n"
        content += f"Target: {metadata.get('target', 'N/A')}\n\n"
        content += f"Raw Output:\n{output}\n\n"
        
        if parsed.get('anomalies'):
            content += f"Detected Anomalies:\n{json.dumps(parsed['anomalies'], indent=2)}\n"
        
        # Ingest into RAG
        success = await rag_engine.ingest_document(doc_id, content, metadata)
        
        # Store parsed data in Redis
        await metadata_db.upload_db_data(
            id=doc_id,
            data={
                "tool_type": tool_type,
                "timestamp": metadata.get('timestamp'),
                "parsed": json.dumps(parsed),
                "has_anomalies": len(parsed.get('anomalies', [])) > 0
            }
        )
        
        return jsonify({
            "success": success,
            "document_id": doc_id,
            "parsed": parsed,
            "ingested_at": datetime.utcnow().isoformat()
        }), 200
        
    except Exception as e:
        logger.error(f"Error ingesting tool output: {e}", exc_info=True)
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


@app.route('/ingest/batch', methods=['POST'])
@rate_limit(10, timedelta=60)
async def ingest_batch():
    """
    Batch ingest multiple tool outputs
    
    Body:
    {
        "documents": [
            {
                "tool_type": "nmap",
                "output": "...",
                "metadata": {...}
            },
            ...
        ]
    }
    """
    try:
        data = await request.get_json()
        documents = data.get('documents', [])
        
        if not documents:
            return jsonify({
                "success": False,
                "error": "No documents provided"
            }), 400
        
        # Process documents
        processed_docs = []
        
        for doc in documents:
            tool_type = doc.get('tool_type')
            output = doc.get('output')
            metadata = doc.get('metadata', {})
            
            if not tool_type or not output:
                continue
            
            if 'timestamp' not in metadata:
                metadata['timestamp'] = datetime.utcnow().isoformat()
            
            metadata['tool_type'] = tool_type
            
            # Parse
            parsed = parser.parse_tool_output(tool_type, output)
            
            # Create document
            doc_id = f"{tool_type}_{metadata.get('timestamp')}_{metadata.get('probe', 'default')}"
            
            content = f"Tool: {tool_type}\n"
            content += f"Timestamp: {metadata.get('timestamp')}\n"
            content += f"Raw Output:\n{output}\n\n"
            
            if parsed.get('anomalies'):
                content += f"Anomalies:\n{json.dumps(parsed['anomalies'], indent=2)}\n"
            
            processed_docs.append({
                'id': doc_id,
                'content': content,
                'metadata': metadata
            })
        
        # Batch ingest
        count = await rag_engine.ingest_batch(processed_docs)
        
        return jsonify({
            "success": True,
            "ingested_count": count,
            "total_submitted": len(documents)
        }), 200
        
    except Exception as e:
        logger.error(f"Error in batch ingest: {e}", exc_info=True)
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


@app.route('/query', methods=['POST'])
@rate_limit(20, timedelta=60)
async def query_rag():
    """
    Query the RAG system
    
    Body:
    {
        "query": "Show me recent port scans",
        "n_results": 5,
        "filter": {"tool_type": "nmap"}
    }
    """
    try:
        data = await request.get_json()
        
        query = data.get('query')
        n_results = data.get('n_results', 5)
        where_filter = data.get('filter')
        
        if not query:
            return jsonify({
                "success": False,
                "error": "Query is required"
            }), 400
        
        # Perform RAG query
        result = await rag_engine.rag_query(query, n_results, where_filter)
        
        return jsonify({
            "success": True,
            "result": result
        }), 200
        
    except Exception as e:
        logger.error(f"Error querying RAG: {e}", exc_info=True)
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


@app.route('/analyze', methods=['POST'])
@rate_limit(15, timedelta=60)
async def analyze_output():
    """
    Analyze tool output for anomalies without ingesting
    
    Body:
    {
        "tool_type": "tcpdump",
        "output": "raw output",
        "metadata": {...}
    }
    """
    try:
        data = await request.get_json()
        
        tool_type = data.get('tool_type')
        output = data.get('output')
        metadata = data.get('metadata', {})
        
        if not tool_type or not output:
            return jsonify({
                "success": False,
                "error": "Missing required fields"
            }), 400
        
        # Parse
        parsed = parser.parse_tool_output(tool_type, output)
        
        # Prepare content
        metadata['tool_type'] = tool_type
        metadata['timestamp'] = metadata.get('timestamp', datetime.utcnow().isoformat())
        
        content = f"Tool: {tool_type}\n{output}"
        
        # Detect anomalies using RAG
        anomaly_result = await rag_engine.detect_anomalies(content, metadata)
        
        return jsonify({
            "success": True,
            "parsed": parsed,
            "rag_analysis": anomaly_result
        }), 200
        
    except Exception as e:
        logger.error(f"Error analyzing output: {e}", exc_info=True)
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


@app.route('/process', methods=['POST'])
@rate_limit(10, timedelta=60)
async def process_and_act():
    """
    Complete pipeline: ingest, analyze, decide action, optionally execute
    
    Body:
    {
        "tool_type": "nmap",
        "output": "...",
        "metadata": {...},
        "available_tools": ["send_email_alert", "create_jira_ticket"],
        "auto_execute": false
    }
    """
    try:
        data = await request.get_json()
        
        tool_type = data.get('tool_type')
        output = data.get('output')
        metadata = data.get('metadata', {})
        available_tools = data.get('available_tools', [])
        auto_execute = data.get('auto_execute', False)
        
        if not tool_type or not output:
            return jsonify({
                "success": False,
                "error": "Missing required fields"
            }), 400
        
        # Prepare metadata
        metadata['tool_type'] = tool_type
        metadata['timestamp'] = metadata.get('timestamp', datetime.utcnow().isoformat())
        
        # Prepare content
        content = f"Tool: {tool_type}\nTimestamp: {metadata['timestamp']}\n\n{output}"
        
        # Process with RAG
        result = await rag_engine.process_and_act(
            content,
            metadata,
            available_tools,
            auto_execute
        )
        
        return jsonify({
            "success": True,
            "result": result
        }), 200
        
    except Exception as e:
        logger.error(f"Error processing: {e}", exc_info=True)
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


@app.route('/mcp/execute', methods=['POST'])
@rate_limit(5, timedelta=60)
async def execute_mcp_tool():
    """
    Manually execute an MCP tool
    
    Body:
    {
        "tool_name": "send_email_alert",
        "params": {
            "recipient": "admin@example.com",
            "subject": "Network Alert",
            "message": "..."
        }
    }
    """
    try:
        data = await request.get_json()
        
        tool_name = data.get('tool_name')
        params = data.get('params', {})
        
        if not tool_name:
            return jsonify({
                "success": False,
                "error": "tool_name is required"
            }), 400
        
        result = await rag_engine.execute_mcp_action(tool_name, params)
        
        return jsonify({
            "success": True,
            "tool": tool_name,
            "result": result
        }), 200
        
    except Exception as e:
        logger.error(f"Error executing MCP tool: {e}", exc_info=True)
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


@app.route('/history', methods=['GET'])
@rate_limit(20, timedelta=60)
async def get_history():
    """
    Get ingestion history from Redis
    
    Query params:
    - tool_type: Filter by tool type
    - has_anomalies: Filter by anomaly presence (true/false)
    """
    try:
        tool_type = request.args.get('tool_type')
        has_anomalies = request.args.get('has_anomalies')
        
        # Build match pattern
        if tool_type:
            pattern = f"{tool_type}_*"
        else:
            pattern = "*"
        
        # Get all matching data from Redis
        all_data = await metadata_db.get_all_data(match=pattern)
        
        if not all_data:
            return jsonify({
                "success": True,
                "history": []
            }), 200
        
        # Filter by has_anomalies if specified
        history = []
        for doc_id, data in all_data.items():
            if has_anomalies is not None:
                has_anom = data.get('has_anomalies', 'False') == 'True'
                filter_anom = has_anomalies.lower() == 'true'
                if has_anom != filter_anom:
                    continue
            
            history.append({
                "document_id": doc_id,
                "tool_type": data.get('tool_type'),
                "timestamp": data.get('timestamp'),
                "has_anomalies": data.get('has_anomalies') == 'True'
            })
        
        return jsonify({
            "success": True,
            "count": len(history),
            "history": history
        }), 200
        
    except Exception as e:
        logger.error(f"Error getting history: {e}", exc_info=True)
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


@app.errorhandler(404)
async def not_found(error):
    return jsonify({
        "success": False,
        "error": "Endpoint not found"
    }), 404


@app.errorhandler(500)
async def internal_error(error):
    return jsonify({
        "success": False,
        "error": "Internal server error"
    }), 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000, debug=False)