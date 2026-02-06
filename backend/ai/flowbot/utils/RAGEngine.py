import os
import logging
import chromadb
from chromadb.config import Settings
from sentence_transformers import SentenceTransformer
import ollama
import httpx
import json
from typing import List, Dict, Any, Optional
import asyncio

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class RAGEngine:
    def __init__(
        self,
        collection_name: str = "network_analysis",
        embedding_model: str = "all-MiniLM-L6-v2",
        ollama_model: str = "qwen2.5:7b",
        chromadb_path: str = "./chromadb_data",
        mcp_server_url: str = None
    ):
        """
        RAG Engine for network analysis with ChromaDB and Ollama
        
        Args:
            collection_name: ChromaDB collection name
            embedding_model: HuggingFace model for embeddings
            ollama_model: Ollama model for LLM inference
            chromadb_path: Path to persist ChromaDB data
            mcp_server_url: URL of the MCP server for tool execution
        """
        self.collection_name = collection_name
        self.ollama_model = ollama_model
        self.mcp_server_url = mcp_server_url
        
        # Initialize embedding model
        logger.info(f"Loading embedding model: {embedding_model}")
        self.embedding_model = SentenceTransformer(embedding_model)
        
        # Initialize ChromaDB
        logger.info(f"Initializing ChromaDB at: {chromadb_path}")
        self.chroma_client = chromadb.PersistentClient(
            path=chromadb_path,
            settings=Settings(anonymized_telemetry=False)
        )
        
        # Get or create collection
        try:
            self.collection = self.chroma_client.get_collection(name=collection_name)
            logger.info(f"Loaded existing collection: {collection_name}")
        except Exception:
            self.collection = self.chroma_client.create_collection(
                name=collection_name,
                metadata={"description": "Network tool analysis and anomaly detection"}
            )
            logger.info(f"Created new collection: {collection_name}")
    
    def generate_embedding(self, text: str) -> List[float]:
        """Generate embedding vector for text"""
        embedding = self.embedding_model.encode(text, convert_to_tensor=False)
        return embedding.tolist()
    
    async def ingest_document(
        self,
        doc_id: str,
        content: str,
        metadata: Dict[str, Any]
    ) -> bool:
        """
        Ingest a network tool output document into ChromaDB
        
        Args:
            doc_id: Unique document identifier
            content: The network tool output text
            metadata: Additional metadata (tool_type, timestamp, probe, etc.)
        
        Returns:
            bool: Success status
        """
        try:
            embedding = self.generate_embedding(content)
            
            self.collection.add(
                ids=[doc_id],
                embeddings=[embedding],
                documents=[content],
                metadatas=[metadata]
            )
            
            logger.info(f"Ingested document: {doc_id} (tool: {metadata.get('tool_type')})")
            return True
            
        except Exception as e:
            logger.error(f"Error ingesting document {doc_id}: {e}", exc_info=True)
            return False
    
    async def ingest_batch(
        self,
        documents: List[Dict[str, Any]]
    ) -> int:
        """
        Batch ingest multiple documents
        
        Args:
            documents: List of dicts with 'id', 'content', and 'metadata'
        
        Returns:
            int: Number of successfully ingested documents
        """
        ids = []
        embeddings = []
        contents = []
        metadatas = []
        
        for doc in documents:
            try:
                embedding = self.generate_embedding(doc['content'])
                ids.append(doc['id'])
                embeddings.append(embedding)
                contents.append(doc['content'])
                metadatas.append(doc['metadata'])
            except Exception as e:
                logger.error(f"Error processing document {doc.get('id')}: {e}")
                continue
        
        if ids:
            try:
                self.collection.add(
                    ids=ids,
                    embeddings=embeddings,
                    documents=contents,
                    metadatas=metadatas
                )
                logger.info(f"Batch ingested {len(ids)} documents")
                return len(ids)
            except Exception as e:
                logger.error(f"Error in batch ingestion: {e}", exc_info=True)
                return 0
        
        return 0
    
    async def query_similar(
        self,
        query_text: str,
        n_results: int = 5,
        where_filter: Optional[Dict] = None
    ) -> Dict[str, Any]:
        """
        Query for similar network patterns
        
        Args:
            query_text: Text to search for
            n_results: Number of results to return
            where_filter: Metadata filter (e.g., {"tool_type": "nmap"})
        
        Returns:
            Dict with results
        """
        try:
            query_embedding = self.generate_embedding(query_text)
            
            results = self.collection.query(
                query_embeddings=[query_embedding],
                n_results=n_results,
                where=where_filter
            )
            
            return {
                "query": query_text,
                "results": results,
                "count": len(results['ids'][0]) if results['ids'] else 0
            }
            
        except Exception as e:
            logger.error(f"Error querying similar documents: {e}", exc_info=True)
            return {"query": query_text, "results": None, "error": str(e)}
    
    async def analyze_with_llm(
        self,
        context: str,
        query: str,
        system_prompt: Optional[str] = None
    ) -> str:
        """
        Use Ollama LLM to analyze network data with RAG context
        
        Args:
            context: Retrieved context from vector DB
            query: User query or analysis request
            system_prompt: Optional system prompt
        
        Returns:
            str: LLM analysis result
        """
        if system_prompt is None:
            system_prompt = """You are an expert network security analyst. Analyze network tool outputs, 
            identify anomalies, security issues, and performance problems. Provide actionable insights 
            and recommend appropriate responses."""
        
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": f"Context:\n{context}\n\nQuery: {query}"}
        ]
        
        try:
            response = ollama.chat(
                model=self.ollama_model,
                messages=messages
            )
            return response['message']['content']
            
        except Exception as e:
            logger.error(f"Error in LLM analysis: {e}", exc_info=True)
            return f"Error: {str(e)}"
    
    async def rag_query(
        self,
        query: str,
        n_results: int = 3,
        where_filter: Optional[Dict] = None
    ) -> Dict[str, Any]:
        """
        Full RAG query: retrieve similar docs and analyze with LLM
        
        Args:
            query: Analysis query
            n_results: Number of similar docs to retrieve
            where_filter: Metadata filter
        
        Returns:
            Dict with retrieved docs and LLM analysis
        """
        # Retrieve similar documents
        similar_results = await self.query_similar(query, n_results, where_filter)
        
        if not similar_results.get('results') or not similar_results['results']['documents']:
            return {
                "query": query,
                "retrieved_docs": [],
                "analysis": "No relevant documents found in the database."
            }
        
        # Build context from retrieved documents
        docs = similar_results['results']['documents'][0]
        metadatas = similar_results['results']['metadatas'][0]
        
        context_parts = []
        for doc, meta in zip(docs, metadatas):
            tool_type = meta.get('tool_type', 'unknown')
            timestamp = meta.get('timestamp', 'unknown')
            context_parts.append(f"[{tool_type} - {timestamp}]\n{doc}\n")
        
        context = "\n---\n".join(context_parts)
        
        # Analyze with LLM
        analysis = await self.analyze_with_llm(context, query)
        
        return {
            "query": query,
            "retrieved_docs": [
                {"content": doc, "metadata": meta} 
                for doc, meta in zip(docs, metadatas)
            ],
            "analysis": analysis
        }
    
    async def detect_anomalies(
        self,
        content: str,
        metadata: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Analyze content for anomalies using RAG and LLM
        
        Args:
            content: Network tool output
            metadata: Tool metadata
        
        Returns:
            Dict with anomaly detection results
        """
        tool_type = metadata.get('tool_type', 'unknown')
        
        # Query for similar historical patterns
        similar = await self.query_similar(
            content,
            n_results=5,
            where_filter={"tool_type": tool_type}
        )
        
        # Build comparison context
        if similar['results'] and similar['results']['documents']:
            historical_docs = similar['results']['documents'][0][:3]
            historical_context = "\n---\n".join(historical_docs)
        else:
            historical_context = "No historical data available."
        
        # LLM analysis for anomaly detection
        anomaly_prompt = f"""Analyze the following {tool_type} output for anomalies, security issues, 
        or unusual patterns. Compare it with historical data if available.

        Current Output:
        {content}

        Historical Similar Patterns:
        {historical_context}

        Identify:
        1. Any security threats (port scans, suspicious traffic, etc.)
        2. Performance issues (packet loss, high latency, etc.)
        3. Configuration problems
        4. Anomalies compared to historical patterns
        5. Severity level (CRITICAL, HIGH, MEDIUM, LOW, INFO)

        Provide your analysis in JSON format with keys: severity, anomalies (list), recommendations (list)"""
        
        analysis = await self.analyze_with_llm(historical_context, anomaly_prompt)
        
        # Try to parse JSON response
        try:
            # Extract JSON from markdown code blocks if present
            if "```json" in analysis:
                analysis = analysis.split("```json")[1].split("```")[0].strip()
            elif "```" in analysis:
                analysis = analysis.split("```")[1].split("```")[0].strip()
            
            anomaly_data = json.loads(analysis)
        except json.JSONDecodeError:
            # Fallback to text analysis
            anomaly_data = {
                "severity": "UNKNOWN",
                "anomalies": ["Unable to parse structured response"],
                "recommendations": [],
                "raw_analysis": analysis
            }
        
        return {
            "tool_type": tool_type,
            "anomaly_data": anomaly_data,
            "similar_patterns_found": similar['count']
        }
    
    async def decide_action(
        self,
        anomaly_result: Dict[str, Any],
        available_tools: List[str]
    ) -> Dict[str, Any]:
        """
        Decide what action to take based on anomaly detection
        
        Args:
            anomaly_result: Result from detect_anomalies
            available_tools: List of available MCP tool names
        
        Returns:
            Dict with recommended actions
        """
        severity = anomaly_result.get('anomaly_data', {}).get('severity', 'UNKNOWN')
        anomalies = anomaly_result.get('anomaly_data', {}).get('anomalies', [])
        
        decision_prompt = f"""Based on the following anomaly detection results, decide what actions to take.

        Severity: {severity}
        Anomalies Found: {json.dumps(anomalies, indent=2)}
        
        Available MCP Tools: {', '.join(available_tools)}
        
        Decide:
        1. Should an alert be sent? (yes/no)
        2. Which alert channels? (email, slack, jira, etc.)
        3. Should any automated remediation be attempted?
        4. What MCP tools should be called and with what parameters?
        
        Respond in JSON format with keys: send_alert (bool), alert_channels (list), 
        remediation_needed (bool), mcp_actions (list of dicts with tool and params)"""
        
        decision = await self.analyze_with_llm("", decision_prompt)
        
        # Parse decision
        try:
            if "```json" in decision:
                decision = decision.split("```json")[1].split("```")[0].strip()
            elif "```" in decision:
                decision = decision.split("```")[1].split("```")[0].strip()
            
            decision_data = json.loads(decision)
        except json.JSONDecodeError:
            # Default safe action for critical/high severity
            if severity in ['CRITICAL', 'HIGH']:
                decision_data = {
                    "send_alert": True,
                    "alert_channels": ["email", "slack"],
                    "remediation_needed": False,
                    "mcp_actions": [],
                    "raw_decision": decision
                }
            else:
                decision_data = {
                    "send_alert": False,
                    "alert_channels": [],
                    "remediation_needed": False,
                    "mcp_actions": [],
                    "raw_decision": decision
                }
        
        return decision_data
    
    async def execute_mcp_action(
        self,
        tool_name: str,
        params: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Execute an action via MCP server
        
        Args:
            tool_name: MCP tool name
            params: Tool parameters
        
        Returns:
            Dict with execution result
        """
        if not self.mcp_server_url:
            return {"error": "MCP server URL not configured"}
        
        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                # Initialize MCP server if needed
                init_response = await client.post(
                    self.mcp_server_url,
                    headers={'content-type': 'application/json'},
                    json={
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "initialize",
                        "params": {
                            "protocolVersion": "2024-11-05",
                            "capabilities": {},
                            "clientInfo": {"name": "rag-network-agent", "version": "1.0.0"}
                        }
                    }
                )
                
                # Call the tool
                tool_response = await client.post(
                    self.mcp_server_url,
                    headers={'content-type': 'application/json'},
                    json={
                        "jsonrpc": "2.0",
                        "id": 2,
                        "method": "tools/call",
                        "params": {
                            "name": tool_name,
                            "arguments": params
                        }
                    }
                )
                
                result = tool_response.json()
                logger.info(f"MCP tool '{tool_name}' executed successfully")
                return result
                
        except Exception as e:
            logger.error(f"Error executing MCP action {tool_name}: {e}", exc_info=True)
            return {"error": str(e)}
    
    async def process_and_act(
        self,
        content: str,
        metadata: Dict[str, Any],
        available_tools: List[str],
        auto_execute: bool = False
    ) -> Dict[str, Any]:
        """
        Complete pipeline: ingest, detect anomalies, decide action, optionally execute
        
        Args:
            content: Network tool output
            metadata: Tool metadata
            available_tools: Available MCP tools
            auto_execute: Whether to automatically execute recommended actions
        
        Returns:
            Dict with complete processing result
        """
        doc_id = f"{metadata.get('tool_type')}_{metadata.get('timestamp')}_{metadata.get('probe', 'default')}"
        
        # Ingest the document
        await self.ingest_document(doc_id, content, metadata)
        
        # Detect anomalies
        anomaly_result = await self.detect_anomalies(content, metadata)
        
        # Decide action
        action_decision = await self.decide_action(anomaly_result, available_tools)
        
        # Execute actions if auto_execute is enabled
        execution_results = []
        if auto_execute and action_decision.get('mcp_actions'):
            for action in action_decision['mcp_actions']:
                tool_name = action.get('tool')
                params = action.get('params', {})
                if tool_name:
                    result = await self.execute_mcp_action(tool_name, params)
                    execution_results.append({
                        "tool": tool_name,
                        "params": params,
                        "result": result
                    })
        
        return {
            "document_id": doc_id,
            "ingested": True,
            "anomaly_detection": anomaly_result,
            "action_decision": action_decision,
            "execution_results": execution_results if execution_results else None
        }
    
    def get_collection_stats(self) -> Dict[str, Any]:
        """Get statistics about the ChromaDB collection"""
        try:
            count = self.collection.count()
            return {
                "collection_name": self.collection_name,
                "total_documents": count,
                "embedding_model": self.embedding_model.get_sentence_embedding_dimension()
            }
        except Exception as e:
            logger.error(f"Error getting collection stats: {e}")
            return {"error": str(e)}