import re
import json
import httpx
import uuid
from quart import request, jsonify
from init_app import app, logger
from utils.RedisDB import RedisDB
import os
import uuid
from datetime import datetime, timezone

cl_data_db = RedisDB(hostname=os.environ.get('CL_DATA_DB'), port=os.environ.get('CL_DATA_DB_PORT'))

OLLAMA_URL_FLOW = "http://ollama:11434"
OLLAMA_URL = "http://ollama:11434/api/chat"
REQUIRED_OUT_OF_SCOPE_MSG = "Please provide a question or request related to network administration or the available MCP tools."

# Headers and payloads to initialize MCP server connections
headers = {
    'accept': 'application/json, text/event-stream',
    'content-type': 'application/json'
}

init_payload = {
    "jsonrpc": "2.0",
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-08-24",
        "capabilities": {},
        "clientInfo": {
            "name": "python-client",
            "version": "1.0.0"
        }
    },
    "id": 1
}

init_complete_payload = {
    "jsonrpc": "2.0",
    "method": "notifications/initialized"
}

# === Utility: Clean Ollama output ===
def clean_ollama_output(raw: str) -> str:
    """Strip <think> blocks and whitespace from model output."""
    return re.sub(r"<think>.*?</think>", "", raw, flags=re.S).strip()


# === Defensive parser for MCP arguments ===
def normalize_arguments(args):
    """
    Ensure arguments are always a dict of values (per OpenAI tool spec).
    If model echoes a schema, convert required keys to placeholders.
    """
    if isinstance(args, dict):
        logger.debug(f"Using arguments as-is: {args}")
        return args
    elif isinstance(args, list) and len(args) > 0 and isinstance(args[0], dict):
        schema_obj = args[0]
        clean_args = {}
        for req in schema_obj.get("required", []):
            clean_args[req] = f"<missing:{req}>"
        logger.warning(f"Model returned schema instead of values. Converted to placeholders: {clean_args}")
        return clean_args
    else:
        logger.warning(f"Unexpected arguments format: {args}")
        return {}

async def call_mcp(server_url: str, tool_call: dict):
    """
    Call the FastMCP server tool with sanitized arguments.
    """
    tool_name = tool_call.get("name")
    args = normalize_arguments(tool_call.get("arguments", {}))
    logger.info(f"Calling MCP tool `{tool_name}` with arguments: {args}")

    async with httpx.AsyncClient() as client:
        # Initialize MCP session
        resp = await client.post(server_url, json=init_payload, headers=headers, timeout=int(os.environ.get('REQUEST_TIMEOUT')))
        
        session_id = resp.headers.get('mcp-session-id')
        headers['Mcp-Session-Id'] = session_id
        logger.info(f"Using MCP session: {session_id}")

        # Complete initialization
        init_complete_resp = await client.post(server_url, json=init_complete_payload, headers=headers, timeout=int(os.environ.get('REQUEST_TIMEOUT')))

        # Perform tool call
        tool_call_payload = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": tool_name,
                "arguments": args
            },
            "id": 2
        }

        tool_call_resp = await client.post(server_url, json=tool_call_payload, headers=headers, timeout=int(os.environ.get('REQUEST_TIMEOUT')))

        # Extract SSE "data:" line
        lines = tool_call_resp.text.split('\n')
        data_line = next((line for line in lines if line.startswith('data: ')), None)
        if data_line:
            result = json.loads(data_line[6:])
            answer = result['result']['content'][0]
            #answer_data = json.loads(answer['text'])
            text = answer.get("text")
            answer_data = json.loads(text)
            return answer_data

async def fetch_mcp_tools(server_url: str) -> list:
    """
    Fetch available tool schemas (inputs + returns) from MCP server manifest.
    """
    async with httpx.AsyncClient() as client:
        resp = await client.post(server_url, json=init_payload, headers=headers, timeout=int(os.environ.get('REQUEST_TIMEOUT')))
      
        session_id = resp.headers.get('mcp-session-id')
        headers['Mcp-Session-Id'] = session_id
        logger.info(f"Fetched MCP session: {session_id}")

        init_complete_resp = await client.post(server_url, json=init_complete_payload, headers=headers, timeout=int(os.environ.get('REQUEST_TIMEOUT')))

        tool_list_payload = {
            "jsonrpc": "2.0",
            "method": "tools/list",
            "id": 2
        }

        tool_list_resp = await client.post(server_url, json=tool_list_payload, headers=headers, timeout=int(os.environ.get('REQUEST_TIMEOUT')))

        lines = tool_list_resp.text.split('\n')
        data_line = next((line for line in lines if line.startswith('data: ')), None)
        if data_line:
            result = json.loads(data_line[6:])
            tool_data = result['result']
            logger.info(f"Available tools: {tool_data['tools']}")
            return tool_data['tools']

@app.route("/v1/multitools", methods=["POST"])
async def multitools():
    data = await request.get_json()
    logger.info(f"Incoming request: {data}")

    model = data.get("model")
    instructions = data.get("instructions")
    user_input = data.get("usr_input")
    tools = data.get("tools")
    user = data.get("user")
    api_key = data.get("api_key")
    headers['x-api-key'] = api_key
    logger.info(headers)
    tool_instructions = ""

    if 'tool_instructions' in data and data['tool_instructions']:
        tool_instructions = data['tool_instructions']

    else:
        # --- Step A: Collect tool schemas from MCP servers ---
        tool_schemas = []
        for t in tools:
            if t.get("type") == "mcp":
                mcp_tools = await fetch_mcp_tools(server_url=t["server_url"])
                if mcp_tools is None:
                    return {'Error': f"Failed to fetch tools from {t['server_url']}"}
                for tool in mcp_tools:
                    tool_schemas.append({
                        "server_label": t["server_label"],
                        "server_url": t["server_url"],
                        "schema": tool
                    })

        logger.info(tool_schemas)
        # --- Step B: Build tool instructions for the LLM ---
        if tool_schemas:
            tool_instructions += (
                "You have access to the following tools. "
                "When using them, respond ONLY with a JSON object in this format:\n"
                '{"name": "<tool_name>", "arguments": {"param1": "value1", "param2": "value2"}}\n\n'
                "Arguments must always be concrete values, not schemas or descriptions.\n\n"
                "✅ Valid example:\n"
                '{"name": "controller_system_data", "arguments": {"user": "hollow", "ip": "ubnt.baughcl.tech"}}\n\n'
                "❌ Invalid example:\n"
                '{"name": "controller_system_data", "arguments": [{"properties": {"user": {...}, "ip": {...}}}]}\n\n'
                "If you want to call multiple tools in a single response, return a JSON array of objects, e.g.:\n"
                "✅ Valid example:\n"
                '[{"name": "tool_a", "arguments": {...}}, {"name": "tool_b", "arguments": {...}}]\n\n'   
                "Available tools:\n"
            )
            for ts in tool_schemas:
                sch = ts["schema"]
                tool_instructions += f"- {sch['name']}: {sch['description']}\n"
                tool_instructions += f"  Parameters: {json.dumps(sch['inputSchema'])}\n"

    # --- Step C: Send conversation to Ollama ---
    conversation = [
        {"role": "system", "content": instructions + "\n" + tool_instructions},
        {"role": "user", "content": user_input},
    ]

    async with httpx.AsyncClient() as client:
        resp = await client.post(
            OLLAMA_URL,
            json={"model": model, "messages": conversation, "stream": False},
            timeout=int(os.environ.get('REQUEST_TIMEOUT')),
        )
      
        ollama_json = resp.json()
        ollama_out = ollama_json.get("message", {}).get("content", "")
        logger.info(f"Ollama output (raw): {ollama_out}")
        #await resp.aclose()

    # --- Step D: Parse model output ---
    ollama_out_clean = clean_ollama_output(ollama_out)

    if f"I am a locally hosted, open source {model} model running on ollama.".lower() in ollama_out_clean.lower():
        logger.info(tools[0].get('server_url'))

        response_payload={
            "id": f"resp:{user}:{tools[0].get('server_url')}:{datetime.now(timezone.utc)}:{uuid.uuid4()}",
            "user_msg": user_input,
            "output_text": ollama_out_clean
        }

        logger.info(response_payload)

        return jsonify(response_payload)
    
    if f"SmartBot-Remediation: ".lower() in ollama_out_clean.lower():
        logger.info(tools[0].get('server_url'))

        response_payload={
            "id": f"resp:{user}:{tools[0].get('server_url')}:{datetime.now(timezone.utc)}:{uuid.uuid4()}",
            "user_msg": user_input,
            "output_text": ollama_out_clean
        }

        logger.info(response_payload)

        return jsonify(response_payload)
    
    parsed = None
    try:
        parsed = json.loads(ollama_out_clean)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", ollama_out_clean, re.S)
        if match:
            try:
                parsed = json.loads(match.group())
            except Exception as e:
                logger.warning(f"Could not parse JSON block: {e}")

    # --- Step E: Handle tool calls with retry on bad format ---
    tool_outputs = []
    final_output = ""

    def is_valid_arguments(obj):
        return isinstance(obj.get("arguments", {}), dict)

    # Helper: re-prompt Ollama when output is invalid
    async def retry_with_clarification(conversation, reason, bad_output):
        logger.warning(f"Bad tool call output detected. Reason: {reason}")
        logger.warning(f"--- BAD OUTPUT ---\n{bad_output}\n-----------------")

        conversation.append({
            "role": "system",
            "content": (
                f"Your previous output could not be parsed because: {reason}. "
                "Please retry by returning ONLY a JSON object with concrete argument values, like:\n"
                '{"name": "tool_name", "arguments": {"param": "value"}}\n'
                "Do NOT return schemas, descriptions, or wrap arguments in arrays."
            )
        })
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                OLLAMA_URL,
                json={"model": model, "messages": conversation, "stream": False},
                timeout=int(os.environ.get('REQUEST_TIMEOUT')),
            )
            #resp.raise_for_status()
            retry_json = resp.json()
            retry_out = retry_json.get("message", {}).get("content", "")
            logger.info(f"--- RETRY OUTPUT ---\n{retry_out}\n-------------------")
            #await resp.aclose()
            return clean_ollama_output(retry_out)

    # If parsed is bad or arguments are schema instead of values
    if not (isinstance(parsed, dict) and "name" in parsed and is_valid_arguments(parsed)) and not (isinstance(parsed, list)):
        reason = "Arguments were not a dict of values or a list of tool calls"
        retry_output = await retry_with_clarification(conversation, reason, ollama_out_clean)
        logger.info(retry_output)

        if retry_output.lower() == REQUIRED_OUT_OF_SCOPE_MSG.lower():
            error_payload={
                "output_text": retry_output
            }

            logger.info(error_payload)

            return jsonify(error_payload)

        try:
            parsed = json.loads(retry_output)
        except json.JSONDecodeError:
            match = re.search(r"\{.*\}", retry_output, re.S)
            if match:
                try:
                    parsed = json.loads(match.group())
                except Exception as e:
                    logger.warning(f"Retry also failed to parse JSON: {e}")

    # After retry, try tool call(s) handling
    # Support multiple tool calls by accepting a JSON array of {"name":..., "arguments": {...}} objects
    tool_calls = []

    if isinstance(parsed, dict) and "name" in parsed and is_valid_arguments(parsed):
        tool_calls = [parsed]
    elif isinstance(parsed, list):
        # Filter only valid tool call dicts
        for item in parsed:
            if isinstance(item, dict) and "name" in item and is_valid_arguments(item):
                tool_calls.append(item)
            else:
                logger.warning(f"Skipping invalid tool call item: {item}")
    else:
        logger.warning("Model did not return a valid tool call after retry.")
        final_output = REQUIRED_OUT_OF_SCOPE_MSG

    # Execute each tool call (if any)
    if tool_calls:
        # For each tool call, find which MCP server provides it and call it
        for tc in tool_calls:
            tool_name = tc.get("name") 
            server_url = None
            server_label = None
            for ts in tool_schemas:
                if ts["schema"]["name"] == tool_name:
                    server_url = ts["server_url"]
                    server_label = ts["server_label"]
                    break

            if server_url:
                try:
                    result = await call_mcp(server_url=server_url, tool_call=tc)
                    tool_outputs.append({"tool": tool_name, "server": server_label, "server_url": server_url, "output": result})
                except Exception as e:
                    logger.exception(f"Error calling MCP tool {tool_name} on {server_url}: {e}")
                    tool_outputs.append({"tool": tool_name, "server": server_label, "server_url": server_url, "error": str(e)})
            else:
                logger.warning(f"No server found exposing tool `{tool_name}`; marking as out-of-scope")
                tool_outputs.append({"tool": tool_name, "error": "Tool not available on known MCP servers"})

        response_payload={}

        """
        if len(tool_outputs) == 1:
            final_output = json.dumps(tool_outputs[0].get("output"))
            response_payload['output_type'] = 'single_tool'
        else:
            final_output = json.dumps(tool_outputs)
            response_payload['output_type'] = 'multi_tool'
        """
    
        final_output = json.dumps(tool_outputs)

    response_payload['id'] = f"resp:{user}:{server_url}:{(tool_calls[0].get('name') if tool_calls else 'none')}:"
    response_payload['user_msg'] = user_input
    response_payload['output_text'] = final_output
    response_payload['tool_outputs'] = tool_outputs
    response_payload['tool_calls'] = tool_calls
    response_payload['tool_instructions'] = tool_instructions
    response_payload['ollama_out_clean'] = ollama_out_clean

    logger.info(response_payload)

    return jsonify(response_payload)

@app.route('/v1/exec', methods=['POST'])
async def exec():
    data = await request.get_json()
    logger.info(data)
    headers['x-api-key'] = data['prb-api-key']
    result = await call_mcp(server_url=data['prb-url'], tool_call=data)

    return {"tool": data['name'], "server_url": data['prb-url'], "output": result}