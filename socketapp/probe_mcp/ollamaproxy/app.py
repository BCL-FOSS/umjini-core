import asyncio
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
import ast
from utils.JiraSM import JiraSM
from utils.EmailAlert import EmailAlert
from utils.SlackAlert import SlackAlert
#from utils.orchestration_framework.Supervisorv3 import Supervisor
from utils.orchestration_framework.Workerv2 import LLMWorker
from utils.orchestration_framework.orchestration import Supervisor, Worker
from crontab import CronTab

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
    
async def flow_call_mcp(server_url: str, tool_call: dict, mcp_headers: dict):
    """
    Call the FastMCP server tool with sanitized arguments.
    """
    tool_name = tool_call.get("name")
    args = normalize_arguments(tool_call.get("arguments", {}))
    logger.info(f"Calling MCP tool `{tool_name}` with arguments: {args}")

    async with httpx.AsyncClient() as client:
        # Initialize MCP session
        resp = await client.post(server_url, json=init_payload, headers=mcp_headers, timeout=int(os.environ.get('REQUEST_TIMEOUT')))
        
        session_id = resp.headers.get('mcp-session-id')
        mcp_headers['Mcp-Session-Id'] = session_id
        logger.info(f"Using MCP session: {session_id}")

        # Complete initialization
        init_complete_resp = await client.post(server_url, json=init_complete_payload, headers=mcp_headers, timeout=int(os.environ.get('REQUEST_TIMEOUT')))
        

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

        tool_call_resp = await client.post(server_url, json=tool_call_payload, headers=mcp_headers, timeout=int(os.environ.get('REQUEST_TIMEOUT')))

        # Extract SSE "data:" line
        lines = tool_call_resp.text.split('\n')
        data_line = next((line for line in lines if line.startswith('data: ')), None)
        if data_line:
            result = json.loads(data_line[6:])
            answer = result['result']['content'][0]
            #answer_data = json.loads(answer['text'])
            text = answer.get("text")
            answer_data = json.loads(text)
            #answer_data_parsed = ast.literal_eval(answer_data)
            logger.info(answer_data)
            #await resp.aclose()
            #await init_complete_resp.aclose()
            #await tool_call_resp.aclose()
            return answer_data

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
            #await resp.aclose()
            #await init_complete_resp.aclose()
            #await tool_call_resp.aclose()
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
            #await resp.aclose()
            #await init_complete_resp.aclose()
            #await tool_list_resp.aclose()
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
    tool_instructions = ""
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

    if 'model trained and developed by Baugh Consulting & Lab L.L.C.'.lower() in ollama_out_clean.lower():
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

    logger.info(response_payload)

    return jsonify(response_payload)

@app.route("/v1/analysis", methods=["POST"])
async def analysis():
    data = await request.get_json()
    logger.info(f"Incoming request: {data}")

    model = data.get("model")
    instructions = data.get("instructions")
    user_input = data.get("usr_input")
    user = data.get("user")
    probe_url = data.get('url')
    #api_key = data.get("api_key")
    #passed_headers = headers.copy()
    #passed_headers['x-api-key'] = api_key
    #logger.info(passed_headers)

    # --- Step A: Send conversation to Ollama ---
    conversation = [
        {"role": "system", "content": instructions},
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

    # --- Step B: Parse model output ---
    ollama_out_clean = clean_ollama_output(ollama_out)

    logger.info(ollama_out_clean)

    final_output = ""
    #final_output+=f'{user_input}\n\n'

    final_output=ollama_out_clean

    response_payload={
        "id": f"resp:{user}:{probe_url}:{datetime.now(timezone.utc)}:{uuid.uuid4()}",
        "user_msg": user_input,
        "output_text": final_output
    }

    # --- Step C: Return OpenAI-style response ---
    return jsonify(response_payload)
    
@app.route('/v1/run', methods=['POST'])
async def run():
    data = await request.get_json()
    logger.info(f"Incoming request: {data}")
    flow_id = data.get('id')
    probe = data.get('probe')

    await cl_data_db.connect_db()

    primary_probe = await cl_data_db.get_all_data(match=f"*{probe}*")
    selected_flow = await cl_data_db.get_all_data(match=f"*{flow_id}*")

    logger.info(primary_probe)

    if primary_probe and selected_flow is not None:
        agents = []
        llm_agents = {}
        agent_count = 0
        static_graph = []

        # Primary probe data
        probe_key=next(iter(primary_probe))
        inner_probe_data=primary_probe[probe_key]
        url = inner_probe_data['url']
        mcp_url = f'{url}/llm/mcp'
        logger.info(selected_flow)

        # Flow data
        main_key = next(iter(selected_flow))
        inner = selected_flow[main_key]
        flow_str = inner['flow']
        # Convert the string into a dict safely
        # Because it uses single quotes, we can use `ast.literal_eval`
        flow_dict = ast.literal_eval(flow_str)

        # Parsed flow data
        workflow = flow_dict
        logger.info(workflow)
        workflow_data = workflow['drawflow']['Home']['data']
        logger.info(workflow_data)

        # Node output mapping for llmagent summarization/alert execution
        node_output_mapping = {}
        supervisor_connection_instructions = ""
            
        for node_id, node in workflow_data.items():
            node_data = node.get('data')
            inputs = node.get('inputs')
            logger.info(inputs)
            outputs = node.get('outputs')
            logger.info(outputs)

            if outputs != {}:
                for key, value in outputs.items():
                    logger.info(f"{key}:{value}")
                    if value.get('connections') != []:
                        for connection in value.get('connections'):
                                #supervisor_connection_instructions+= f'Agent {node_id} sends output to agent {connection['node']}\n' 
                            if node_id not in static_graph:
                                static_graph.append(node_id)
                            if connection["node"] not in static_graph:
                                static_graph.append(connection["node"])
                            node_output_mapping[node_id] = connection['node']

            if inputs != {}:
                for key, value in inputs.items():
                    if value.get('connections') != []:
                        for connection in value.get('connections'):
                                #supervisor_connection_instructions+= f'Agent {node_id} receives input from agent {connection['node']}\n'
                            if node_id not in static_graph:
                                static_graph.append(node_id)
                            if connection["node"] not in static_graph:
                                static_graph.append(connection["node"])

                            

            match node_data['type']:
                case 'mcp':
                    secondary_probe = await cl_data_db.get_all_data(match=f'*{node_data['name']}*')
                    if secondary_probe is not None:
                        secondary_probe_key=next(iter(secondary_probe))
                        inner_secondary_probe_data=secondary_probe[secondary_probe_key]
                        url = inner_secondary_probe_data['url']
                        secondary_mcp_url = f'{url}/llm/mcp'
                       
                        primary_args = {}
                        secondary_args = {}

                        primary_tool_data = {}
                        secondary_tool_data = {}

                        primary_probe_headers = {
                            'accept': 'application/json, text/event-stream',
                            'content-type': 'application/json',
                            'x-api-key': inner_probe_data['prb_api_key']
                        }

                        secondary_probe_headers = {
                            'accept': 'application/json, text/event-stream',
                            'content-type': 'application/json',
                            'x-api-key': inner_secondary_probe_data['prb_api_key']
                        }

                        if node_data['mcptool'] == 'iperf_c':
                            # Server Settings
                            primary_tool_data['name'] = 'speedtest_server'
                            
                            if node_data['spdsoptions'] is not None or "".strip():
                                primary_args['options'] = node_data['spdsoptions']
                            
                            if node_data['spdshost'] is not None or "".strip():
                                primary_args['host'] = node_data['spdshost']

                            primary_tool_data['arguments'] = primary_args

                            # Client Settings
                            secondary_tool_data['name'] = 'speedtest_client'

                            if node_data['spdcserver'] is not None or "".strip():
                                secondary_args['server'] = node_data['spdcserver']
                            
                            if node_data['spdcoptions'] is not None or "".strip():
                                secondary_args['options'] = node_data['spdcoptions']
                            
                            if node_data['spdchost'] is not None or "".strip():
                                secondary_args['host'] = node_data['spdchost']

                            secondary_tool_data['arguments'] = secondary_args

                            tool_params = {
                                "flow_call_mcp": [
                                    {
                                        "tool_call": primary_tool_data,
                                        "server_url": mcp_url,
                                        "mcp_headers": primary_probe_headers,
                                    },
                                    {
                                        "tool_call": secondary_tool_data,
                                        "server_url": secondary_mcp_url,
                                        "mcp_headers": secondary_probe_headers,
                                    }
                                ]
                            }

                        if node_data['mcptool'] == 'iperf_s':
                            # Server Settings
                            secondary_tool_data['name'] = 'speedtest_server'
                            
                            if node_data['spdsoptions'] is not None or "".strip():
                                secondary_args['options'] = node_data['spdsoptions']
                            
                            if node_data['spdshost'] is not None or "".strip():
                                secondary_args['host'] = node_data['spdshost']

                            secondary_tool_data['arguments'] = secondary_args

                            # Client Settings
                            primary_tool_data['name'] = 'speedtest_client'

                            if node_data['spdcserver'] is not None or "".strip():
                                primary_args['server'] = node_data['spdcserver']
                            
                            if node_data['spdcoptions'] is not None or "".strip():
                                primary_args['options'] = node_data['spdcoptions']
                            
                            if node_data['spdchost'] is not None or "".strip():
                                primary_args['host'] = node_data['spdchost']

                            primary_tool_data['arguments'] = primary_args

                            tool_params = {
                                "flow_call_mcp": [
                                    {
                                        "tool_call": secondary_tool_data,
                                        "server_url": secondary_mcp_url,
                                        "mcp_headers": secondary_probe_headers,
                                    },
                                    {
                                        "tool_call": primary_tool_data,
                                        "server_url": mcp_url,
                                        "mcp_headers": primary_probe_headers,
                                    }
                                ]
                            }

                        if node_data['mcptool'] == 'trct_tar':
                            primary_tool_data['name'] = 'traceroute'

                            primary_args['target'] = secondary_probe.get('url')

                            if node_data['trcoptions'] is not None or "".strip():
                                primary_args['options'] = node_data['trcoptions']

                            if node_data['packetlen'] is not None or "".strip():
                                primary_args['packetlength'] = node_data['packetlen']

                            primary_tool_data['arguments'] = primary_args

                            tool_params = {
                                "flow_call_mcp": [
                                    {
                                        "tool_call": primary_tool_data,
                                        "server_url": mcp_url,
                                        "mcp_headers": primary_probe_headers,
                                    }
                                ]
                            }

                        if node_data['mcptool'] == 'dnstrct_tar':
                            primary_tool_data['name'] = 'traceroute'

                            primary_args['target'] = secondary_probe.get('url')

                            if node_data['trcoptions'] is not None or "".strip():
                                primary_args['options'] = node_data['trcoptions']

                            if node_data['dnstrcserver'] is not None or "".strip():
                                primary_args['server'] = node_data['dnstrcserver']

                            primary_tool_data['arguments'] = primary_args

                            
                            tool_params = {
                                "flow_call_mcp": [
                                    {
                                        "tool_call": primary_tool_data,
                                        "server_url": mcp_url,
                                        "mcp_headers": primary_probe_headers,
                                    }
                                ]
                            }

                        agents.append(Worker(
                                name=node_id,
                                tools={"flow_call_mcp": flow_call_mcp},
                                tool_params=tool_params
                            )
                        )
                        #agent_count +=1
                
                case 'alert':
                    if node_data['name'] == 'jsm':

                        if await cl_data_db.get_all_data(match=f'alrt:jira:*', cnfrm=True) is False:
                            return jsonify({'Create an email alert contact. None currently available.'}), 404

                        if await cl_data_db.get_all_data(match=f'alrt:jira:{node_data['jiraid']}*', cnfrm=True) is False:
                            jira_contact = await cl_data_db.get_all_data(match=f'alrt:jira:1*')
                        else:
                            jira_contact = await cl_data_db.get_all_data(match=f'alrt:jira:{node_data['jiraid']}*')

                        jira_contact_dict=next(iter(jira_contact.values()))

                        jira_alert = JiraSM(cloud_id=jira_contact_dict.get('cloud_id'), auth_email=jira_contact_dict.get('eml'), auth_token=jira_contact_dict.get('token'))

                        tool_key = "jira_send_alert"
                        fields = {
                            "message": "<short summary of the incident or anomaly>",
                            "desc": "<detailed description including metrics/errors>",
                            "note": "<any notes for responders>",
                            "source": "<name of originating system or upstream agent>",
                            "entity": "<affected entity/server>",
                            "alias": "<unique alias for alert>",
                            "priority": "<P1|P2|P3...>",
                            "actions": [],
                            "extra_properties": {},
                        }
                        fallback = {**fields}
                        prompt = f"""You are an alert agent called {node_id} that receives traceroute, dnstraceroute, iperf speedtest and nmap scan results as input. Use your knowledge of network engineering, network administration, firewall configurations, and network security according to NIST, PCI DSS, GDPR, HIPAA and SOC 2 compliance standards to analyze the input for any network misconfigurations, anomalies, errors and security vulnerabilities. If your analysis finds any network misconfigurations, anomalies, errors or security vulnerabilities, build a JIRA alert payload and generate the following fields:
                            - message, desc, note, source, entity, alias, priority, actions, extra_properties
                        Output the JIRA alert payload in the following format:
                            TOOL:jira_send_alert:[{json.dumps(fields)}]
                        Fill each field dynamically from the incoming message/context.
                        If you cannot determine the parameters, output nothing and the fallback configuration will be used.
                        If no network misconfigurations, anomalies, errors or security vulnerabilities are found in the received input data, output:
                            No anomalies, errors or misconfigurations have been identified.
                        """
                        tool_name = {"jira_send_alert": jira_alert.send_alert}

                    if node_data['name'] == 'email':

                        if await cl_data_db.get_all_data(match=f'alrt:eml:*', cnfrm=True) is False:
                            return jsonify({'Create an email alert contact. None currently available.'}), 404
                        
                        if await cl_data_db.get_all_data(match=f'alrt:eml:{node_data['emailid']}*', cnfrm=True) is False:
                            email_contact = await cl_data_db.get_all_data(match=f'alrt:eml:1*')
                        else:
                            email_contact = await cl_data_db.get_all_data(match=f'alrt:eml:{node_data['emailid']}*')
                            
                        email_contact_dict=next(iter(email_contact.values()))

                        email_alert = EmailAlert(host=email_contact_dict.get('host'), port=email_contact_dict.get('port'), username=email_contact_dict.get('user'), password=email_contact_dict.get('pwd'), tls=email_contact_dict.get('tls'), sender=email_contact_dict.get('sender'))

                        tool_key = "email_send_alert"
                        fields = {
                            "subject": "<short summary>",
                            "message": "<detailed description including errors and actions>",
                            "recipient": node_data['emailrecipient'],
                        }
                        fallback = {**fields}
                        prompt = f"""You are an alert agent called {node_id} that receives traceroute, dnstraceroute, iperf speedtest and nmap scan results as input. Use your knowledge of network engineering, network administration, firewall configurations, and network security according to NIST, PCI DSS, GDPR, HIPAA and SOC 2 compliance standards to analyze the input for any network misconfigurations, anomalies, errors and security vulnerabilities. If your analysis finds any network misconfigurations, anomalies, errors or security vulnerabilities, build a EMAIL alert payload and generate the following fields:
                            - subject, message
                        Output the EMAIL alert payload in the following format:
                            TOOL:email_send_alert:[{json.dumps(fields)}]
                        Fill each field dynamically from the incoming message/context.
                        If you cannot determine the parameters, output nothing and the fallback configuration will be used.
                        If no network misconfigurations, anomalies, errors or security vulnerabilities are found in the received input data, output:
                            No anomalies, errors or misconfigurations have been identified.
                       """
                        tool_name = {"email_send_alert": email_alert.send_email_alert}

                    if node_data['name'] == 'slack':

                        if await cl_data_db.get_all_data(match=f'alrt:slack:*', cnfrm=True) is False:
                            return jsonify({'Create a slack alert contact. None currently available.'}), 404
                        
                        if await cl_data_db.get_all_data(match=f'alrt:slack:{node_data['slackid']}*', cnfrm=True) is False:
                            slack_contact = await cl_data_db.get_all_data(match=f'alrt:slack:1*')
                        else:
                            slack_contact = await cl_data_db.get_all_data(match=f'alrt:slack:{node_data['slackid']}*')

                        slack_contact_dict=next(iter(slack_contact.values()))

                        slack_alert = SlackAlert(slack_bot_token=slack_contact_dict.get('token'), slack_channel_id=slack_contact_dict.get('channel_id'))

                        tool_key = "slack_send_alert"
                        fields = {
                            "channel_id": "<slack channel id>",
                            "message": "<detailed alert message>",
                        }
                        fallback = {**fields}
                        prompt = f"""You are an alert agent called {node_id} that receives traceroute, dnstraceroute, iperf speedtest and nmap scan results as input. Use your knowledge of network engineering, network administration, firewall configurations, and network security according to NIST, PCI DSS, GDPR, HIPAA and SOC 2 compliance standards to analyze the input for any network misconfigurations, anomalies, errors and security vulnerabilities. If your analysis finds any network misconfigurations, anomalies, errors or security vulnerabilities, build a SLACK alert payload and generate the following fields:
                            - message
                        Output the SLACK alert payload in the following format:
                            TOOL:slack_send_alert:[{json.dumps(fields)}]
                        Fill each field dynamically from the incoming message/context.
                        If you cannot determine the parameters, output nothing and the fallback configuration will be used.
                        If no network misconfigurations, anomalies, errors or security vulnerabilities are found in the received input data, output:
                            No anomalies, errors or misconfigurations have been identified.
                        """
                        tool_name = {"slack_send_alert": slack_alert.send_alert_message}

                    tool_params = {tool_key: [fallback]}

                    llm_agents[node_id] = LLMWorker(
                                name=node_id,
                                model=os.environ.get("OLLAMA_MODEL"),
                                tools=tool_name,
                                prompt=prompt,
                                tool_params=tool_params
                            )
                        
                    #agent_count +=1
                case 'tool':
                    primary_args = {}
                    primary_tool_data = {}
                    primary_probe_headers = {
                        'accept': 'application/json, text/event-stream',
                        'content-type': 'application/json',
                        'x-api-key': inner_probe_data['prb_api_key']
                    }

                    logger.info(f"Primary probe API key: {inner_probe_data['prb_api_key']}")

                    if node_data['name'] == 'traceroute':
                        if 'target' in node_data and node_data['target'] is not None or "".strip():
                            primary_args['target'] = node_data['target']

                        if 'options' in node_data and node_data['options'] is not None or "".strip():
                            primary_args['options'] = str(node_data['options'])

                        if 'packetlen' in node_data and node_data['packetlen'] is not None or "".strip():
                            primary_args['packetlength'] = str(node_data['packetlen'])

                        primary_tool_data['name'] = node_data['name']
                        primary_tool_data['arguments'] = primary_args

                        tool_params = {
                                "flow_call_mcp": [
                                    {
                                        "tool_call": primary_tool_data,
                                        "server_url": mcp_url,
                                        "mcp_headers": primary_probe_headers,
                                    }
                                ]
                            }

                    if node_data['name'] == 'traceroute_dns':
                        if node_data['target'] is not None or "".strip():
                            primary_args['target'] = node_data['target']

                        if node_data['options'] is not None or "".strip():
                            primary_args['options'] = str(node_data['options'])

                        if node_data['server'] is not None or "".strip():
                            primary_args['server'] = str(node_data['server'])

                        primary_tool_data['name'] = node_data['name']
                        primary_tool_data['arguments'] = primary_args

                        tool_params = {
                                "flow_call_mcp": [
                                    {
                                        "tool_call": primary_tool_data,
                                        "server_url": mcp_url,
                                        "mcp_headers": primary_probe_headers,
                                    }
                                ]
                            }

                    agents.append(Worker(
                        name=node_id,
                        tools={"flow_call_mcp": flow_call_mcp},
                        tool_params=tool_params
                        )
                    )
                    #agent_count +=1

        """
        advanced_supervisor_prompt = (
            f"You are an AI workflow supervisor for a multi-agent orchestration system managing {agent_count} agents. "
            "Agents may need to run in different orders, with results passed between them, depending on the workflow state. "
            "At each step, decide which agent to run next and what inputs/results to pass. "
            "You must reason about dependencies, results, and overall workflow goals. "
            "Output your orchestration decision as valid JSON: "
            "{\"run_agent\": \"<name>\", \"inputs\": {...}, \"done\": false} "
            "If you are finished, set \"done\": true. "
            "If you cannot reason about next actions, the system will fallback to static connection order."
            f"\nAvailable agents: {', '.join([a.name for a in agents])}\n"
            f"Workflow connection instructions:\n{supervisor_connection_instructions}\n"
            "History and state will be provided at each step."
        )
        """

        logger.info(f"Current workers: {agents}")

        logger.info(static_graph)

        supervisor = Supervisor(
            workers=agents
        )

        result = await supervisor.orchestrate(static_graph=static_graph)
        logger.info(result)

        if node_output_mapping != {}:
            executed_agents = list(result.keys())

            for agent in executed_agents:
                if node_output_mapping.get(agent) is not None:
                    llm_worker_input=result[agent]['flow_call_mcp'][0][1]
                    llm_agent_result = await llm_agents.get(node_output_mapping.get(agent)).act(incoming_message=llm_worker_input)
                    llm_output_data = llm_agent_result[0]['result']
                    logger.info(llm_output_data)
                    return jsonify({'compiled': True, 'result': llm_output_data}), 200  

        #agent_count = 0

        return jsonify({'compiled': True, 'result': result}), 200    
    else:
        return jsonify({'compiled': False, 'result': None}), 400

@app.route('/v1/save', methods=['POST'])
async def save():
    data = await request.get_json()
    logger.info(data)
    id = data.get('id')
    flow = json.loads(data.get('flow'))
    user = data.get('unm')
    selected_probe = data.get('probe')
    name = data.get('name')
    flow_id = f'flow:{id}:{str(uuid.uuid4())}'

    flow_data = {
        'id': flow_id,
        'probe': selected_probe,
        'flow': flow,
        'name': name
    }
    logger.info(flow_data)

    await cl_data_db.connect_db()

    save_flow = await cl_data_db.upload_db_data(id=flow_id, data=flow_data)

    if save_flow is not None:
        return jsonify({'status':'saved', 'flow':f'{flow_id}.json'})
    else:
        return jsonify({'status':'failed'})

@app.route('/v1/load', methods=['POST'])
async def load():
    data = await request.get_json()
    logger.info(data)
    id = data.get('id')

    await cl_data_db.connect_db()

    requested_flow = await cl_data_db.get_all_data(f'*{id}*')

    if requested_flow is not None:
        logger.info(requested_flow)
        flow_key=next(iter(requested_flow))
        requested_flow_data=requested_flow[flow_key]
        flow_data_str = requested_flow_data['flow']
        flow_dict = ast.literal_eval(flow_data_str)

        logger.info(flow_dict)
        return jsonify(flow_dict)
    else:
        return jsonify({'status':'error'}), 400
    
@app.route('/v1/delete', methods=['POST'])
async def delete():
    data = await request.get_json()
    logger.info(data)
    id = data.get('id')

    await cl_data_db.connect_db()

    result = await cl_data_db.del_obj(key=id)

    if result is not None:
        return jsonify(result), 200
    
@app.route('/v1/edit', methods=['POST'])
async def edit():
    data = await request.get_json()
    logger.info(data)
    id = data.get('id')
    probe = data.get('probe')
    flow_data = data.get('flow')
    name = data.get('name')

    await cl_data_db.connect_db()

    if await cl_data_db.del_obj(key=id) is not None:
        flow_data_payload = {
            'id': id,
            'probe': probe,
            'flow': flow_data,
            'name': name
        }
        logger.info(flow_data_payload)

        if await cl_data_db.upload_db_data(id=id, data=flow_data_payload) > 0:
            return jsonify({'status':'edited', 'flow':f'{id}.json'}), 200
        else:
            return jsonify({'status':'failed'}), 400
        
@app.route('/v1/schedule', methods=['POST'])
async def schedule():
    data = await request.get_json() 
    logger.info(data)
    id = data.get('id')
    schedule = data.get('schedule')
    probe = data.get('probe')
    cron=CronTab()
    cwd = os.getcwd()

    await cl_data_db.connect_db()

    if await cl_data_db.get_all_data(match=f'{probe}', cnfrm=True) is True:
        probe_data = await cl_data_db.get_all_data(match=f'*{probe}*')
        probe_data_dict=next(iter(probe_data.values()))
        prb_id = probe_data_dict.get('prb_id')

    ws_url = f'wss://{os.environ.get('SERVER_NAME')}/heartbeat/{prb_id}'
    script_path = os.path.join(cwd, 'task_auto.py') 
    job1=cron.new(command=f"python3 {script_path} -id {id} -p {probe} -ws {ws_url}", comment=f"auto_task_{id}_{probe}")

    if 'minutes' in schedule and schedule['minutes']:
        minutes_range = str(schedule['minutes']).split(",")
        if isinstance(minutes_range, list):
            if len(minutes_range) == 3:
                job1.minute.during(minutes_range[0], minutes_range[1]).every(minutes_range[2])
            elif len(minutes_range) == 2:
                job1.minute.during(minutes_range[0], minutes_range[1])
            elif len(minutes_range) == 1:
                job1.minute.every(minutes_range[0])

    if 'hours' in schedule and schedule['hours']:
        hours_range = str(schedule['hours']).split(",")
        if isinstance(hours_range, list):
            if len(hours_range) == 3:
                job1.hour.during(hours_range[0], hours_range[1]).every(hours_range[2])
            elif len(hours_range) == 2:
                job1.hour.during(hours_range[0], hours_range[1])
            elif len(hours_range) == 1:
                job1.hour.every(hours_range[0])

    if 'dom' in schedule and schedule['dom']:
        dom_range = str(schedule['dom']).split(",")
        if isinstance(dom_range, list):
            if len(dom_range) == 3:
                job1.dom.during(dom_range[0], dom_range[1]).every(dom_range[2])
            elif len(dom_range) == 2:
                job1.dom.during(dom_range[0], dom_range[1])
            elif len(dom_range) == 1:
                job1.dom.every(dom_range[0])

    if 'days' in schedule and schedule['days']:
        days_range = str(schedule['days']).split(",")
        if isinstance(days_range, list):
            job1.dow.on(days_range)

    if 'months' in schedule and schedule['months']:
        months_range = str(schedule['months']).split(",")
        if isinstance(months_range, list):
            if len(months_range) == 3:
                job1.month.during(months_range[0], months_range[1]).every(months_range[2])
            elif len(months_range) == 2:
                job1.month.during(months_range[0], months_range[1])
            elif len(months_range) == 1:
                job1.month.every(months_range[0])


    if await asyncio.to_thread(job1.is_valid()):
        await asyncio.to_thread(cron.write())
        return jsonify({'status':'scheduled'}), 200
    else:
        return jsonify({'status':'failed'}), 400
                         

   
