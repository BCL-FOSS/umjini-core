from init_app import (app)
from quart import (Request, Websocket, websocket, render_template_string, make_response)
import asyncio
from utils.broker import Broker
from quart import jsonify
from quart.utils import run_sync
import json
from init_app import app, logger
from quart_rate_limiter import rate_exempt
import os
from probe_mcp.ollamaproxy.utils.RedisDB import RedisDB
from quart import (websocket, abort, redirect, url_for, render_template, flash, jsonify)
import asyncio
import jwt
from jwt import ExpiredSignatureError, InvalidTokenError
import json
from utils.WSRateLimiter import WSRateLimiter
from utils.Util import Util
import redis.asyncio as redis
from quart import request, jsonify, request, Response
from passlib.hash import bcrypt
from quart_auth import Unauthorized
from passlib.hash import bcrypt
import asyncio
import httpx
import ast
import secrets
from datetime import datetime, timedelta, timezone
from tzlocal import get_localzone
from probe_mcp.ollamaproxy.utils.EmailAlert import EmailAlert
from onetimesecret import OneTimeSecretCli
from probe_mcp.ollamaproxy.utils.EmailSenderHandler import EmailSenderHandler

# Session and Auth Redis DB init
cl_sess_db = RedisDB(hostname=os.environ.get('CLIENT_SESS_DB'), 
                                                    port=os.environ.get('CLIENT_SESS_DB_PORT'))
cl_auth_db = RedisDB(hostname=os.environ.get('CLIENT_AUTH_DB'), 
                                                    port=os.environ.get('CLIENT_AUTH_DB_PORT'))
cl_data_db = RedisDB(hostname=os.environ.get('CLIENT_DATA_DB'),
                                                    port=os.environ.get('CLIENT_DATA_DB_PORT'))
ip_ban_db = RedisDB(hostname=os.environ.get('IP_BAN_DB'), 
                    port=os.environ.get('IP_BAN_DB_PORT'))
# Websocket rate limit init
ws_rate_limiter = WSRateLimiter(redis_host=os.environ.get('RATE_LIMIT_DB'), 
                                redis_port=os.environ.get('RATE_LIMIT_DB_PORT'))

broker = Broker()
util_obj=Util()
api_name = 'umj-api-wflw'
auth_ping_counter = {}
mntr_url=os.environ.get('SERVER_NAME')
REQUIRED_OUT_OF_SCOPE_MSG = "Please provide a question or request related to network administration or the available MCP tools."
email_sender_handler = EmailSenderHandler(brevo_api_key=os.environ.get('BREVO_API_KEY'))
cli = OneTimeSecretCli(os.environ.get('OTS_USER'), os.environ.get('OTS_KEY'), os.environ.get('REGION'))
auth_attempts={}
max_auth_attempts=int(os.environ.get('MAX_AUTH_ATTEMPTS'))
connected_probes={}

# Helper functions to quantize datetimes to 5-minute increments
def round_down_to_5min(dt: datetime) -> datetime:
    """Round dt down (floor) to the nearest 5-minute boundary."""
    if dt is None:
        return dt
    minute = (dt.minute // 5) * 5
    return dt.replace(minute=minute, second=0, microsecond=0)

def round_up_to_5min(dt: datetime) -> datetime:
    """Round dt up (ceiling) to the next 5-minute boundary (if already on boundary, keep)."""
    if dt is None:
        return dt
    # If already exact boundary, return as-is (but zero seconds/microseconds)
    if dt.second == 0 and dt.microsecond == 0 and (dt.minute % 5) == 0:
        return dt.replace(second=0, microsecond=0)
    # Compute minutes to add to reach next multiple of 5
    remainder = dt.minute % 5
    add_minutes = 5 - remainder
    # Normalize to next boundary with seconds/microseconds cleared
    # Use a base truncated to the minute first
    base = dt.replace(second=0, microsecond=0)
    res = base + timedelta(minutes=add_minutes)
    return res.replace(second=0, microsecond=0)

# Helper functions to quantize datetimes to 30-second increments
def round_down_to_30sec(dt: datetime) -> datetime:
    """Round dt down (floor) to the nearest 30-second boundary."""
    if dt is None:
        return dt
    # Determine the 30-second bucket: 0-29 => 0, 30-59 => 30
    sec = (dt.second // 30) * 30
    return dt.replace(second=sec, microsecond=0)

def round_up_to_30sec(dt: datetime) -> datetime:
    """Round dt up (ceiling) to the next 30-second boundary (if already on boundary, keep)."""
    if dt is None:
        return dt
    # If already exact boundary, return as-is (but zero microseconds)
    if (dt.second % 30) == 0 and dt.microsecond == 0:
        return dt.replace(microsecond=0)
    remainder = dt.second % 30
    add_seconds = 30 - remainder
    base = dt.replace(microsecond=0)
    res = base + timedelta(seconds=add_seconds)
    return res.replace(microsecond=0)

async def ip_blocker(conn_obj: Request | Websocket, auto_ban: bool = False):
    if auto_ban is True:
        logger.info(f"Auto banning IP: {conn_obj.access_route[-1]}")
        await ip_ban_db.connect_db()
        now = datetime.now(tz=timezone.utc)
        ban_data = {'ip': conn_obj.access_route[-1],
                    'banned_at': now.isoformat()}
        if await ip_ban_db.upload_db_data(id=f"blocked_ip:{conn_obj.access_route[-1]}", data=ban_data) > 0:
            logger.warning(f"Max authentication attempts reached for {conn_obj.access_route[-1]}. Blocking further attempts.")
            auth_attempts.pop(conn_obj.access_route[-1], None) 

    if conn_obj.access_route[-1] not in auth_attempts:
        auth_attempts[conn_obj.access_route[-1]] = 1

    if auth_attempts[conn_obj.access_route[-1]] != max_auth_attempts:
        auth_attempts[conn_obj.access_route[-1]] += 1
        
    else:
        await ip_ban_db.connect_db()
        now = datetime.now(tz=timezone.utc)
        ban_data = {'ip': conn_obj.access_route[-1],
                    'banned_at': now.isoformat()}
        if await ip_ban_db.upload_db_data(id=f"blocked_ip:{conn_obj.access_route[-1]}", data=ban_data) > 0:
            logger.warning(f"Max authentication attempts reached for {conn_obj.access_route[-1]}. Blocking further attempts.")
            auth_attempts.pop(conn_obj.access_route[-1], None)

async def _receive() -> None:
    while True:
        message = await websocket.receive()
        logger.debug(message)
        message = json.loads(message)
        action=message['act']

        if action:
            match action:
                case 'llm':
                
                    usr_msg_data = {
                        "from": message["from"],
                        "msg": message["msg"],
                        "url": message["url"],
                    }

                    logger.info(usr_msg_data)

                    await cl_auth_db.connect_db()
                    await cl_data_db.connect_db()
                    
                    if await cl_auth_db.get_all_data(match=f'*uid:{message["usr"]}*', cnfrm=True) is True:

                        # NETWORK ADMIN PROMPT
                        INSTRUCTIONS = (
                            "You are a Network Admin assistant with knowledge of "
                            "network engineering, network administration, firewall configurations, and securing networks according to "
                            "NIST, PCI DSS, GDPR, HIPAA and SOC 2 compliance standards. "
                            "You have access to MCP servers with tools that execute common network administration functions. "
                            "Always use the provided tools when applicable.\n"
                            "IMPORTANT: Only answer questions that are related to the tools below or your network administration expertise. "
                            "If a user asks something unrelated to the provided tools or prompt, DO NOT answer the question. "
                            f"Instead, only reply with: '{REQUIRED_OUT_OF_SCOPE_MSG}.'. Do not give any other type of reply.\n"
                            "If you are asked about your architecture, provider, or model identity, only respond with: "
                            "'I am a proprietary language model trained and developed by Baugh Consulting & Lab L.L.C.'\n"
                        )
                        
                        SUMMARY_INSTRUCTIONS = (
                                "You are a Network Admin assistant with knowledge of "
                                "network engineering, network administration, firewall configurations, and securing networks according to"
                                "NIST, PCI DSS, GDPR, HIPAA and SOC 2 compliance standards."
                                "Your only task is to analyze the outputs of traceroutes, iperf speedtests, nmap network scans, SNMP statistics and network packet captures. You will use this analysis to troubleshoot network performance issues, diagnose network outages, identify anomalies within current and historical network data and provide suggestions for network performance improvements."
                            )
                        
                        probes = await cl_data_db.get_all_data(match=f"prb:{message['usr']}*")

                        logger.info(probes)

                        for k, v in probes.items():
                            if v['url'] in message['url']:
                                api = v['prb_api_key']
                                logger.info(api)

                        processing_msg_data = {
                            "from": "agent",
                            "msg": "Give me a minute, I'm thinking about your request. I'll get back to you in a few...",
                            "url": message["url"],
                            "usr_id": message['usr_id']
                        }

                        await broker.publish(message=json.dumps(processing_msg_data))

                        tool_request, analysis_request = await run_sync(lambda: util_obj.split_analysis(text=message['msg']))()

                        logger.info(f'Tool request: {tool_request}')

                        if analysis_request:
                            logger.info(f'Analysis request: {analysis_request}')

                        async with httpx.AsyncClient() as client:
                            payload = {
                                'model': os.environ.get('OLLAMA_MODEL'),
                                'tools':[
                                        {
                                            "type": "mcp",
                                            "server_label": "netadmin_mcp_server",
                                            "server_url": f"{message['url']}",
                                            "require_approval": "never",
                                        },
                                    ],
                                'usr_input':f"{tool_request}",
                                'instructions': INSTRUCTIONS,
                                'api_key': api,
                                'user': message['usr'],
                            }

                            headers = {'content-type': 'application/json'}
                            
                            tool_resp = await client.post(f"{os.environ.get('OLLAMA_PROXY_URL')}/multitools", json=payload, headers=headers, timeout=int(os.environ.get('REQUEST_TIMEOUT')))

                            # Extract agent response
                            logger.info(tool_resp)
                            logger.info(tool_resp.json())

                            tool_msg = tool_resp.json()  

                            logger.info(tool_msg['output_text'])

                            error_check = tool_msg['output_text']
                        
                            if error_check == REQUIRED_OUT_OF_SCOPE_MSG:
                                err_msg_data = {
                                    "from": "agent",
                                    "msg": REQUIRED_OUT_OF_SCOPE_MSG,
                                    "url": message["url"],
                                    "usr_id": message['usr_id']
                                }

                                await broker.publish(message=json.dumps(err_msg_data))
                            else:
                                output_message = ""
                                logger.info(f"Request result = {tool_msg['output_text']}\n")
                                logger.info(type(tool_msg['output_text']))

                                data = json.loads(tool_msg['output_text'])

                                for item in data:
                                    net_cmd_output = item['output'][1]
                                    logger.info(f"Net command output: {net_cmd_output}")
                                    decoded_output = net_cmd_output.encode('utf-8').decode('unicode_escape')
                                    lines = decoded_output.split('\n')

                                    for i, line in enumerate(lines):
                                        net_cmd_data = f'{line}\n'
                                        output_message+=net_cmd_data

                                if analysis_request:
                                    summary_msg = (
                                        f"{output_message}\n\n"
                                        f"{analysis_request}"
                                        )

                                    smmry_payload = {
                                        'model': os.environ.get('OLLAMA_MODEL'),
                                        'usr_input':f"{summary_msg}",
                                        'instructions': SUMMARY_INSTRUCTIONS,
                                        'url': message['url'],
                                        'api_key': api,
                                        'user': message['usr'],
                                    }

                                    smmry_resp = await client.post(f"{os.environ.get('OLLAMA_PROXY_URL')}/analysis", json=smmry_payload, headers=headers, timeout=int(os.environ.get('REQUEST_TIMEOUT')))

                                    logger.info(smmry_resp)
                                    logger.info(smmry_resp.json())

                                    summary_msg = smmry_resp.json()

                                    final_output = ""
                                    final_output+=f'{output_message}\n\n'
                                    final_output+=summary_msg['output_text']
                                    logger.info(final_output)
                                else:
                                    final_output = output_message
                                    
                                time_stamp = datetime.now(timezone.utc).isoformat()

                                chat_data_id = f"chat:{tool_msg['id']}{time_stamp}"

                                chat_data = {'id': chat_data_id,
                                            'usr_msg': message["msg"],
                                            'agent_msg': final_output,
                                            'timestamp': time_stamp
                                            }

                                if await cl_data_db.upload_db_data(id=chat_data_id, data=chat_data) > 0:
                                    logger.info(f"Chat data uploaded successfully with id: {chat_data_id}")
                                
                                agnt_msg_data = {
                                    "from": "agent",
                                    "msg": final_output,
                                    "url": message["url"],
                                    "usr_id": message['usr_id']
                                }
                        
                                await broker.publish(message=json.dumps(agnt_msg_data))
                            
                case 'ping':
                    logger.debug(f"Received ping message: {message}")

                    await cl_sess_db.connect_db()

                    if await cl_sess_db.get_all_data(match=f'{message["sess_id"]}', cnfrm=True) is False:
                        pass  # Session does not exist, ignore ping
                    
                    global auth_ping_counter
                    
                    # Check if we have an expiry entry for this session and validate it
                    now = datetime.now(tz=timezone.utc)

                    if message["sess_id"] in auth_ping_counter:
                        entry = auth_ping_counter.get(message["sess_id"])
                        exp = entry.get('exp')

                        # If the stored expiry is still in the future, refresh it (sliding window)
                        if exp and now <= exp:
                            new_exp = round_up_to_5min(now + timedelta(minutes=5))
                            entry['exp'] = new_exp
                            auth_ping_counter[message["sess_id"]] = entry

                            logger.debug(f"Refreshed ping expiry for session {message['sess_id']} to {new_exp}")

                    else:
                        pass

                case 'heart_beat':
                    logger.debug(f"Received probe {message['sess_id']} heartbeat: {message}")

                    global connected_probes

                    now = datetime.now(tz=timezone.utc)

                    if message["sess_id"] in connected_probes:
                        entry = connected_probes.get(message["sess_id"])
                        exp = entry.get('exp')

                        # If the stored expiry is still in the future, refresh it (sliding window)
                        if exp and now <= exp:
                            new_exp = round_up_to_30sec(now + timedelta(seconds=30))
                            entry['exp'] = new_exp
                            connected_probes[message["sess_id"]] = entry

                            logger.debug(f"Refreshed ping expiry for session {message['sess_id']} to {new_exp}")

                    else:
                        pass

                case "prb_act_rslt":
                    match message['act_rslt_type']:
                        case 'pcap_lcl':
                            data = message['act_rslt']  
                        case 'pcap_tux':
                            data = message['act_rslt']  

                case _:
                    pass
        else:
            pass

async def session_watchdog(sess_id: str, check_interval: float = 5.0):
    """
    Background monitor for a given session id. If auth_ping_counter shows expiry older than now,
    call logout endpoint and close the websocket.
    check_interval controls how often we poll the expiry (seconds).
    """
    logger.info(f"Starting session watchdog for {sess_id}")
    while True:
        try:
            USER = False
            PROBE = False

            if auth_ping_counter.get(sess_id):
                entry = auth_ping_counter.get(sess_id)
                USER = True

            if connected_probes.get(sess_id):
                entry = connected_probes.get(sess_id)
                PROBE = True

            now = datetime.now(tz=timezone.utc)
                
            if not entry:
                # No entry yet (client hasn't pinged). We still want to expire after specified time from connection start,
                # but the connection code initializes an entry at connect. So just sleep and continue.
                await asyncio.sleep(check_interval)
                continue

            exp = entry.get('exp')
            if exp is None:
                await asyncio.sleep(check_interval)
                continue

            # Quantize times to avoid small-drift expirations.
            if USER is True:
                now_quant = round_down_to_5min(now)
                exp_quant = round_up_to_5min(exp)

            if PROBE is True:
                now_quant = round_down_to_30sec(now)
                exp_quant = round_up_to_30sec(exp)

            logger.debug(f"Session {sess_id} now_quant={now_quant} exp_quant={exp_quant} (raw now={now} raw exp={exp})")

            # Expiration occurred
            if now_quant > exp_quant:
                logger.info(f"Session {sess_id} expired at {exp_quant} (now_quant={now_quant}), logging out and closing ws")

                if USER is True:
                    # Remove tracking
                    auth_ping_counter.pop(sess_id, None)

                    # Remove user session profile from sess redis db/automatically invalidates active JWT tokens   
                    cur_usr_id = sess_id
                    await cl_sess_db.connect_db()
                            
                    result = await cl_sess_db.del_obj(key=cur_usr_id)
                    logger.info(f"Session {sess_id} data removal result: {result}")

                    # Clear JWT cookie
                    resp = jsonify({"Session": "Logged out due to inactivity"})
                    resp.delete_cookie("access_token")
                    resp.delete_cookie("api_access_token")

                    logger.info(f"User session {sess_id} logged out due to inactivity")
                    return resp
                    
                if PROBE is True:
                    logger.info(f'Probe {sess_id} is either offline or a network outage has occurred.')
                    connected_probes.pop(sess_id)
                    probe_data = await cl_data_db.get_all_data(match=f"*{sess_id}*")
                    probe_data_dict = next(iter(probe_data.values()))

                    probe_outage_data = {'alert_type': 'outage',
                                            'site': probe_data_dict.get('site'),
                                            'name': probe_data_dict.get('name'),
                                            'url': probe_data_dict.get('url'),
                                            'timestamp': datetime.now(tz=timezone.utc)}

                    await broker.publish(message=json.dumps(probe_outage_data))
                    break

            else:
                # Not yet expired: sleep until the sooner of check_interval or time to expiry (based on quantized values)
                seconds_to_expiry = (exp_quant - now_quant).total_seconds()
                sleep_for = min(check_interval, max(seconds_to_expiry, 0))
                logger.debug(f"Session {sess_id} not yet expired (expires at {exp_quant}), sleeping for {sleep_for} seconds")
                await asyncio.sleep(sleep_for)
                    
        except asyncio.CancelledError:
            logger.info(f"Session watchdog for {sess_id} cancelled")
            break
                
        except Exception as e:
            logger.exception(f"Error in session_watchdog for {sess_id}: {e}")

@app.before_request
async def check_ip():
    await ip_ban_db.connect_db()

    if await ip_ban_db.get_all_data(match=f"blocked_ip:{request.access_route[-1]}", cnfrm=True) is True:
        abort(401)

@app.before_websocket
async def check_ip_ws():
    await ip_ban_db.connect_db()

    if await ip_ban_db.get_all_data(match=f"blocked_ip:{websocket.access_route[-1]}", cnfrm=True) is True:
        try:
            await websocket.accept()
            await websocket.close(3000)
        except RuntimeError:
            return None
        
    
@app.websocket("/ws")
@rate_exempt
async def ws():
    try:
        if websocket.cookies.get("access_token") is not None:
            logger.info(websocket.args)

            id = None
            user = None
            probe_conn = None
            probe_id = None
            recv_task = None
            monitor_task = None

            if websocket.args.get('id') is not None:
                id = websocket.args.get('id')
            
            if websocket.args.get('amp;unm') is not None:
                user = websocket.args.get('amp;unm')

            if websocket.args.get('prb') is not None:
                probe_conn = websocket.args.get('prb')

            if websocket.args.get('amp;prb_id') is not None:
                probe_id = websocket.args.get('amp;prb_id')

            jwt_token = websocket.cookies.get("access_token")
            logger.info(f"Received JWT: {jwt_token}")

            # Set rate limit check connection ID to the jwt used to initiate the connection
            client_connection = jwt_token

            # Rate limiter for websocket connections using user jwt tokens
            if await ws_rate_limiter.check_rate_limit(client_id=client_connection) is True:

                if isinstance(user, str) is False:
                    raise Exception()
                    
                await cl_auth_db.connect_db()
                await cl_sess_db.connect_db()

                if id is not None:

                    if await cl_auth_db.get_all_data(match=f'*uid:{user}*', cnfrm=True) and await cl_sess_db.get_all_data(match=f'{id}', cnfrm=True) is True:
                            
                        account_data = await cl_sess_db.get_all_data(match=f'*{id}*')
                        if account_data is None:
                            await ip_blocker(conn_obj=websocket)
                            raise Exception()
                          
                        else:
                            logger.info(account_data)
                            sub_dict = next(iter(account_data.values()))
                            logger.info(sub_dict)

                        jwt_key = sub_dict.get('usr_jwt_secret')
                        logger.info(jwt_key)
                        decoded_token = jwt.decode(jwt=jwt_token, key=jwt_key , algorithms=["HS256"])
                        logger.info(decoded_token)

                        if decoded_token.get('rand') != sub_dict.get('usr_rand'):
                            raise InvalidTokenError()

                if probe_conn is not None:

                    if await cl_auth_db.get_all_data(match=f'*uid:{user}*', cnfrm=True) and probe_conn.strip().lower() == 'y':
                        user_data = await cl_auth_db.get_all_data(match=f'uid:{user}')
                        user_data_dict = next(iter(user_data.values()))
                        user_data_dict.get('db_id')

                        api_data = await cl_data_db.get_all_data(match=f"api_dta:{user_data_dict.get('db_id')}")

                        if api_data is None:
                            await ip_blocker(conn_obj=websocket)
                            raise Exception()
                            
                        api_data_dict = next(iter(api_data.values()))
                        logger.info(api_data_dict)
                        
                        api_jwt_key = api_data_dict.get(f'{api_name}_jwt_secret')
                        api_rand = api_data_dict.get(f'{api_name}_rand')
                        decoded_token = jwt.decode(jwt=jwt_token, key=api_jwt_key, algorithms=["HS256"])

                        if decoded_token.get('rand') != api_rand:
                            raise InvalidTokenError()
                        
                logger.info('websocket authentication successful')
                await websocket.accept()

                if id and (id not in auth_ping_counter):
                    # Initialize a session expiry entry for this connection so that a missing ping
                    # during the first 5 minutes will still expire the session.
                    now = datetime.now(tz=timezone.utc)
                    auth_ping_counter[id] = {
                                "sess_id": id,
                                "exp": round_up_to_5min(now + timedelta(minutes=5, seconds=0, microseconds=0)), # First expiry 5 minutes from now, quantized down
                        }
                    logger.debug(f"Initialized ping expiry for session {id} -> {auth_ping_counter[id]['exp']}")
                    
                    recv_task = asyncio.ensure_future(_receive())

                    monitor_task = asyncio.create_task(session_watchdog(sess_id=id))

                if id and (id in auth_ping_counter):
                    recv_task = asyncio.ensure_future(_receive())

                    monitor_task = asyncio.create_task(session_watchdog(sess_id=id))

                if probe_id and (probe_id not in connected_probes):
                    now = datetime.now(tz=timezone.utc)
                    connected_probes[probe_id] = {'conn_start': now,
                                                  'id': probe_id,
                                                  "exp": round_up_to_30sec(now + timedelta(seconds=30)),
                                                  }
                    logger.debug(f"Initialized ping expiry for session {probe_id} -> {connected_probes[probe_id]['exp']}")

                    recv_task = asyncio.ensure_future(_receive())

                    monitor_task = asyncio.create_task(session_watchdog(sess_id=probe_id))

                if probe_id and (probe_id in connected_probes):
                    recv_task = asyncio.ensure_future(_receive())

                    monitor_task = asyncio.create_task(session_watchdog(sess_id=probe_id))

                try:
                    async for message in broker.subscribe():
                        await websocket.send(message)
                except asyncio.CancelledError:
                    # Connection was closed, exit loop to cleanup normally
                    logger.debug("Subscribe loop cancelled (client disconnected)")
                except Exception as e:
                    logger.exception("Error while reading from broker or sending websocket message")
                    raise
            else:
                raise Exception()
        else:
           await ip_blocker(conn_obj=websocket)
           raise Exception()
    except Exception as e:
        logger.error(e)
    except asyncio.CancelledError as e:
        if recv_task:
            recv_task.cancel()
            try:
                await recv_task
            except asyncio.CancelledError:
                pass
            except Exception:
                logger.exception("Error while awaiting monitor_task shutdown")
        
        if monitor_task:
            monitor_task.cancel()
            try:
                await monitor_task
            except asyncio.CancelledError:
                pass
            except Exception:
                logger.exception("Error while awaiting monitor_task shutdown")

        logger.error(e)
    except ExpiredSignatureError:
        logger.warning("JWT expired, need to refresh token")
        await ip_blocker(conn_obj=websocket)
        logger.error(ExpiredSignatureError)

        if recv_task:
            recv_task.cancel()
            try:
                await recv_task
            except asyncio.CancelledError:
                pass
            except Exception:
                logger.exception("Error while awaiting monitor_task shutdown")
        
        if monitor_task:
            monitor_task.cancel()
            try:
                await monitor_task
            except asyncio.CancelledError:
                pass
            except Exception:
                logger.exception("Error while awaiting monitor_task shutdown")
        
    except InvalidTokenError as e:
        logger.error(f"JWT invalid: {e}")
        await ip_blocker(conn_obj=websocket)
        logger.error(InvalidTokenError)

        if recv_task:
            recv_task.cancel()
            try:
                await recv_task
            except asyncio.CancelledError:
                pass
            except Exception:
                logger.exception("Error while awaiting monitor_task shutdown")
        
        if monitor_task:
            monitor_task.cancel()
            try:
                await monitor_task
            except asyncio.CancelledError:
                pass
            except Exception:
                logger.exception("Error while awaiting monitor_task shutdown")

@app.route('/init', methods=['GET'])
async def init():
    api_key = request.headers.get("X-UMJ-WFLW-API-KEY")
    usr = request.args.get('usr')

    try:

        if not api_key or not usr:
            await ip_blocker(conn_obj=request)
            abort(401)
                
        await cl_auth_db.connect_db()
        await cl_data_db.connect_db()
        await cl_sess_db.connect_db()

        if await cl_auth_db.get_all_data(match=f'*{usr}*', cnfrm=True) is False:
            await ip_blocker(conn_obj=request)
            abort(401)
        
        usr_data = await cl_auth_db.get_all_data(match=f'*uid:{usr}*')
        logger.info(usr_data)
        usr_data_dict = next(iter(usr_data.values()))
        logger.info(usr_data_dict)

        api_data = await cl_data_db.get_all_data(match=f"api_dta:{usr_data_dict.get('db_id')}")

        if api_data is None:
            return jsonify(error="Generate your umjiniti-core API key."), 404
            
        api_data_dict = next(iter(api_data.values()))
        logger.info(api_data_dict)
    
        if bcrypt.verify(api_key, api_data_dict.get(api_name)) is False:
            await ip_blocker(conn_obj=request)
            abort(401)
        
        api_jwt_key = api_data_dict.get(f'{api_name}_jwt_secret')
        api_rand = api_data_dict.get(f'{api_name}_rand')
        api_id = api_data_dict.get(f'{api_name}_id')
        
        # Generate JWT to authenticate probe sessions with monitor backend
        jwt_token = util_obj.generate_ephemeral_token(id=api_id, secret_key=api_jwt_key, rand=api_rand, type='prb')
            
        # Build response with cookie
        response = Response(response='Probe Token Success', status=200)
            
        response.set_cookie(
            key='access_token',
            value=jwt_token,
            httponly=True,
            secure=True,
            samesite="Strict",
            max_age=3600  # 1 hour, adjust as needed
        )
            
        return response
    except Exception():
        return jsonify({'error': 'Error occurred'}), 400
    
@app.route("/enroll", methods=['POST'])
async def enroll():
    logger.info(request.args)

    api_key = request.headers.get("X-UMJ-WFLW-API-KEY")
    usr = request.args.get('usr')
    site = request.args.get('site')
    jwt_token = request.cookies.get('access_token')

    if not api_key or not usr or not jwt_token:
        await ip_blocker(conn_obj=request)
        abort(401)
    
    if not site:
        site = 'default'
        
    await cl_auth_db.connect_db()
    await cl_data_db.connect_db()

    try:

        if await cl_auth_db.get_all_data(match=f'*uid:{usr}*', cnfrm=True) is False:
            await ip_blocker(conn_obj=request)
            abort(401)
        
        usr_data = await cl_auth_db.get_all_data(match=f'*uid:{usr}*')
        logger.info(usr_data)
        usr_data_dict = next(iter(usr_data.values()))
        logger.info(usr_data_dict)

        api_data = await cl_data_db.get_all_data(match=f"api_dta:{usr_data_dict.get('db_id')}")

        if api_data is None:
            await ip_blocker(conn_obj=request)
            abort(401)
            
        api_data_dict = next(iter(api_data.values()))
        logger.info(api_data_dict)

        jwt_key = api_data_dict.get(f'{api_name}_jwt_secret')
        logger.info(jwt_key)
        decoded_token = jwt.decode(jwt=jwt_token, key=jwt_key , algorithms=["HS256"])
        logger.info(decoded_token)

        if decoded_token.get('rand') != api_data_dict.get(f'{api_name}_rand') or bcrypt.verify(api_key,api_data_dict.get(api_name)) is False:
            raise InvalidTokenError()
                
        # Adopt new probe
        adopted_probe_data = await request.get_json()
        logger.info(adopted_probe_data)
        prb_db_id = f"prb:{usr}:{adopted_probe_data['prb_id']}"
        adopted_probe_data['db_id'] = prb_db_id
        logger.info(adopted_probe_data)

        if await cl_data_db.upload_db_data(id=prb_db_id, data=adopted_probe_data) > 0:
            return jsonify({'status':'probe adopted'})
        else:
            return jsonify({'status':'probe adoption failed'}), 400
        
    except ExpiredSignatureError:
        logger.warning("JWT expired, need to refresh token")
        await ip_blocker(conn_obj=request)
        abort(401)
    except InvalidTokenError as e:
        logger.error(f"JWT invalid: {e}")
        await ip_blocker(conn_obj=request)
        abort(401)
    except Exception as e:
        return jsonify({f'error occurred: {e}'})
    
@app.route('/delete', methods=['POST'])
async def delete():
    jwt_token = request.cookies.get("api_access_token")
    usr = request.args.get('usr')

    if not jwt_token or not usr:
        await ip_blocker(conn_obj=request)
        abort(401)
        
    await cl_auth_db.connect_db()
    await cl_data_db.connect_db()

    try:
        if await cl_auth_db.get_all_data(match=f'*uid:{usr}*', cnfrm=True) is False:
            await ip_blocker(conn_obj=request)
            abort(401)
        
        usr_data = await cl_auth_db.get_all_data(match=f'*uid:{usr}*')
        logger.info(usr_data)
        usr_data_dict = next(iter(usr_data.values()))
        logger.info(usr_data_dict)

        api_data = await cl_data_db.get_all_data(match=f"api_dta:{usr_data_dict.get('db_id')}")

        if api_data is None:
            await ip_blocker(conn_obj=request)
            abort(401)
            
        api_data_dict = next(iter(api_data.values()))
        logger.info(api_data_dict)

        jwt_key = api_data_dict.get(f'{api_name}_jwt_secret')
        logger.info(jwt_key)
        decoded_token = jwt.decode(jwt=jwt_token, key=jwt_key , algorithms=["HS256"])
        logger.info(decoded_token)

        if decoded_token.get('rand') != api_data_dict.get(f'{api_name}_rand'):
            raise InvalidTokenError()
            
        data = await request.get_json()
        logger.info(data)
        id = data['id']
        logger.info(id)

        result = await cl_data_db.del_obj(key=id)
        logger.info(result)

        if result is None:
            return jsonify('Probe deletion failed'), 400

        return jsonify('Probe deleted')

    except ExpiredSignatureError:
        logger.warning("JWT expired, need to refresh token")
        await ip_blocker(conn_obj=request)
        abort(401)
    except InvalidTokenError as e:
        logger.error(f"JWT invalid: {e}")
        await ip_blocker(conn_obj=request)
        abort(401)
    except Exception as e:
        return jsonify({f'error occurred: {e}'})
        
@app.route('/flowrun', methods=['POST'])
async def flowrun():
    jwt_token = request.cookies.get("api_access_token")
    usr = request.args.get('usr')

    if not jwt_token or not usr:
        await ip_blocker(conn_obj=request)
        return jsonify(error="Missing required request data"), 400
    
    await cl_auth_db.connect_db()
    await cl_data_db.connect_db() 

    try:
        if await cl_auth_db.get_all_data(match=f'*uid:{usr}*', cnfrm=True) is False:
            await ip_blocker(conn_obj=request)
            abort(401)
        
        usr_data = await cl_auth_db.get_all_data(match=f'*uid:{usr}*')
        logger.info(usr_data)
        usr_data_dict = next(iter(usr_data.values()))
        logger.info(usr_data_dict)

        api_data = await cl_data_db.get_all_data(match=f"api_dta:{usr_data_dict.get('db_id')}")

        if api_data is None:
            await ip_blocker(conn_obj=request)
            abort(401)
            
        api_data_dict = next(iter(api_data.values()))
        logger.info(api_data_dict)

        jwt_key = api_data_dict.get(f'{api_name}_jwt_secret')
        logger.info(jwt_key)
        decoded_token = jwt.decode(jwt=jwt_token, key=jwt_key , algorithms=["HS256"])
        logger.info(decoded_token)

        if decoded_token.get('rand') != api_data_dict.get(f'{api_name}_rand'):
            raise InvalidTokenError()

        data = await request.get_json()

        async with httpx.AsyncClient() as client:

            headers = {'content-type': 'application/json'}
                            
            run_resp = await client.post(f"{os.environ.get('OLLAMA_PROXY_URL')}/run", json=data, headers=headers, timeout=int(os.environ.get('REQUEST_TIMEOUT')))

            if run_resp.status_code == 200:
                run_data = await run_resp.json()
                return jsonify(run_data)
            else:
                return jsonify({'status':'error'}), 400

    except ExpiredSignatureError:
        logger.warning("JWT expired, need to refresh token")
        await ip_blocker(conn_obj=request)
        abort(401)
    except InvalidTokenError as e:
        logger.error(f"JWT invalid: {e}")
        await ip_blocker(conn_obj=request)
        abort(401)
    except Exception as e:
        return jsonify({f'error occurred: {e}'})
        
@app.route('/flowdelete', methods=['POST'])
async def flowdelete():
    jwt_token = request.cookies.get("api_access_token")
    usr = request.args.get('usr')

    if not jwt_token or not usr:
        await ip_blocker(conn_obj=request)
        abort(401)
    
    await cl_auth_db.connect_db()
    await cl_data_db.connect_db()

    try:
        if await cl_auth_db.get_all_data(match=f'*uid:{usr}*', cnfrm=True) is False:
            await ip_blocker(conn_obj=request)
            abort(401)
        
        usr_data = await cl_auth_db.get_all_data(match=f'*uid:{usr}*')
        logger.info(usr_data)
        usr_data_dict = next(iter(usr_data.values()))
        logger.info(usr_data_dict)

        api_data = await cl_data_db.get_all_data(match=f"api_dta:{usr_data_dict.get('db_id')}")

        if api_data is None:
            return jsonify(error="Resource not found"), 404
            
        api_data_dict = next(iter(api_data.values()))
        logger.info(api_data_dict)

        jwt_key = api_data_dict.get(f'{api_name}_jwt_secret')
        logger.info(jwt_key)
        decoded_token = jwt.decode(jwt=jwt_token, key=jwt_key , algorithms=["HS256"])
        logger.info(decoded_token)

        if decoded_token.get('rand') != api_data_dict.get(f'{api_name}_rand'):
            raise InvalidTokenError()
            
        data = await request.get_json()

        async with httpx.AsyncClient() as client:

            headers = {'content-type': 'application/json'}
                            
            del_resp = await client.post(f"{os.environ.get('OLLAMA_PROXY_URL')}/delete", json=data, headers=headers, timeout=int(os.environ.get('REQUEST_TIMEOUT')))

            if del_resp.status_code == 200:
                del_data = await del_resp.json()
                return jsonify(del_data)
            else:
                return jsonify({'status':'error'}), 400
            
    except ExpiredSignatureError:
        logger.warning("JWT expired, need to refresh token")
        await ip_blocker(conn_obj=request)
        abort(401)
    except InvalidTokenError as e:
        logger.error(f"JWT invalid: {e}")
        await ip_blocker(conn_obj=request)
        abort(401)
    except Exception as e:
        return jsonify({f'error occurred: {e}'})
        
@app.route('/flowsave', methods=['POST'])
async def flowsave():
    jwt_token = request.cookies.get("api_access_token")
    usr = request.args.get('usr')

    if not jwt_token or not usr:
        await ip_blocker(conn_obj=request)
        return jsonify(error="Missing required request data"), 400

    await cl_auth_db.connect_db()
    await cl_data_db.connect_db()

    try:

        if await cl_auth_db.get_all_data(match=f'*uid:{usr}*', cnfrm=True) is False:
            await ip_blocker(conn_obj=request)
            return Unauthorized()
        
        usr_data = await cl_auth_db.get_all_data(match=f'*uid:{usr}*')
        logger.info(usr_data)
        usr_data_dict = next(iter(usr_data.values()))
        logger.info(usr_data_dict)

        api_data = await cl_data_db.get_all_data(match=f"api_dta:{usr_data_dict.get('db_id')}")

        if api_data is None:
            return jsonify(error="Resource not found"), 404
            
        api_data_dict = next(iter(api_data.values()))
        logger.info(api_data_dict)

        jwt_key = api_data_dict.get(f'{api_name}_jwt_secret')
        logger.info(jwt_key)
        decoded_token = jwt.decode(jwt=jwt_token, key=jwt_key , algorithms=["HS256"])
        logger.info(decoded_token)

        if decoded_token.get('rand') != api_data_dict.get(f'{api_name}_rand'):
            await ip_blocker(conn_obj=request)
            return Unauthorized()

        data = await request.get_json()

        async with httpx.AsyncClient() as client:

            headers = {'content-type': 'application/json'}
                            
            save_resp = await client.post(f"{os.environ.get('OLLAMA_PROXY_URL')}/save", json=data, headers=headers, timeout=int(os.environ.get('REQUEST_TIMEOUT')))

            if save_resp.status_code == 200:
                save_data = await save_resp.json()
                return jsonify(save_data)
            else:
                return jsonify({'status':'error'}), 400
            
    except ExpiredSignatureError:
        logger.warning("JWT expired, need to refresh token")
        return ExpiredSignatureError()
    except InvalidTokenError as e:
        logger.error(f"JWT invalid: {e}")
        return InvalidTokenError()
        
@app.route('/flowload', methods=['POST'])
async def flowload():
    jwt_token = request.cookies.get("api_access_token")
    usr = request.args.get('usr')

    if not jwt_token or not usr:
        await ip_blocker(conn_obj=request)
        return jsonify(error="Missing required request data"), 400
    
    await cl_auth_db.connect_db()
    await cl_data_db.connect_db()

    try:
        if await cl_auth_db.get_all_data(match=f'*uid:{usr}*', cnfrm=True) is False:
            await ip_blocker(conn_obj=request)
            return Unauthorized()
        
        usr_data = await cl_auth_db.get_all_data(match=f'*uid:{usr}*')
        logger.info(usr_data)
        usr_data_dict = next(iter(usr_data.values()))
        logger.info(usr_data_dict)

        api_data = await cl_data_db.get_all_data(match=f"api_dta:{usr_data_dict.get('db_id')}")

        if api_data is None:
            return jsonify(error="Resource not found"), 404
            
        api_data_dict = next(iter(api_data.values()))
        logger.info(api_data_dict)

        jwt_key = api_data_dict.get(f'{api_name}_jwt_secret')
        logger.info(jwt_key)
        decoded_token = jwt.decode(jwt=jwt_token, key=jwt_key , algorithms=["HS256"])
        logger.info(decoded_token)

        if decoded_token.get('rand') != api_data_dict.get(f'{api_name}_rand'):
            await ip_blocker(conn_obj=request)
            return Unauthorized()
            
        data = await request.get_json()

        async with httpx.AsyncClient() as client:

            headers = {'content-type': 'application/json'}
                            
            load_resp = await client.post(f"{os.environ.get('OLLAMA_PROXY_URL')}/load", json=data, headers=headers, timeout=int(os.environ.get('REQUEST_TIMEOUT')))

            if load_resp.status_code == 200:
                load_data = await load_resp.json()
                #await load_resp.aclose()
                return jsonify(load_data)
            else:
                return jsonify({'status':'error'}), 400
            
    except ExpiredSignatureError:
        logger.warning("JWT expired, need to refresh token")
        return ExpiredSignatureError()
    except InvalidTokenError as e:
        logger.error(f"JWT invalid: {e}")
        return InvalidTokenError()
        
@app.route('/resetapi', methods=['POST'])
async def resetapi():
    jwt_token = request.cookies.get("access_token")
    sess_id = request.args.get('sess_id')

    if not jwt_token or not sess_id:
        await ip_blocker(conn_obj=request)
        return jsonify(error="Missing required request data"), 400
    
    await cl_sess_db.connect_db()
    await cl_data_db.connect_db()

    if await cl_sess_db.get_all_data(match=f'*{sess_id}*', cnfrm=True) is False:
        await ip_blocker(conn_obj=request)
        return Unauthorized()
    
    try:
        usr_sess_data = await cl_sess_db.get_all_data(match=f'*{sess_id}*')
        logger.info(usr_sess_data)
        usr_data_dict = next(iter(usr_sess_data.values()))
        logger.info(usr_data_dict)

        jwt_key = usr_data_dict.get(f'usr_jwt_secret')
        logger.info(jwt_key)
        decoded_token = jwt.decode(jwt=jwt_token, key=jwt_key , algorithms=["HS256"])
        logger.info(decoded_token)

        if decoded_token.get('rand') != usr_data_dict.get(f'usr_rand'):
            await ip_blocker(conn_obj=request)
            return Unauthorized()
        
        if await cl_data_db.del_obj(key=f"api_dta:{usr_data_dict['db_id']}") is not None:

            api_id = util_obj.key_gen(size=10) 

            new_api_key = util_obj.generate_api_key()

            updated_api_data = {api_name: bcrypt.hash(new_api_key),
                            f"{api_name}_id": api_id,
                            f"{api_name}_rand": secrets.token_urlsafe(500),
                            f"{api_name}_jwt_secret": secrets.token_urlsafe(500)
                        }
        else:
            return jsonify('API key reset failed'), 400
        
        if await cl_data_db.upload_db_data(id=f"api_dta:{usr_data_dict['db_id']}", data=updated_api_data) > 0:
            link = cli.create_link(secret=new_api_key, ttl=int(os.environ.get('OTS_TTL')))

            html_snippet = f"""<div style="font-family: Arial, sans-serif; color: #111; line-height: 1.5;">
                        <p>Hello,</p>
                        <p><strong>umjiniti</strong> API key for user <strong>{usr_data_dict.get('unm')}</strong> has been reset.</p>
                        <p>You can retrieve the API key using the following one-time secret link. Note that this link will expire after a single use.</p>
                        <p>API Key Retrieval Link: <a href="{link}">{link}</a></p>
                        <p>Thank you,<br/>umjiniti Team</p>

                        </div>"""
            send_result = await run_sync(lambda: email_sender_handler.send_transactional_email(sender={'name': 'umjiniti Admin', 'email': os.environ.get('BREVO_SENDER_EMAIL')},
                                                                                 to=[{"name": usr_data_dict.get('unm'), "email": usr_data_dict.get('eml')}],
                                                                                 subject=f"umjiniti-core API Key Reset for {usr_data_dict.get('unm')}",
                                                                                 html_content=html_snippet
                                                                                 ))()

            logger.info(f"API key reset email send result: {send_result}")
            return jsonify('API key reset successful. Check your email for the new API key.')
        else:
            return jsonify('API key reset failed'), 400
        
    except ExpiredSignatureError:
        logger.warning("JWT expired, need to refresh token")
        await ip_blocker(conn_obj=request)
        return ExpiredSignatureError()
    except InvalidTokenError as e:
        logger.error(f"JWT invalid: {e}")
        await ip_blocker(conn_obj=request)
        return InvalidTokenError()
    except Exception:
        return jsonify("Error, occurred"), 400
    
@app.route('/createapi', methods=['POST'])
async def createapi():
    jwt_token = request.cookies.get("access_token")
    sess_id = request.args.get('sess_id')

    logger.info(f"Create API JWT: {jwt_token}, SESS: {sess_id}")

    if not jwt_token or not sess_id:
        await ip_blocker(conn_obj=request)
        return jsonify(error="Missing required request data"), 400

    await cl_sess_db.connect_db()
    await cl_data_db.connect_db()

    if await cl_sess_db.get_all_data(match=f'*{sess_id}*', cnfrm=True) is False:
        await ip_blocker(conn_obj=request)
        return Unauthorized()

    try:
        usr_sess_data = await cl_sess_db.get_all_data(match=f'*{sess_id}*')
        logger.info(usr_sess_data)
        usr_data_dict = next(iter(usr_sess_data.values()))
        logger.info(usr_data_dict)

        jwt_key = usr_data_dict.get(f'usr_jwt_secret')
        logger.info(jwt_key)
        decoded_token = jwt.decode(jwt=jwt_token, key=jwt_key , algorithms=["HS256"])
        logger.info(decoded_token)

        if decoded_token.get('rand') != usr_data_dict.get(f'usr_rand'):
            await ip_blocker(conn_obj=request)
            return Unauthorized()

        api_id = util_obj.key_gen(size=10)
        new_api_key = util_obj.generate_api_key()
        
        updated_api_data = {api_name: bcrypt.hash(new_api_key),
                            f"{api_name}_id": api_id,
                            f"{api_name}_rand": secrets.token_urlsafe(500),
                            f"{api_name}_jwt_secret": secrets.token_urlsafe(500)
                        }
        
        logger.info(usr_data_dict['db_id'])

        if await cl_data_db.upload_db_data(id=f"api_dta:{usr_data_dict['db_id']}", data=updated_api_data) > 0:
            link = cli.create_link(secret=new_api_key, ttl=int(os.environ.get('OTS_TTL')))

            #check_contact = await run_sync(email_sender_handler.get_contact(user_id=usr_data_dict.get('db_id')))

            contact_data = {"LASTNAME": usr_data_dict.get('lname'),
                                "FIRSTNAME": usr_data_dict.get('fname'),
                                }
            new_contact_result = await run_sync(lambda: email_sender_handler.add_contact(email=usr_data_dict.get('eml'),
                                                                ext_id=usr_data_dict.get('db_id'), attributes=contact_data
                                                            ))()
            logger.info(f"New contact creation result: {new_contact_result}")
                
            html_snippet = f"""<div style="font-family: Arial, sans-serif; color: #111; line-height: 1.5;">
                        <p>Hello,</p>
                        <p>A new <strong>umjiniti</strong> API key has been generated for user <strong>{usr_data_dict.get('unm')}</strong>.</p>
                        <p>You can retrieve the API key using the following one-time secret link. Note that this link will expire after a single use.</p>
                        <p>API Key Retrieval Link: <a href="{link}">{link}</a></p>
                        <p>Thank you,<br/>umjiniti Team</p>

                        </div>"""
            send_result = await run_sync(lambda: email_sender_handler.send_transactional_email(sender={'name': 'umjiniti Admin', 'email': os.environ.get('BREVO_SENDER_EMAIL')},
                                                                                 to=[{"name": usr_data_dict.get('unm'), "email": usr_data_dict.get('eml')}],
                                                                                 subject=f"New umjiniti-core API Key Generated for {usr_data_dict.get('unm')}",
                                                                                 html_content=html_snippet
                                                                                 ))()
           
            logger.info(f"API key creation email send result: {send_result}")
            return jsonify('API key creation successful. Check your email for the new API key.'), 200       
        else:
            return jsonify('API key creation failed'), 400

    except ExpiredSignatureError:
        logger.warning("JWT expired, need to refresh token")
        await ip_blocker(conn_obj=request)
        return ExpiredSignatureError()
    except InvalidTokenError as e:
        logger.error(f"JWT invalid: {e}")
        await ip_blocker(conn_obj=request)
        return InvalidTokenError()
    except Exception:
        return jsonify("Error, occurred"), 400
    
@app.errorhandler(Unauthorized)
async def unauthorized():
    await ip_blocker(conn_obj=request)
    return await render_template_string(json.dumps({"error": "Authentication error"})), 401

@app.errorhandler(ExpiredSignatureError)
async def token_expired():
    await ip_blocker(conn_obj=request)
    return await render_template_string(json.dumps({"error": "Token expired"})), 1008

@app.errorhandler(InvalidTokenError)
async def invalid_token():
    await ip_blocker(conn_obj=request)
    return await render_template_string(json.dumps({"error": "Invalid token"})), 1000

@app.errorhandler(400)
async def bad_request():
    await ip_blocker(conn_obj=request)
    return await render_template_string(json.dumps({"error": "Bad Request"})), 400

@app.errorhandler(401)
async def need_to_login():
    await ip_blocker(conn_obj=request)
    return await render_template_string(json.dumps({"error": "Authentication error"})), 401
    
@app.errorhandler(404)
async def page_not_found():
    await ip_blocker(conn_obj=request)
    return await render_template_string(json.dumps({"error": "Resource not found"})), 404

@app.errorhandler(500)
async def handle_internal_error(e):
    return await render_template_string(json.dumps({"error": "Internal server error"})), 500