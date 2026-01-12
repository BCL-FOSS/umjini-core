from init_app import (app)
from quart import (websocket, render_template_string, make_response)
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

async def ip_blocker(auto_ban: bool = False):
    if auto_ban is True:
        logger.info(f"Auto banning IP: {request.access_route[-1]}")
        await ip_ban_db.connect_db()
        now = datetime.now(tz=timezone.utc)
        ban_data = {'ip': request.access_route[-1],
                    'banned_at': now.isoformat()}
        if await ip_ban_db.upload_db_data(id=f"blocked_ip:{request.access_route[-1]}", data=ban_data) > 0:
            logger.warning(f"Max authentication attempts reached for {request.access_route[-1]}. Blocking further attempts.")
            auth_attempts.pop(request.access_route[-1], None)
            #abort(403) 

    if request.access_route[-1] not in auth_attempts:
        auth_attempts[request.access_route[-1]] = 1

    if auth_attempts[request.access_route[-1]] != max_auth_attempts:
        auth_attempts[request.access_route[-1]] += 1
        await flash(message=f'Try again...', category='danger')
        return jsonify(error="Unauthorized"), 401
    else:
        await ip_ban_db.connect_db()
        now = datetime.now(tz=timezone.utc)
        ban_data = {'ip': request.access_route[-1],
                    'banned_at': now.isoformat()}
        if await ip_ban_db.upload_db_data(id=f"blocked_ip:{request.access_route[-1]}", data=ban_data) > 0:
            logger.warning(f"Max authentication attempts reached for {request.access_route[-1]}. Blocking further attempts.")
            auth_attempts.pop(request.access_route[-1], None)
            #abort(403) 

async def _receive() -> None:
    while True:
        message = await websocket.receive()
        logger.debug(message)
        message = json.loads(message)
        action=message['act']

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
                            "Your only task is to summarize the outputs of traceroutes, iperf speedtests, nmap host discovery scans, SNMP polling and Ansible playbooks."
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

                    async with httpx.AsyncClient() as client:
                        payload = {
                            'model':"qwen3:1.7b",
                            'tools':[
                                    {
                                        "type": "mcp",
                                        "server_label": "netadmin_mcp_server",
                                        "server_url": f"{message['url']}",
                                        "require_approval": "never",
                                    },
                                ],
                            'usr_input':f"{message['msg']}",
                            'instructions': INSTRUCTIONS,
                            'api_key': api,
                            'user': message['usr'],
                        }

                        headers = {'content-type': 'application/json'}
                        
                        tool_resp = await client.post(f"{os.environ.get('OLLAMA_PROXY_URL')}/tools", json=payload, headers=headers, timeout=int(os.environ.get('REQUEST_TIMEOUT')))

                        # Extract agent response
                        logger.info(tool_resp)
                        logger.info(await tool_resp.json())
                        #logger.info(resp.output[0].content[0].text)

                        tool_msg = await tool_resp.json()  

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
                            if 'traceroute' in message['msg'].lower():
                                lst = ast.literal_eval(tool_msg['output_text'])

                                # Extract the traceroute output (element at index 1)
                                traceroute_output = lst[1]

                                # Convert escaped newlines to real newlines
                                decoded_output = traceroute_output.encode('utf-8').decode('unicode_escape')

                                # Split into lines (each line as a string, with '\n' at the end if you want)
                                lines = decoded_output.split('\n')

                                # Print each line (as string variables)
                                for i, line in enumerate(lines):
                                    #var_name = f"line_{i+1}"
                                    hop = f'{line}\n'
                                    #logger.info(hop)
                                    output_message+=hop
                                
                                #logger.info(output_message)

                            smmry_payload = {
                                'model':"qwen3:1.7b",
                                'usr_input':f"{output_message}",
                                'instructions': SUMMARY_INSTRUCTIONS,
                                'url': message['url'],
                                'api_key': api,
                                'user': message['usr'],
                            }

                            smmry_resp = await client.post(f"{os.environ.get('OLLAMA_PROXY_URL')}/summary", json=smmry_payload, headers=headers, timeout=int(os.environ.get('REQUEST_TIMEOUT')))

                            logger.info(smmry_resp)
                            logger.info(await smmry_resp.json())

                            summary_msg = await smmry_resp.json()

                            final_output = ""
                            final_output+=f'{output_message}\n\n'
                            final_output+=summary_msg['output_text']
                            logger.info(final_output)

                            agnt_msg_data = {
                                "from": "agent",
                                "msg": final_output,
                                "url": message["url"],
                                "usr_id": message['usr_id']
                            }
                    
                            await broker.publish(message=json.dumps(agnt_msg_data))
                            #await tool_resp.aclose()
                            #await smmry_resp.aclose()
            case 'ping':
                logger.debug(f"Received ping message: {message}")

                await cl_sess_db.connect_db()

                if await cl_sess_db.get_all_data(match=f'{message["sess_id"]}', cnfrm=True) is False:
                    return Unauthorized()  # Session does not exist, ignore ping
                
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
                        logger.info(f"Ping for session {message['sess_id']} received after expiry; dropping and removing entry")

                        # Session expired: remove tracking and notify if needed
                        auth_ping_counter.pop(message["sess_id"])

                        # Remove user session profile from sess redis db/automatically invalidates active JWT tokens
                        #auth_id = request.args.get('auth_id')
                        cur_usr_id = message["sess_id"]

                        await cl_sess_db.connect_db()
                        if await cl_sess_db.get_all_data(match=f'{cur_usr_id}', cnfrm=True) is False:
                            return Unauthorized()
                        
                        result = await cl_sess_db.del_obj(key=cur_usr_id)
                        logger.info(f"Session {message["sess_id"]} data removal result: {result}")

                        # Clear JWT cookie
                        resp = jsonify({"Session": "Logged out due to inactivity"})
                        resp.delete_cookie("access_token")
                        resp.delete_cookie("api_access_token")

                        # quart-auth sign out
                        #client_auth.logout_user()
                        logger.info(f"User session {message["sess_id"]} logged out due to inactivity")
                        return resp
                else:
                    # No entry existed — create a new one and respond with a 5 minute expiry
                    now = datetime.now(tz=timezone.utc)

                    pong_msg_data = {
                        "sess_id": message["sess_id"],
                        "exp": round_up_to_5min(now + timedelta(minutes=5)),
                    }

                    auth_ping_counter[message["sess_id"]] = pong_msg_data
                    logger.debug(f"Created ping expiry for new session {message['sess_id']} -> {pong_msg_data['exp']}")
           
            case _:
                pass

async def session_watchdog(sess_id: str, check_interval: float = 5.0):
    """
    Background monitor for a given session id. If auth_ping_counter shows expiry older than now,
    call logout endpoint and close the websocket.
    check_interval controls how often we poll the expiry (seconds).
    """
    logger.info(f"Starting session watchdog for {sess_id}")
    try:
        while True:
            entry = auth_ping_counter.get(sess_id)
            now = datetime.now(tz=timezone.utc)
            
            if not entry:
                # No entry yet (client hasn't pinged). We still want to expire after 5 minutes from connection start,
                # but the connection code initializes an entry at connect. So just sleep and continue.
                await asyncio.sleep(check_interval)
                continue

            exp = entry.get('exp')
            if exp is None:
                await asyncio.sleep(check_interval)
                continue

            # Quantize times to 5-minute increments to avoid small-drift expirations.
            now_quant = round_down_to_5min(now)
            exp_quant = round_up_to_5min(exp)

            logger.debug(f"Session {sess_id} now_quant={now_quant} exp_quant={exp_quant} (raw now={now} raw exp={exp})")

            # If expired, perform logout and close websocket
            if now_quant > exp_quant:
                logger.info(f"Session {sess_id} expired at {exp_quant} (now_quant={now_quant}), logging out and closing ws")
                # Remove tracking
                auth_ping_counter.pop(sess_id, None)

                # Remove user session profile from sess redis db/automatically invalidates active JWT tokens
                #auth_id = request.args.get('auth_id')
                cur_usr_id = sess_id

                await cl_sess_db.connect_db()
                if await cl_sess_db.get_all_data(match=f'{cur_usr_id}', cnfrm=True) is False:
                    await ip_blocker(auto_ban=True)
                    return Unauthorized()
                
                result = await cl_sess_db.del_obj(key=cur_usr_id)
                logger.info(f"Session {sess_id} data removal result: {result}")

                # Clear JWT cookie
                resp = jsonify({"Session": "Logged out due to inactivity"})
                resp.delete_cookie("access_token")
                resp.delete_cookie("api_access_token")

                # quart-auth sign out
                #client_auth.logout_user()
                logger.info(f"User session {sess_id} logged out due to inactivity")
                return resp

            else:
                # Not yet expired: sleep until the sooner of check_interval or time to expiry (based on quantized values)
                seconds_to_expiry = (exp_quant - now_quant).total_seconds()
                sleep_for = min(check_interval, max(seconds_to_expiry, 0))
                logger.debug(f"Session {sess_id} not yet expired (expires at {exp_quant}), sleeping for {sleep_for} seconds")
                await asyncio.sleep(sleep_for)
                """
                # Not yet expired: sleep until the sooner of check_interval or time to expiry
                seconds_to_expiry = (exp - now).total_seconds()
                sleep_for = min(check_interval, max(seconds_to_expiry, 0))
                logger.debug(f"Session {sess_id} not yet expired (expires at {exp}), sleeping for {sleep_for} seconds")
                await asyncio.sleep(sleep_for)
                """
                
    except asyncio.CancelledError:
        logger.info(f"Session watchdog for {sess_id} cancelled")
        # Remove tracking
        auth_ping_counter.pop(sess_id, None)

        # Remove user session profile from sess redis db/automatically invalidates active JWT tokens
        #auth_id = request.args.get('auth_id')
        cur_usr_id = sess_id

        await cl_sess_db.connect_db()
        if await cl_sess_db.get_all_data(match=f'{cur_usr_id}', cnfrm=True) is False:
            return Unauthorized()
                
        result = await cl_sess_db.del_obj(key=cur_usr_id)
        logger.info(f"Session {sess_id} data removal result: {result}")

        # Clear JWT cookie
        resp = jsonify({"Session": "Logged out as user ended session"})
        resp.delete_cookie("access_token")
        resp.delete_cookie("api_access_token")

        logger.info(f"User session {sess_id} logged out due to session end")
        return resp
    except Exception as e:
        logger.exception(f"Unhandled error in session_watchdog for {sess_id}: {e}")

@app.before_request
async def check_ip():
    await ip_ban_db.connect_db()

    if await ip_ban_db.get_all_data(match=f"blocked_ip:{request.access_route[-1]}", cnfrm=True) is True:
        abort(403)
    
@app.websocket("/ws")
@rate_exempt
async def ws():
    try:
        if websocket.args is not None or "".strip():
            logger.info(websocket.args)
            for key, value in websocket.args.items():
                match key:
                    case 'id':
                        id = value
                    case 'amp;unm':
                        user = value

            jwt_token = websocket.cookies.get("access_token")
            logger.info(f"Received JWT: {jwt_token}")
            logger.info(id)

            # Set rate limit check connection ID to the jwt used to initiate the connection
            client_connection = jwt_token

            # Rate limiter for websocket connections using user jwt tokens
            if await ws_rate_limiter.check_rate_limit(client_id=client_connection) is True:

                if not user or not id:
                    await ip_blocker(auto_ban=True)
                    await websocket.accept()    
                    await websocket.close(1010, 'Missing required args...')
                    
                await cl_auth_db.connect_db()
                await cl_sess_db.connect_db()

                if await cl_auth_db.get_all_data(match=f'*uid:{user}*', cnfrm=True) and await cl_sess_db.get_all_data(match=f'{id}', cnfrm=True) is True:
                        
                    account_data = await cl_sess_db.get_all_data(match=f'*{id}*')
                    if account_data is None:
                        await websocket.accept()
                        await websocket.close(1000)
                    else:
                        logger.info(account_data)
                        sub_dict = next(iter(account_data.values()))
                        logger.info(sub_dict)

                jwt_key = sub_dict.get('usr_jwt_secret')
                logger.info(jwt_key)
                decoded_token = jwt.decode(jwt=jwt_token, key=jwt_key , algorithms=["HS256"])
                logger.info(decoded_token)

                if decoded_token.get('rand') != sub_dict.get('usr_rand'):
                    await ip_blocker(auto_ban=True)
                    await websocket.accept()
                    await websocket.close(1010, 'websocket authentication failed')
                        
                logger.info('websocket authentication successful')

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

                async for message in broker.subscribe():
                    await websocket.send(message)
            else:
                await websocket.accept()
                await websocket.close(1010, "Stream rate limit exceeded...")
        else:
           await ip_blocker(auto_ban=True)
           await websocket.accept()
           await websocket.close(1010, "Missing required args...")
    except Exception as e:
        if recv_task and monitor_task:
            recv_task.cancel()
            monitor_task.cancel()
            await recv_task
            await monitor_task
        await websocket.accept()
        await websocket.close(1000)
        raise e
    except asyncio.CancelledError:
        if recv_task and monitor_task:
            recv_task.cancel()
            monitor_task.cancel()
            await recv_task
            await monitor_task
        await websocket.accept()
        await websocket.close(1000)
        raise Exception(asyncio.CancelledError)
    except ExpiredSignatureError:
        if recv_task and monitor_task:
            recv_task.cancel()
            monitor_task.cancel()
            await recv_task
            await monitor_task
        logger.warning("JWT expired, need to refresh token")
        await ip_blocker()
        await websocket.accept()
        await websocket.close(1008, 'Token expired')
    except InvalidTokenError as e:
        if recv_task and monitor_task:
            recv_task.cancel()
            monitor_task.cancel()
            await recv_task
            await monitor_task
        logger.error(f"JWT invalid: {e}")
        await ip_blocker(auto_ban=True)
        await websocket.accept()
        await websocket.close(1000, 'Invalid token')
    finally:
        if recv_task and monitor_task:
            recv_task.cancel()
            monitor_task.cancel()
            await recv_task
            await monitor_task
        await websocket.accept()
        await websocket.close(1000)

@app.route('/init', methods=['GET'])
async def init():
    api_key = request.headers.get("X-UMJ-WFLW-API-KEY")
    usr = request.args.get('usr')

    if not api_key or not usr:
        await ip_blocker(auto_ban=True)
        return jsonify(error="Missing required request data"), 400
             
    await cl_auth_db.connect_db()
    await cl_data_db.connect_db()

    if await cl_auth_db.get_all_data(match=f'*{usr}*', cnfrm=True) is False:
        await ip_blocker(auto_ban=True)
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
 
    if bcrypt.verify(api_key, api_data_dict.get(api_name)) is False:
        await ip_blocker()
        return Unauthorized()
    
    api_jwt_key = api_data_dict.get(f'{api_name}_jwt_secret')
    api_rand = api_data_dict.get(f'{api_name}_rand')
    api_id = api_data_dict.get(f'{api_name}_id')
       
    # Generate JWT to authenticate probe sessions with monitor backend
    jwt_token = util_obj.generate_ephemeral_token(id=api_id, secret_key=api_jwt_key, rand=api_rand, expire=1)
        
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
    
@app.route("/enroll", methods=['POST'])
async def enroll():
    api_key = request.headers.get("X-UMJ-WFLW-API-KEY")
    usr = request.args.get('usr')
    site = request.args.get('site')

    if not api_key or not usr:
        await ip_blocker(auto_ban=True)
        return jsonify(error="Missing required request data"), 400
    
    if not site:
        site = 'default'

    jwt_token = request.cookies.get('access_token')
        
    await cl_auth_db.connect_db()
    await cl_data_db.connect_db()

    if await cl_auth_db.get_all_data(match=f'*uid:{usr}*', cnfrm=True) is False:
        await ip_blocker()
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

    if decoded_token.get('rand') != api_data_dict.get(f'{api_name}_rand') or bcrypt.verify(api_key,api_data_dict.get(api_name)) is False:
        await ip_blocker()
        return Unauthorized()
            
    # Adopt new probe
    adopted_probe_data = await request.get_json()
    logger.info(adopted_probe_data)
    prb_db_id = f"prb:{site}:{adopted_probe_data['prb_id']}"
    adopted_probe_data['db_id'] = prb_db_id
    logger.info(adopted_probe_data)

    if await cl_data_db.upload_db_data(id=prb_db_id, data=adopted_probe_data) > 0:
        return jsonify({'status':'probe adopted'})
    else:
        return jsonify({'status':'probe adoption failed'}), 400
    
@app.route('/delete', methods=['POST'])
async def delete():
    jwt_token = request.cookies.get("api_access_token")
    usr = request.args.get('usr')

    if not jwt_token or not usr:
        await ip_blocker(auto_ban=True)
        return jsonify(error="Missing required request data"), 400
        
    await cl_auth_db.connect_db()
    await cl_data_db.connect_db()

    try:
        if await cl_auth_db.get_all_data(match=f'*uid:{usr}*', cnfrm=True) is False:
            await ip_blocker(auto_ban=True)
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
            await ip_blocker(auto_ban=True)
            return Unauthorized()
            
        data = await request.get_json()
        logger.info(data)
        id = data.get('id')
        logger.info(id)

        result = await cl_data_db.del_obj(key=id)
        logger.info(result)

        if result is None:
            return jsonify('Probe deletion failed'), 400

        return jsonify('Probe deleted')

    except ExpiredSignatureError:
        logger.warning("JWT expired, need to refresh token")
        return ExpiredSignatureError()
    except InvalidTokenError as e:
        logger.error(f"JWT invalid: {e}")
        return InvalidTokenError()
        
@app.route('/flowrun', methods=['POST'])
async def flowrun():
    jwt_token = request.cookies.get("api_access_token")
    usr = request.args.get('usr')

    if not jwt_token or not usr:
        await ip_blocker(auto_ban=True)
        return jsonify(error="Missing required request data"), 400
    
    await cl_auth_db.connect_db()
    await cl_data_db.connect_db() 

    try:
        if await cl_auth_db.get_all_data(match=f'*uid:{usr}*', cnfrm=True) is False:
            await ip_blocker(auto_ban=True)
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
            await ip_blocker(auto_ban=True)
            return Unauthorized()

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
        return ExpiredSignatureError()
    except InvalidTokenError as e:
        logger.error(f"JWT invalid: {e}")
        return InvalidTokenError()
        
@app.route('/flowdelete', methods=['POST'])
async def flowdelete():
    jwt_token = request.cookies.get("api_access_token")
    usr = request.args.get('usr')

    if not jwt_token or not usr:
        await ip_blocker(auto_ban=True)
        return jsonify(error="Missing required request data"), 400
    
    await cl_auth_db.connect_db()
    await cl_data_db.connect_db()

    try:
        if await cl_auth_db.get_all_data(match=f'*uid:{usr}*', cnfrm=True) is False:
            await ip_blocker(auto_ban=True)
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
            await ip_blocker(auto_ban=True)
            return Unauthorized()
            
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
        return ExpiredSignatureError()
    except InvalidTokenError as e:
        logger.error(f"JWT invalid: {e}")
        return InvalidTokenError()
        
@app.route('/flowsave', methods=['POST'])
async def flowsave():
    jwt_token = request.cookies.get("api_access_token")
    usr = request.args.get('usr')

    if not jwt_token or not usr:
        await ip_blocker(auto_ban=True)
        return jsonify(error="Missing required request data"), 400

    await cl_auth_db.connect_db()
    await cl_data_db.connect_db()

    try:

        if await cl_auth_db.get_all_data(match=f'*uid:{usr}*', cnfrm=True) is False:
            await ip_blocker(auto_ban=True)
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
            await ip_blocker(auto_ban=True)
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
        await ip_blocker(auto_ban=True)
        return jsonify(error="Missing required request data"), 400
    
    await cl_auth_db.connect_db()
    await cl_data_db.connect_db()

    try:
        if await cl_auth_db.get_all_data(match=f'*uid:{usr}*', cnfrm=True) is False:
            await ip_blocker(auto_ban=True)
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
            await ip_blocker(auto_ban=True)
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
        await ip_blocker(auto_ban=True)
        return jsonify(error="Missing required request data"), 400
    
    await cl_sess_db.connect_db()
    await cl_data_db.connect_db()

    if await cl_sess_db.get_all_data(match=f'*{sess_id}*', cnfrm=True) is False:
        await ip_blocker(auto_ban=True)
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
            await ip_blocker(auto_ban=True)
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
            send_result = await run_sync(email_sender_handler.send_transactional_email(sender={'name': 'umjiniti Admin', 'email': os.environ.get('BREVO_SENDER_EMAIL')},
                                                                                 to=[{"name": usr_data_dict.get('unm'), "email": usr_data_dict.get('eml')}],
                                                                                 subject=f"umjiniti-core API Key Reset for {usr_data_dict.get('unm')}",
                                                                                 html_content=html_snippet
                                                                                 ))()
                
            if send_result is None:
                logger.error("Failed to send API key reset email")
                return jsonify('API key reset failed'), 400

            logger.info(f"API key reset email send result: {send_result}")
            return jsonify('API key reset successful. Check your email for the new API key.')
        else:
            return jsonify('API key reset failed'), 400
        
    except ExpiredSignatureError:
        logger.warning("JWT expired, need to refresh token")
        return ExpiredSignatureError()
    except InvalidTokenError as e:
        logger.error(f"JWT invalid: {e}")
        return InvalidTokenError()
    
@app.route('/createapi', methods=['POST'])
async def createapi():
    jwt_token = request.cookies.get("access_token")
    sess_id = request.args.get('sess_id')

    if not jwt_token or not sess_id:
        await ip_blocker(auto_ban=True)
        return jsonify(error="Missing required request data"), 400

    await cl_sess_db.connect_db()
    await cl_data_db.connect_db()

    if await cl_sess_db.get_all_data(match=f'*{sess_id}*', cnfrm=True) is False:
        await ip_blocker(auto_ban=True)
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
            await ip_blocker(auto_ban=True)
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
            new_contact_result = await run_sync(email_sender_handler.add_contact(email=usr_data_dict.get('eml'),
                                                                ext_id=usr_data_dict.get('db_id'), attributes=contact_data
                                                            ))()
            logger.info(f"Brevo contact creation result: {new_contact_result}")

            if new_contact_result is None:
                logger.error("Failed to create new contact for API key creation email")
                return jsonify('Brevo contact creation failed'), 400
                
            html_snippet = f"""<div style="font-family: Arial, sans-serif; color: #111; line-height: 1.5;">
                        <p>Hello,</p>
                        <p>A new <strong>umjiniti</strong> API key has been generated for user <strong>{usr_data_dict.get('unm')}</strong>.</p>
                        <p>You can retrieve the API key using the following one-time secret link. Note that this link will expire after a single use.</p>
                        <p>API Key Retrieval Link: <a href="{link}">{link}</a></p>
                        <p>Thank you,<br/>umjiniti Team</p>

                        </div>"""
            send_result = await run_sync(email_sender_handler.send_transactional_email(sender={'name': 'umjiniti Admin', 'email': os.environ.get('BREVO_SENDER_EMAIL')},
                                                                                 to=[{"name": usr_data_dict.get('unm'), "email": usr_data_dict.get('eml')}],
                                                                                 subject=f"New umjiniti-core API Key Generated for {usr_data_dict.get('unm')}",
                                                                                 html_content=html_snippet
                                                                                 ))()
                
            if send_result is None:
                logger.error("Failed to send API key creation email")
                return jsonify('API key creation failed'), 400

            logger.info(f"API key creation email send result: {send_result}")
            return jsonify('API key creation successful. Check your email for the new API key.')
                    
        else:
            return jsonify('API key creation failed'), 400

    except ExpiredSignatureError:
        logger.warning("JWT expired, need to refresh token")
        return ExpiredSignatureError()
    except InvalidTokenError as e:
        logger.error(f"JWT invalid: {e}")
        return InvalidTokenError()
    
@app.errorhandler(ExpiredSignatureError)
async def token_expired():
    return await render_template_string(json.dumps({"error": "Token expired"})), 1008

@app.errorhandler(InvalidTokenError)
async def invalid_token():
    return await render_template_string(json.dumps({"error": "Invalid token"})), 1000

@app.errorhandler(400)
async def bad_request():
    return await render_template_string(json.dumps({"error": "Bad Request"})), 400

@app.errorhandler(401)
async def need_to_login():
    return await render_template_string(json.dumps({"error": "Authentication error"})), 401
    
@app.errorhandler(404)
async def page_not_found():
    return await render_template_string(json.dumps({"error": "Resource not found"})), 404

@app.errorhandler(500)
async def handle_internal_error(e):
    return await render_template_string(json.dumps({"error": "Internal server error"})), 500