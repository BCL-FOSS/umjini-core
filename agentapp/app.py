from init_app import (app, client_auth, current_admin, current_client, logger,
                      Client
                      )
from forms.LoginForm import LoginForm
from forms.RegisterForm import RegisterForm
from forms.AlertJiraForm import AlertJiraForm
from forms.AlertSlackForm import AlertSlackForm
from quart import (render_template_string, render_template, flash, redirect, url_for, session, request, abort)
from quart_wtf.csrf import CSRFError
from quart_auth import (
    Action
)
from quart_auth import Unauthorized
from functools import wraps
from utils.Util import Util
from utils.RedisDB import RedisDB
import json
import os
from passlib.hash import bcrypt
import secrets
import jwt
from datetime import datetime, timezone

util_obj = Util()
url_key = util_obj.key_gen(size=100)
url_cmp_id = util_obj.key_gen(size=100)

# Redis DB initialization
cl_auth_db = RedisDB(hostname=os.environ.get('CLIENT_AUTH_DB'), 
                     port=os.environ.get('CLIENT_AUTH_DB_PORT'))
cl_sess_db = RedisDB(hostname=os.environ.get('CLIENT_SESS_DB'), 
                     port=os.environ.get('CLIENT_SESS_DB_PORT'))
cl_data_db = RedisDB(hostname=os.environ.get('CLIENT_DATA_DB'), 
                     port=os.environ.get('CLIENT_DATA_DB_PORT'))
ip_ban_db = RedisDB(hostname=os.environ.get('IP_BAN_DB'), 
                    port=os.environ.get('IP_BAN_DB_PORT'))
mntr_url=os.environ.get('SERVER_NAME')
api_name = 'umj-api-wflw'
max_auth_attempts=int(os.environ.get('MAX_AUTH_ATTEMPTS'))
auth_attempts={}
reg_attempts={}

async def ip_blocker(auto_ban: bool = False):
    if auto_ban is True:
        await ip_ban_db.connect_db()
        now = datetime.now(tz=timezone.utc)
        ban_data = {'ip': request.access_route[-1],
                    'banned_at': now.isoformat()}
        if await ip_ban_db.upload_db_data(id=f"blocked_ip:{request.access_route[-1]}", data=ban_data) > 0:
            logger.warning(f"Max authentication attempts reached for {request.access_route[-1]}. Blocking further attempts.")
            auth_attempts.pop(request.access_route[-1], None)
            abort(403) 

    if request.access_route[-1] not in auth_attempts:
        auth_attempts[request.access_route[-1]] = 1

    if auth_attempts[request.access_route[-1]] != max_auth_attempts:
        auth_attempts[request.access_route[-1]] += 1
        #await flash(message=f'Try again...', category='danger')
        #return redirect(url_for('login'))
    else:
        await ip_ban_db.connect_db()
        now = datetime.now(tz=timezone.utc)
        ban_data = {'ip': request.access_route[-1],
                    'banned_at': now.isoformat()}
        if await ip_ban_db.upload_db_data(id=f"blocked_ip:{request.access_route[-1]}", data=ban_data) > 0:
            logger.warning(f"Max authentication attempts reached for {request.access_route[-1]}. Blocking further attempts.")
            auth_attempts.pop(request.access_route[-1], None)
            abort(403) 

def admin_login_required(func):
    @wraps(func)
    async def wrapper(*args, **kwargs):
        await cl_sess_db.connect_db()
        await cl_auth_db.connect_db()

        if current_admin.auth_id is not None and await cl_sess_db.get_all_data(match=f"{current_admin.auth_id}", cnfrm=True) is True: 
            admin_data = await cl_sess_db.get_all_data(match=f"{current_admin.auth_id}")
            admin_data_sub_dict = next(iter(admin_data.values()))

    return wrapper

def user_login_required(func):
    @wraps(func)
    async def wrapper(*args, **kwargs):
        await cl_sess_db.connect_db()
        await cl_auth_db.connect_db()

        auth_id = current_client.auth_id
        jwt_token = request.cookies.get("access_token")

        if auth_id is None or "".strip() or await cl_sess_db.get_all_data(match=f"{auth_id}", cnfrm=True) is False or jwt_token is None or "".strip():
            await ip_blocker()
            return Unauthorized()
        
        logger.info(f"JWT Token from cookie: {jwt_token}")
        account_data = await cl_sess_db.get_all_data(match=f'*{auth_id}*')
        if account_data is not None:          
            logger.info(account_data)
            sub_dict = next(iter(account_data.values()))
            logger.info(sub_dict)

            jwt_key = sub_dict.get('usr_jwt_secret')
            logger.info(jwt_key)
            try:
                decoded_token = jwt.decode(jwt=jwt_token, key=jwt_key , algorithms=["HS256"])
            except jwt.InvalidTokenError:
                await ip_blocker()
                return Unauthorized()
            except jwt.ExpiredSignatureError:
                await ip_blocker()
                return Unauthorized()
            except jwt.DecodeError:
                await ip_blocker()
                return Unauthorized()
            logger.info(decoded_token)

            if decoded_token.get('rand') != sub_dict.get('usr_rand'):
                await ip_blocker()
                return Unauthorized()
                    
            return await app.ensure_async(func)(*args, **kwargs)
    return wrapper

@app.before_request
async def check_ip():
    await ip_ban_db.connect_db()
    logger.info(f"Checking if IP {request.access_route[-1]} is banned.")

    if await ip_ban_db.get_all_data(match=f"blocked_ip:{request.access_route[-1]}", cnfrm=True) is True:
        abort(403)

@app.route('/', methods=['GET'])
async def index():
    return await render_template('index/index.html')

@app.route('/login', methods=['GET', 'POST'])
async def login():
    try:
        logger.info(request.access_route)
        session["csrf_ready"] = True
        form = await LoginForm.create_form()

        if await form.validate_on_submit():
            username = form.username.data
            password = form.password.data

            username = username.replace(" ", "").lower()
            
            await cl_auth_db.connect_db()
            await cl_sess_db.connect_db()
            await cl_data_db.connect_db()

            if await cl_auth_db.get_all_data(match=f'*uid:{username}*', cnfrm=True) is False:
                await flash(message='Create an account...', category='danger')
                return redirect(url_for('register'))

            account_data = await cl_auth_db.get_all_data(match=f'*uid:{username}*')
            logger.info(account_data)
            sub_dict = next(iter(account_data.values()))
            logger.info(sub_dict)
            password_hash = sub_dict.get('pwd')
                
            if account_data and bcrypt.verify(password, password_hash) is False:
                await ip_blocker()
                return Unauthorized()
            
            logger.info(f'Account credentials verified for {username}')
            # Assign session ID for authenticated account
            session_id = util_obj.gen_id()

            # Client sign in and account sess. data -> sess-redis
            client_auth.login_user(Client(auth_id=session_id, action=Action.WRITE))

            await cl_sess_db.connect_db()

            # Pop password to mitigate potential leaks from redis session storage
            sub_dict.pop('pwd')

            # Generate user JWT data
            usr_rand=secrets.token_urlsafe(500)
            usr_jwt_secret=secrets.token_urlsafe(500)

            # Add JWT data to user session profile for upload to session redis db
            sub_dict["usr_rand"] = usr_rand
            sub_dict["usr_jwt_secret"] = usr_jwt_secret
            sub_dict['show_alerts'] = 'y'
            logger.info(sub_dict)

            # Generate user JWT to authenticate socket connection
            usr_jwt_token = util_obj.generate_ephemeral_token(user_id=session_id, secret_key=usr_jwt_secret, user_rand=usr_rand)
                        
            if await cl_sess_db.upload_db_data(id=session_id, data=sub_dict) > 0:
                rndm_cmp_id=util_obj.key_gen(size=100)
                session['url_key'] = util_obj.key_gen(size=100)

                resp = redirect(url_for('dashboard', cmp_id=rndm_cmp_id, obsc=session.get('url_key')))

                resp.set_cookie(
                            "access_token",
                            usr_jwt_token,
                            httponly=True,
                            secure=True,      # require HTTPS/WSS
                            samesite="Strict",
                            max_age=None      # 1 hour: 3600
                        )

                if await cl_data_db.get_all_data(match=f"api_dta:{sub_dict.get('db_id')}*", cnfrm=True) is False:
                    logger.info("User JWT token set in cookie.")
                    await flash(message=f'Authentication successful for {sub_dict.get('unm')}!', category='success')
                    return resp
                           
                else:
                    api_data = await cl_data_db.get_all_data(match=f"api_dta:{sub_dict.get('db_id')}*")
                    api_data_sub_dict = next(iter(api_data.values()))

                    api_jwt_key = api_data_sub_dict.get(f'{api_name}_jwt_secret')
                    api_rand = api_data_sub_dict.get(f'{api_name}_rand')
                    api_id = api_data_sub_dict.get(f'{api_name}_id')
                        
                    jwt_token = util_obj.generate_ephemeral_token(user_id=api_id, secret_key=api_jwt_key, user_rand=api_rand)

                    resp.set_cookie(
                                "api_access_token",
                                jwt_token,
                                httponly=True,
                                secure=True,      # require HTTPS/WSS
                                samesite="Strict",
                                max_age=None      # 1 hour: 3600
                            )

                    logger.info("API JWT token set in cookie.")

                    await flash(message=f'Authentication successful for {sub_dict.get('unm')}!', category='success')
                    return resp

        return await render_template('index/login.html', form=form)
    except Exception as e:
        logger.error( json.dumps({
            'status': 'error',
            'message': str(e)
        }), exc_info=True)

        return redirect(url_for('login'))
    
@app.route('/register', methods=['GET', 'POST'])
async def register():
    try:
        session["csrf_ready"] = True
        form = await RegisterForm.create_form()

        if await form.validate_on_submit():
            reg_key = form.reg_key.data
            username = form.uname.data.replace(" ", "").lower()

            await cl_auth_db.connect_db()

            if await cl_auth_db.get_all_data(match=f"reg_key:{username}:*", cnfrm=True) is False:
                await ip_blocker()
                await flash(message=f'Registration failed. Try again.', category='danger')
                return redirect(url_for('register'))
                
            reg_key_data = await cl_auth_db.get_all_data(match=f"reg_key:{username}:*")

            reg_key_sub_dict = next(iter(reg_key_data.values()))

            logger.info(reg_key_sub_dict)

            if bcrypt.verify(secret=reg_key, hash=reg_key_sub_dict.get("reg_key")) is False:
                await ip_blocker()
                await flash(message=f'Registration failed. Try again.', category='danger')
                return redirect(url_for('register'))

            password = form.password.data
            email = form.email.data
            fname = form.fname.data
            lname = form.lname.data

            password_hash = bcrypt.hash(password)

            username = username.replace(" ", "").lower()

            logger.info("Registering user: %s", username)

            user_nmp, user_id = util_obj.gen_user(username=username)

            user_obj = {
                "id": user_id,
                "unm": username,
                "eml": email,
                "pwd": password_hash,
                "fname": fname, 
                "lname": lname
            }

            logger.info(f"User ID: {user_obj['id']}")

            user_exist = await cl_auth_db.get_all_data(match=f'*uid:{username}*', cnfrm=True)

            if user_exist is False:
                # redis db key for new users
                user_key = f"{user_nmp}:{user_id}"
                user_obj['db_id'] = user_key
                logger.info(user_obj)

                # Upload user data
                if await cl_auth_db.upload_db_data(id=f"{user_key}", data=user_obj) > 0:
                    reg_key_del = await cl_auth_db.del_obj(key=reg_key_sub_dict.get('id')) 
                    logger.info(f"Registration key deletion status: {reg_key_del}")

                    await flash(message=f'Registration successful for {username}!', category='success')
                    return redirect(url_for('login'))
                else:
                    await flash(message=f'Registration failed for {username}. Try again.', category='danger')
                    return redirect(url_for('register'))
            else:
                await flash(message=f'Account for {username} already exist!', category='danger')
                return redirect(url_for('login'))

        return await render_template('index/register.html', form=form)

    except Exception as e:
        logger.error(json.dumps({'status': 'error', 'message': str(e)}), exc_info=True)
        return redirect(url_for('register'))

@app.route('/logout/<string:auth_id>', methods=['GET'])
@user_login_required
async def logout(auth_id):
    try:
        cur_usr_id = auth_id

        await cl_sess_db.connect_db()
        if await cl_sess_db.get_all_data(match=f'{cur_usr_id}', cnfrm=True) is False:
            await ip_blocker()
            return Unauthorized()
        
        result = await cl_sess_db.del_obj(key=cur_usr_id)

        logger.info(result)

        resp = redirect(url_for("login"))
        resp.delete_cookie("access_token")
        resp.delete_cookie("api_access_token")

        client_auth.logout_user()

        await flash(message="You have been logged out.", category="info")
        return resp

    except Exception as e:
        logger.error(json.dumps({
            "status": "error",
            "message": str(e)
        }), exc_info=True)
        resp = redirect(url_for("login"))
        resp.delete_cookie("access_token")
        resp.delete_cookie("api_access_token")
        return resp

@app.route('/dashboard', defaults={'cmp_id': url_cmp_id,'obsc': url_key}, methods=['GET', 'POST'])
@app.route("/dashboard/<string:cmp_id>/<string:obsc>", methods=['GET', 'POST'])
@user_login_required
async def dashboard(cmp_id, obsc):
    cur_usr_id = current_client.auth_id

    await cl_auth_db.connect_db()
    await cl_sess_db.connect_db()

    # Retrieve user session data
    cl_sess_data = await cl_sess_db.get_all_data(match=f"{cur_usr_id}")
    cl_sess_data_dict = next(iter(cl_sess_data.values()))
    logger.info(cl_sess_data_dict)

    cur_usr = cl_sess_data_dict.get('unm')

    data = {'unm': cl_sess_data_dict.get('unm'),
            'id': cl_sess_data_dict.get('db_id'),
            'fnm': cl_sess_data_dict.get('fname'),
            'lnm': cl_sess_data_dict.get('lname'),
            'eml': cl_sess_data_dict.get('eml')}

    # Retrieve user data from auth db
    main_user_data = await cl_auth_db.get_all_data(match=f'*{cl_sess_data_dict.get('unm')}*')
    logger.info(main_user_data)

    # URL for agent websocket connection initialization
    ws_url = f"wss://{mntr_url}/ws?id={cur_usr_id}&unm={cl_sess_data_dict.get('unm')}"

    return await render_template("app/dashboard.html", obsc_key=session.get('url_key'), cmp_id=cmp_id, auth_id=cur_usr_id, ws_url=ws_url, cur_usr=cur_usr, data=data)

@app.route('/agent', defaults={'cmp_id': url_cmp_id,'obsc': url_key}, methods=['GET', 'POST'])
@app.route("/agent/<string:cmp_id>/<string:obsc>", methods=['GET', 'POST'])
@user_login_required
async def agent(cmp_id, obsc):
    cur_usr_id = current_client.auth_id

    await cl_auth_db.connect_db()
    await cl_sess_db.connect_db()
    await cl_data_db.connect_db()

    # Retrieve user session data
    cl_sess_data = await cl_sess_db.get_all_data(match=f"{cur_usr_id}")
    cl_sess_data_dict = next(iter(cl_sess_data.values()))
    logger.info(cl_sess_data_dict)

    cur_usr = cl_sess_data_dict.get('unm')

    data = {'unm': cl_sess_data_dict.get('unm'),
            'id': cl_sess_data_dict.get('db_id'),
            'fnm': cl_sess_data_dict.get('fname'),
            'lnm': cl_sess_data_dict.get('lname'),
            'eml': cl_sess_data_dict.get('eml')}

    # URL for agent websocket connection initialization
    ws_url = f"wss://{mntr_url}/ws?id={cur_usr_id}&unm={cl_sess_data_dict.get('unm')}"

    probe_data = await cl_data_db.get_all_data(match=f"prb:*")

    if probe_data is None:
        probe_data = {"":""}

    return await render_template("app/agent.html", obsc_key=session.get('url_key'), ws_url=ws_url, cmp_id=cmp_id, user=cl_sess_data_dict.get('unm'), options=probe_data, mntr_url=mntr_url, cur_usr=cur_usr, auth_id=cur_usr_id, data=data)

@app.route('/settings', defaults={'cmp_id': url_cmp_id,'obsc': url_key}, methods=['GET', 'POST'])
@app.route("/settings/<string:cmp_id>/<string:obsc>", methods=['GET', 'POST'])
@user_login_required
async def settings(cmp_id, obsc):
    cur_usr_id = current_client.auth_id

    await cl_auth_db.connect_db()
    await cl_sess_db.connect_db()
    await cl_data_db.connect_db()

    session["csrf_ready"] = True

    # Retrieve user session data
    cl_sess_data = await cl_sess_db.get_all_data(match=f"{cur_usr_id}")
    cl_sess_data_dict = next(iter(cl_sess_data.values()))

    cur_usr = cl_sess_data_dict.get('unm')

    data = {'unm': cl_sess_data_dict.get('unm'),
            'id': cl_sess_data_dict.get('db_id'),
            'fnm': cl_sess_data_dict.get('fname'),
            'lnm': cl_sess_data_dict.get('lname'),
            'eml': cl_sess_data_dict.get('eml')}
    
    all_alert_types = await cl_data_db.get_all_data(match="alrt:*")

    if all_alert_types is None:
        all_alert_types = {'':''}

    # URL for agent websocket connection initialization
    ws_url = f"wss://{mntr_url}/ws?id={cur_usr_id}&unm={cl_sess_data_dict.get('unm')}"
  
    return await render_template("app/settings.html", obsc_key=session.get('url_key'), cmp_id=cmp_id, data=data, cur_usr=cl_sess_data_dict.get('unm'), mntr_url=mntr_url, all_alert_types=all_alert_types, ws_url=ws_url, auth_id=cur_usr_id)

@app.route('/floweditor', defaults={'cmp_id': 'bcl','obsc': url_key}, methods=['GET', 'POST'])
@app.route("/floweditor/<string:cmp_id>/<string:obsc>", methods=['GET', 'POST'])
@user_login_required
async def floweditor(cmp_id, obsc):
    util_obj = Util()

    cur_usr_id = current_client.auth_id
    
    await cl_auth_db.connect_db()
    await cl_sess_db.connect_db()
    await cl_data_db.connect_db()

    # Retrieve user session data
    cl_sess_data = await cl_sess_db.get_all_data(match=f"{cur_usr_id}")
    cl_sess_data_dict = next(iter(cl_sess_data.values()))
    logger.info(cl_sess_data_dict)

    cur_usr = cl_sess_data_dict.get('unm')

    data = {'unm': cl_sess_data_dict.get('unm'),
            'id': cl_sess_data_dict.get('db_id'),
            'fnm': cl_sess_data_dict.get('fname'),
            'lnm': cl_sess_data_dict.get('lname'),
            'eml': cl_sess_data_dict.get('eml')}

    # URL for agent websocket connection initialization
    ws_url = f"wss://{mntr_url}/ws?id={cur_usr_id}&unm={cl_sess_data_dict.get('unm')}"

    probe_data = await cl_data_db.get_all_data(match=f"prb:*")
    if probe_data is None:
        probe_data = {'':''}
        
    all_flows = await cl_data_db.get_all_data(match=f"flow:*")
    if all_flows is None:
        all_flows = {'':''}
    
    logger.info(probe_data)
    logger.info(all_flows)

    return await render_template("app/floweditor.html", obsc_key=session.get('url_key') ,
                                cmp_id=cmp_id, all_probes=probe_data, mntr_url=mntr_url, 
                                user=cl_sess_data_dict.get('unm'), flows=all_flows, cur_usr=cur_usr, ws_url=ws_url, auth_id=cur_usr_id, data=data)

@app.route('/probes', defaults={'cmp_id': 'bcl','obsc': url_key}, methods=['GET', 'POST'])
@app.route("/probes/<string:cmp_id>/<string:obsc>", methods=['GET', 'POST'])
@user_login_required
async def probes(cmp_id, obsc):
    util_obj = Util()

    cur_usr_id = current_client.auth_id
    
    await cl_auth_db.connect_db()
    await cl_sess_db.connect_db()
    await cl_data_db.connect_db()

    # Retrieve user session data
    cl_sess_data = await cl_sess_db.get_all_data(match=f"{cur_usr_id}")
    cl_sess_data_dict = next(iter(cl_sess_data.values()))
    logger.info(cl_sess_data_dict)

    cur_usr = cl_sess_data_dict.get('unm')

    data = {'unm': cl_sess_data_dict.get('unm'),
            'id': cl_sess_data_dict.get('db_id'),
            'fnm': cl_sess_data_dict.get('fname'),
            'lnm': cl_sess_data_dict.get('lname'),
            'eml': cl_sess_data_dict.get('eml')}

    # URL for agent websocket connection initialization
    ws_url = f"wss://{mntr_url}/ws?id={cur_usr_id}&unm={cl_sess_data_dict.get('unm')}"

    all_probes = await cl_data_db.get_all_data(match=f"prb:*")
    logger.info(all_probes)

    if all_probes is None:
        all_probes = {'':''}

    return await render_template("app/probes.html", obsc_key=session.get('url_key'),
                                all_probes=all_probes, cmp_id=cmp_id, mntr_url=mntr_url, cur_usr=cur_usr, auth_id=cur_usr_id, ws_url=ws_url, data=data)

@app.route('/flowmgr', defaults={'cmp_id': 'bcl','obsc': url_key}, methods=['GET', 'POST'])
@app.route("/flowmgr/<string:cmp_id>/<string:obsc>", methods=['GET', 'POST'])
@user_login_required
async def flowmgr(cmp_id, obsc):
    util_obj = Util()

    cur_usr_id = current_client.auth_id
    
    await cl_auth_db.connect_db()
    await cl_sess_db.connect_db()
    await cl_data_db.connect_db()

    # Retrieve user session data
    cl_sess_data = await cl_sess_db.get_all_data(match=f"{cur_usr_id}")
    cl_sess_data_dict = next(iter(cl_sess_data.values()))
    logger.info(cl_sess_data_dict)

    cur_usr = cl_sess_data_dict.get('unm')

    data = {'unm': cl_sess_data_dict.get('unm'),
            'id': cl_sess_data_dict.get('db_id'),
            'fnm': cl_sess_data_dict.get('fname'),
            'lnm': cl_sess_data_dict.get('lname'),
            'eml': cl_sess_data_dict.get('eml')}

    # URL for agent websocket connection initialization
    ws_url = f"wss://{mntr_url}/ws?id={cur_usr_id}&unm={cl_sess_data_dict.get('unm')}"

    all_flows = await cl_data_db.get_all_data(match=f"flow:*")
    logger.info(all_flows)

    if all_flows is None:
        all_flows = {'':''}

    return await render_template("app/flowmgr.html", obsc_key=session.get('url_key') ,
                                flows=all_flows, cmp_id=cmp_id, ollama_proxy =os.environ.get('OLLAMA_PROXY_URL'), user=cl_sess_data_dict.get('unm'), mntr_url=mntr_url, cur_usr=cur_usr, auth_id=cur_usr_id, ws_url=ws_url, data=data)

@app.route('/alerts', defaults={'cmp_id': 'bcl','obsc': url_key}, methods=['GET', 'POST'])
@app.route("/alerts/<string:cmp_id>/<string:obsc>", methods=['GET', 'POST'])
@user_login_required
async def alerts(cmp_id, obsc):
    util_obj = Util()

    cur_usr_id = current_client.auth_id
    
    await cl_auth_db.connect_db()
    await cl_sess_db.connect_db()

    # Retrieve user session data
    cl_sess_data = await cl_sess_db.get_all_data(match=f"{cur_usr_id}")
    cl_sess_data_dict = next(iter(cl_sess_data.values()))
    logger.info(cl_sess_data_dict)

    cur_usr = cl_sess_data_dict.get('unm')

    data = {'unm': cl_sess_data_dict.get('unm'),
            'id': cl_sess_data_dict.get('db_id'),
            'fnm': cl_sess_data_dict.get('fname'),
            'lnm': cl_sess_data_dict.get('lname'),
            'eml': cl_sess_data_dict.get('eml')}

    # URL for agent websocket connection initialization
    ws_url = f"wss://{mntr_url}/ws?id={cur_usr_id}&unm={cl_sess_data_dict.get('unm')}"
    
    discovery_results = None

    return await render_template("app/alerts.html", obsc_key=session.get('url_key') ,
                                  cmp_id=cmp_id, discovery_results = discovery_results, auth_id=cur_usr_id, ws_url=ws_url, cur_usr=cur_usr, data=data)

@app.route('/chats', defaults={'cmp_id': 'bcl','obsc': url_key}, methods=['GET', 'POST'])
@app.route("/chats/<string:cmp_id>/<string:obsc>", methods=['GET', 'POST'])
@user_login_required
async def chats(cmp_id, obsc):
    util_obj = Util()

    cur_usr_id = current_client.auth_id
    
    await cl_auth_db.connect_db()
    await cl_sess_db.connect_db()

    # Retrieve user session data
    cl_sess_data = await cl_sess_db.get_all_data(match=f"{cur_usr_id}")
    cl_sess_data_dict = next(iter(cl_sess_data.values()))
    logger.info(cl_sess_data_dict)

    cur_usr = cl_sess_data_dict.get('unm')

    data = {'unm': cl_sess_data_dict.get('unm'),
            'id': cl_sess_data_dict.get('db_id'),
            'fnm': cl_sess_data_dict.get('fname'),
            'lnm': cl_sess_data_dict.get('lname'),
            'eml': cl_sess_data_dict.get('eml')}

    # URL for agent websocket connection initialization
    ws_url = f"wss://{mntr_url}/ws?id={cur_usr_id}&unm={cl_sess_data_dict.get('unm')}"
    
    discovery_results = None

    return await render_template("app/chats.html", obsc_key=session.get('url_key') ,
                                  cmp_id=cmp_id, discovery_results = discovery_results, auth_id=cur_usr_id, ws_url=ws_url, cur_usr=cur_usr, data=data)

@app.route('/tasks', defaults={'cmp_id': 'bcl','obsc': url_key}, methods=['GET', 'POST'])
@app.route("/tasks/<string:cmp_id>/<string:obsc>", methods=['GET', 'POST'])
@user_login_required
async def tasks(cmp_id, obsc):
    util_obj = Util()

    cur_usr_id = current_client.auth_id
    
    await cl_auth_db.connect_db()
    await cl_sess_db.connect_db()

    # Retrieve user session data
    cl_sess_data = await cl_sess_db.get_all_data(match=f"{cur_usr_id}")
    cl_sess_data_dict = next(iter(cl_sess_data.values()))
    logger.info(cl_sess_data_dict)

    cur_usr = cl_sess_data_dict.get('unm')

    data = {'unm': cl_sess_data_dict.get('unm'),
            'id': cl_sess_data_dict.get('db_id'),
            'fnm': cl_sess_data_dict.get('fname'),
            'lnm': cl_sess_data_dict.get('lname'),
            'eml': cl_sess_data_dict.get('eml')}

    # URL for agent websocket connection initialization
    ws_url = f"wss://{mntr_url}/ws?id={cur_usr_id}&unm={cl_sess_data_dict.get('unm')}"
    
    discovery_results = None

    return await render_template("app/tasks.html", obsc_key=session.get('url_key') ,
                                  cmp_id=cmp_id, discovery_results = discovery_results, auth_id=cur_usr_id, ws_url=ws_url, cur_usr=cur_usr, data=data)

@app.errorhandler(Unauthorized)
async def redirect_to_login(*_):
    return redirect(url_for("login"))

@app.errorhandler(CSRFError)
async def handle_csrf_error(e):
    return await render_template('error/csrf_error.html', reason=e.description), 400

@app.errorhandler(401)
async def need_to_login(e):
    return await render_template("error/401.html"), 401


@app.errorhandler(404)
async def page_not_found(e):
    return await render_template("error/404.html"), 404

@app.errorhandler(500)
async def handle_internal_error(e):
    return await render_template_string(json.dumps({"error": "Internal server error"})), 500   
