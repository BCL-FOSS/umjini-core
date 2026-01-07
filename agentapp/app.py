from init_app import (app, client_auth, current_admin, current_client, logger,
                      Client
                      )
from forms.LoginForm import LoginForm
from forms.RegisterForm import RegisterForm
from forms.SDNCredForm import SDNCredForm
from forms.APIKeyGenForm import APIKeyGenForm
from forms.AlertEmailForm import AlertEmailForm
from forms.AlertJiraForm import AlertJiraForm
from forms.AlertSlackForm import AlertSlackForm
from quart import (render_template_string, render_template, flash, redirect, url_for, session, request, jsonify, abort)
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
from datetime import datetime, timedelta, timezone
from tzlocal import get_localzone
from onetimesecret import OneTimeSecretCli
from utils.EmailHandler import EmailHandler

cli = OneTimeSecretCli(os.environ.get('OTS_USER'), os.environ.get('OTS_KEY'), os.environ.get('REGION'))
email_handler = EmailHandler(host=os.environ.get('SMTP_SERVER'),
                             port=int(os.environ.get('SMTP_PORT')),
                             username=os.environ.get('SMTP_SENDER'),
                             password=os.environ.get('SMTP_SENDER_APP_PASSWORD'),
                             sender=os.environ.get('SMTP_SENDER'),
                             tls=True)

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
max_auth_attempts=3
auth_attempts={}

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

        if auth_id is not None or "".strip() and await cl_sess_db.get_all_data(match=f"{auth_id}", cnfrm=True) is True:
            jwt_token = request.cookies.get("access_token")
            logger.info(f"JWT Token from cookie: {jwt_token}")
            account_data = await cl_sess_db.get_all_data(match=f'*{auth_id}*')
            if account_data is not None:
                      
                logger.info(account_data)
                sub_dict = next(iter(account_data.values()))
                logger.info(sub_dict)

                jwt_key = sub_dict.get('usr_jwt_secret')
                logger.info(jwt_key)
                decoded_token = jwt.decode(jwt=jwt_token, key=jwt_key , algorithms=["HS256"])
                logger.info(decoded_token)

                if decoded_token.get('rand') == sub_dict.get('usr_rand'):
                    return await app.ensure_async(func)(*args, **kwargs)
                else:
                    await ip_ban_db.connect_db()
                    now = datetime.now(tz=timezone.utc)
                    ban_data = {'ip': request.access_route[-1],
                                            'banned_at': now.isoformat()}
                    if await ip_ban_db.upload_db_data(id=f"blocked_ip:{request.access_route[-1]}", data=ban_data) is not None:
                        return Unauthorized()
        else:
            return Unauthorized()
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

            if await cl_auth_db.get_all_data(match=f'*{username}*', cnfrm=True) is True:
              
                account_data = await cl_auth_db.get_all_data(match=f'*{username}*')
                logger.info(account_data)
                sub_dict = next(iter(account_data.values()))
                logger.info(sub_dict)
                password_hash = sub_dict.get('pwd')
                
                if account_data and bcrypt.verify(password, password_hash):
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
                    logger.info(sub_dict)

                    # Generate user JWT to authenticate initial agent websocket connection
                    usr_jwt_token = util_obj.generate_ephemeral_token(user_id=session_id, secret_key=usr_jwt_secret, user_rand=usr_rand)
                        
                    if await cl_sess_db.upload_db_data(id=session_id, data=sub_dict) > 0:
                        # db_id = sub_dict.get('db_id')
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

                        if sub_dict.get(f'{api_name}_id') is None:  
                            await flash(message=f'Authentication successful for {sub_dict.get('unm')}!', category='success')
                            return resp
                        else:
                            api_jwt_key = sub_dict.get(f'{api_name}_jwt_secret')
                            api_rand = sub_dict.get(f'{api_name}_rand')
                            api_id = sub_dict.get(f'{api_name}_id')
                        
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

                else:
                    if request.access_route[-1] not in auth_attempts:
                        auth_attempts[request.access_route[-1]] = 1

                    if auth_attempts[request.access_route[-1]] != max_auth_attempts:
                        auth_attempts[request.access_route[-1]] += 1
                        await flash(message=f'Try again...', category='danger')
                        return redirect(url_for('login'))
                    else:
                        await ip_ban_db.connect_db()
                        now = datetime.now(tz=timezone.utc)
                        ban_data = {'ip': request.access_route[-1],
                                    'banned_at': now.isoformat()}
                        if await ip_ban_db.upload_db_data(id=f"blocked_ip:{request.access_route[-1]}", data=ban_data) is not None:
                            logger.warning(f"Max authentication attempts reached for {request.access_route[-1]}. Blocking further attempts.")
                            auth_attempts.pop(request.access_route[-1], None)
                            abort(403) 
            else:
                await flash(message='Create an account...', category='danger')
                return redirect(url_for('register'))

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
            username, password = form.uname.data.replace(" ", "").lower(), form.password.data

            password_hash = bcrypt.hash(password)

            username = username.replace(" ", "").lower()

            logger.info("Registering user: %s", username)

            user_nmp, user_id = util_obj.gen_user(username=username)

            user_obj = {
                "id": user_id,
                "unm": username,
                "pwd": password_hash,
                "sdn_users": None,
                "mcp_api_key": []
            }

            logger.info(f"User ID: {user_obj['id']}")

            await cl_auth_db.connect_db()

            user_exist = await cl_auth_db.get_all_data(match=f'*{username}*', cnfrm=True)

            if user_exist is False:
                # redis db key for new users
                user_key = f"{user_nmp}:{user_id}"
                user_obj['db_id'] = user_key
                logger.info(user_obj)

                # Upload user data
                if await cl_auth_db.upload_db_data(id=f"{user_key}", data=user_obj) > 0:
                    await flash(message=f'Registration successful for {username}!', category='success')
                    return redirect(url_for('login'))
                else:
                    await flash(message=f'Registration falied for {username}. Try again.', category='danger')
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
        # Remove user session profile from sess redis db/automatically invalidates active JWT tokens
        #auth_id = request.args.get('auth_id')
        cur_usr_id = auth_id

        await cl_sess_db.connect_db()
        if await cl_sess_db.get_all_data(match=f'{cur_usr_id}', cnfrm=True) is False:
            return Unauthorized()
        
        result = await cl_sess_db.del_obj(key=cur_usr_id)

        logger.info(result)

        # Clear JWT cookie
        resp = redirect(url_for("login"))
        resp.delete_cookie("access_token")
        resp.delete_cookie("api_access_token")

        # quart-auth sign out
        client_auth.logout_user()

        await flash(message="You have been logged out.", category="info")
        return resp

    except Exception as e:
        logger.error(json.dumps({
            "status": "error",
            "message": str(e)
        }), exc_info=True)
        # Still clear cookie as fail-safe and redirect to login
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

    # Retrieve user data from auth db
    main_user_data = await cl_auth_db.get_all_data(match=f'*{cl_sess_data_dict.get('unm')}*')
    logger.info(main_user_data)

    # URL for agent websocket connection initialization
    ws_url = f"wss://{mntr_url}/ws?id={cur_usr_id}&unm={cl_sess_data_dict.get('unm')}"

    return await render_template("app/dashboard.html", obsc_key=session.get('url_key'), cmp_id=cmp_id, auth_id=cur_usr_id, ws_url=ws_url, cur_usr=cur_usr)

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

    # URL for agent websocket connection initialization
    ws_url = f"wss://{mntr_url}/ws?id={cur_usr_id}&unm={cl_sess_data_dict.get('unm')}"

    probe_data = await cl_data_db.get_all_data(match=f"prb:*")

    mcp_urls = []
    if probe_data is not None:
        for k,v in probe_data.items():
            mcp_urls.append(f"{v['url']}/llm/mcp")

    logger.info(mcp_urls)

    return await render_template("app/agent.html", obsc_key=session.get('url_key'), ws_url=ws_url, cmp_id=cmp_id, user=cl_sess_data_dict.get('unm'), options=mcp_urls, mntr_url=mntr_url, cur_usr=cur_usr, auth_id=cur_usr_id)

@app.route('/settings', defaults={'cmp_id': url_cmp_id,'obsc': url_key}, methods=['GET', 'POST'])
@app.route("/settings/<string:cmp_id>/<string:obsc>", methods=['GET', 'POST'])
@user_login_required
async def settings(cmp_id, obsc):
    cur_usr_id = current_client.auth_id

    await cl_auth_db.connect_db()
    await cl_sess_db.connect_db()
    await cl_data_db.connect_db()

    session["csrf_ready"] = True
    sdn_form = await SDNCredForm.create_form()
    api_form = await APIKeyGenForm.create_form()
    email_alert_form = await AlertEmailForm.create_form()
    jira_alert_form = await AlertJiraForm.create_form()
    slack_alert_form = await AlertSlackForm.create_form()

    # Retrieve user session data
    cl_sess_data = await cl_sess_db.get_all_data(match=f"{cur_usr_id}")
    cl_sess_data_dict = next(iter(cl_sess_data.values()))

    cur_usr = cl_sess_data_dict.get('unm')

    data = {'unm': cl_sess_data_dict.get('unm'),
            'id': cl_sess_data_dict.get('db_id')}
    
    all_alert_types = await cl_data_db.get_all_data(match="alrt:*")
    all_sdn = await cl_data_db.get_all_data(match=f"sdn:*")

    if all_alert_types is None:
        all_alert_types = {'':''}

    if all_sdn is None:
        all_sdn = {'':''}

    # URL for agent websocket connection initialization
    ws_url = f"wss://{mntr_url}/ws?id={cur_usr_id}&unm={cl_sess_data_dict.get('unm')}"
    
    if await sdn_form.validate_on_submit():
        if len(all_sdn.keys()) == int(os.environ.get('SDN_COUNT')):
            await flash(message=f"Maximum of 3 SDN controller credentials reached. Delete an existing entry to add a new one.")
            return redirect(url_for('settings', cmp_id=cmp_id, obsc=obsc))
        
        sdn_id = f"sdn:{sdn_form.controller.data}:{sdn_form.fqdn.data}"
            
        sdn_data = {'type': sdn_form.controller.data, 
                    'ip': sdn_form.fqdn.data, 
                    'user': sdn_form.uname.data, 
                    'pwd': sdn_form.password.data,
                    'count': len(all_sdn.keys()) + 1,
                    'id': sdn_id
                }

        if await cl_data_db.upload_db_data(id=sdn_id, data=sdn_data) is None:
            await flash(message=f"API key gen failed...")
            return redirect(url_for('settings', cmp_id=cmp_id, obsc=obsc))
        
        await flash(message=f'Controller Credentials saved to account: {cl_sess_data_dict.get('unm')}!', category='success')
        return redirect(url_for('settings',  cmp_id=cmp_id, obsc=obsc))
        
    if await api_form.validate_on_submit():
        api_type = api_form.api.data
        api_name = f"{api_type}"
        api_id = util_obj.key_gen(size=10)

        user_data = await cl_auth_db.get_all_data(match=f'*{cl_sess_data_dict.get('unm')}*')

        user_data_dict = next(iter(user_data.values()))

        logger.info(user_data_dict.keys())

        if api_name in list(user_data_dict.keys()):
            await flash(message=f"{api_type} API Key already exists for {cl_sess_data_dict.get('unm')}.")
            return redirect(url_for('settings', cmp_id=cmp_id, obsc=obsc))
                
        new_api_key = util_obj.generate_api_key()

        updt_obj = {api_name: bcrypt.hash(new_api_key),
                    f"{api_name}_id": api_id,
                    f"{api_name}_rand": secrets.token_urlsafe(500),
                    f"{api_name}_jwt_secret": secrets.token_urlsafe(500)
                }

        if await cl_data_db.upload_db_data(id=f"api_dta:{cl_sess_data_dict.get('db_id')}", data=updt_obj) is None:
            await flash(message=f"API key gen failed...")
            return redirect(url_for('settings', cmp_id=cmp_id, obsc=obsc))
        
        link = cli.create_link(secret=new_api_key, ttl=int(os.environ.get('OTS_TTL')))

        await email_handler.send_email(
            recipient=os.environ.get('SMTP_RECEIVER'),
            subject=f"New umjiniti-core API Key Generated",
            message=f"""
            Hello,

            A new umjiniti API key has been generated for user {cl_sess_data_dict.get('unm')}.

            You can retrieve the API key using the following one-time secret link. Note that this link will expire after a single use.

            API Key Retrieval Link: {link}

            Thank you,
            umjiniti Team
            """
        )
        
        await flash(message=f"{api_type} API Key has been generated and sent to the registered email address.")
        return redirect(url_for('settings', cmp_id=cmp_id, obsc=obsc))
           
    if await email_alert_form.validate_on_submit():
        all_emails = await cl_data_db.get_all_data(match=f"alrt:eml:*")
        if all_emails is not None and len(all_emails.keys()) == int(os.environ.get('ALERT_COUNT')):
            await flash(message=f"Maximum of 3 email alert contacts reached. Delete an existing contact to add a new one.")
            return redirect(url_for('settings', cmp_id=cmp_id, obsc=obsc))
        
        count_id = len(all_emails.keys()) + 1
        
        email_alert_id = f"alrt:eml:{count_id}:{email_alert_form.smtp_host.data}:{email_alert_form.smtp_user.data}"

        email_alert_data = {'type': 'email',
                                'name': email_alert_form.smtp_sender.data,
                                'tls': email_alert_form.tls_enabled.data,
                                'host': email_alert_form.smtp_host.data,
                                'port': email_alert_form.smtp_port.data,
                                'user': email_alert_form.smtp_user.data,
                                'sender': email_alert_form.smtp_sender.data,
                                'pwd': email_alert_form.password.data,
                                'id': email_alert_id,
                                'count': count_id
                            }
            
        if await cl_data_db.upload_db_data(id=email_alert_id, data=email_alert_data) is None:
            await flash(message=f"Alert contact creation failed...")
            return redirect(url_for('settings', cmp_id=cmp_id, obsc=obsc))
        
        await flash(message=f"Alert contact {email_alert_form.smtp_sender.data} uploaded successfully.")
        return redirect(url_for('settings', cmp_id=cmp_id, obsc=obsc))
      
    if await jira_alert_form.validate_on_submit():
        all_jira = await cl_data_db.get_all_data(match=f"alrt:jira:*")
        if all_jira is not None and len(all_jira.keys()) == int(os.environ.get('ALERT_COUNT')):
            await flash(message=f"Maximum of 3 Jira alert contacts reached. Delete an existing contact to add a new one.")
            return redirect(url_for('settings', cmp_id=cmp_id, obsc=obsc))
        
        count_id = len(all_jira.keys()) + 1
        
        jira_alert_id = f"alrt:jira:{count_id}:{jira_alert_form.email.data}"

        jira_alert_data = {'type': 'jira',
                           'name': jira_alert_form.email.data,
                            'cloud_id': jira_alert_form.cloud_id.data,
                           'eml': jira_alert_form.email.data,
                           'token': jira_alert_form.auth_token.data,
                           'id': jira_alert_id,
                           'count': count_id
                        }
        
        if await cl_data_db.upload_db_data(id=jira_alert_id, data=jira_alert_data) is None:
            await flash(message=f"Alert contact creation failed...")
            return redirect(url_for('settings', cmp_id=cmp_id, obsc=obsc))
        
        await flash(message=f"Alert contact {jira_alert_form.email.data} uploaded successfully.")
        return redirect(url_for('settings', cmp_id=cmp_id, obsc=obsc))
   
    if await slack_alert_form.validate_on_submit():
        all_slack = await cl_data_db.get_all_data(match=f"alrt:slack:*")
        if all_slack is not None and len(all_slack.keys()) == int(os.environ.get('ALERT_COUNT')):
            await flash(message=f"Maximum of 3 Slack alert contacts reached. Delete an existing contact to add a new one.")
            return redirect(url_for('settings', cmp_id=cmp_id, obsc=obsc))
        
        count_id = len(all_slack.keys()) + 1
        
        slack_alert_id = f"alrt:slack:{count_id}:{slack_alert_form.slack_channel_id.data}"

        slack_alert_data = {'type': 'slack',
                            'name': slack_alert_form.slack_channel_id.data,
                            'channel_id': slack_alert_form.slack_channel_id.data,
                            'token': slack_alert_form.slack_token.data,
                            'id': slack_alert_id,
                            'count': count_id
                        }
        
        if await cl_data_db.upload_db_data(id=slack_alert_id, data=slack_alert_data) is None:
            await flash(message=f"Alert contact creation failed...")
            return redirect(url_for('settings', cmp_id=cmp_id, obsc=obsc))
        
        await flash(message=f"Alert contact {slack_alert_form.slack_channel_id.data} uploaded successfully.")
        return redirect(url_for('settings', cmp_id=cmp_id, obsc=obsc))
  
    return await render_template("app/settings.html", obsc_key=session.get('url_key'), cmp_id=cmp_id, data=data, sdn_form=sdn_form, api_form=api_form, jira_alert_form=jira_alert_form, slack_alert_form=slack_alert_form, email_alert_form=email_alert_form, cur_usr=cl_sess_data_dict.get('unm'), all_sdn=all_sdn, mntr_url=mntr_url, all_alert_types=all_alert_types, ws_url=ws_url, auth_id=cur_usr_id)

@app.route('/floweditor', defaults={'cmp_id': 'bcl','obsc': url_key}, methods=['GET', 'POST'])
@app.route("/floweditor/<string:cmp_id>/<string:obsc>", methods=['GET', 'POST'])
@user_login_required
async def floweditor(cmp_id, obsc):
    util_obj = Util()

    cur_usr_id = current_client.auth_id
    
    await cl_auth_db.connect_db()
    await cl_sess_db.connect_db()
    await cl_data_db.connect_db()

    all_emails = await cl_data_db.get_all_data(match=f"alrt:eml:*")
    all_jira = await cl_data_db.get_all_data(match=f"alrt:jira:*")
    all_slack = await cl_data_db.get_all_data(match=f"alrt:slack:*")

    if all_emails is None:
        all_emails = {'':''}

    if all_jira is None:
        all_jira = {'':''}

    if all_slack is None:
        all_slack = {'':''}

    # Retrieve user session data
    cl_sess_data = await cl_sess_db.get_all_data(match=f"{cur_usr_id}")
    cl_sess_data_dict = next(iter(cl_sess_data.values()))
    logger.info(cl_sess_data_dict)

    cur_usr = cl_sess_data_dict.get('unm')

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
                                user=cl_sess_data_dict.get('unm'), flows=all_flows, cur_usr=cur_usr, ws_url=ws_url, auth_id=cur_usr_id)

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

    # URL for agent websocket connection initialization
    ws_url = f"wss://{mntr_url}/ws?id={cur_usr_id}&unm={cl_sess_data_dict.get('unm')}"

    all_probes = await cl_data_db.get_all_data(match=f"prb:*")
    logger.info(all_probes)

    if all_probes is None:
        all_probes = {'':''}

    return await render_template("app/probes.html", obsc_key=session.get('url_key'),
                                all_probes=all_probes, cmp_id=cmp_id, mntr_url=mntr_url, cur_usr=cur_usr, auth_id=cur_usr_id, ws_url=ws_url)

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

    # URL for agent websocket connection initialization
    ws_url = f"wss://{mntr_url}/ws?id={cur_usr_id}&unm={cl_sess_data_dict.get('unm')}"

    all_flows = await cl_data_db.get_all_data(match=f"flow:*")
    logger.info(all_flows)

    if all_flows is None:
        all_flows = {'':''}

    return await render_template("app/flowmgr.html", obsc_key=session.get('url_key') ,
                                flows=all_flows, cmp_id=cmp_id, ollama_proxy =os.environ.get('OLLAMA_PROXY_URL'), user=cl_sess_data_dict.get('unm'), mntr_url=mntr_url, cur_usr=cur_usr, auth_id=cur_usr_id, ws_url=ws_url)

@app.route('/netvis', defaults={'cmp_id': 'bcl','obsc': url_key}, methods=['GET', 'POST'])
@app.route("/netvis/<string:cmp_id>/<string:obsc>", methods=['GET', 'POST'])
@user_login_required
async def netvis(cmp_id, obsc):
    util_obj = Util()

    cur_usr_id = current_client.auth_id
    
    await cl_auth_db.connect_db()
    await cl_sess_db.connect_db()

    # Retrieve user session data
    cl_sess_data = await cl_sess_db.get_all_data(match=f"{cur_usr_id}")
    cl_sess_data_dict = next(iter(cl_sess_data.values()))
    logger.info(cl_sess_data_dict)

    cur_usr = cl_sess_data_dict.get('unm')

    # URL for agent websocket connection initialization
    ws_url = f"wss://{mntr_url}/ws?id={cur_usr_id}&unm={cl_sess_data_dict.get('unm')}"
    
    discovery_results = None

    return await render_template("app/netvis.html", obsc_key=session.get('url_key') ,
                                  cmp_id=cmp_id, discovery_results = discovery_results, auth_id=cur_usr_id, ws_url=ws_url, cur_usr=cur_usr)

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
