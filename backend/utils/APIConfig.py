from onetimesecret import OneTimeSecretCli
from EmailSenderHandler import EmailSenderHandler
import os
import uuid
from passlib.hash import bcrypt
import secrets
from app import logger, util_obj, cl_data_db, api_name

email_sender_handler = EmailSenderHandler(brevo_api_key=os.environ.get('BREVO_API_KEY'))
cli = OneTimeSecretCli(os.environ.get('OTS_USER'), os.environ.get('OTS_KEY'), os.environ.get('REGION'))

async def resetapi(usr_data_dict: dict):
    old_api_data = await cl_data_db.get_all_data(match=f"{api_name}:dta:*")
    old_api_data_dict = next(iter(old_api_data.values())) if old_api_data else None
    if await cl_data_db.del_obj(key=f"{api_name}:dta:{old_api_data_dict.get(f'{api_name}_id')}") is not None:
        api_id = util_obj.key_gen(size=10) 
        new_api_key = str(uuid.uuid4())
        updated_api_data = {
            api_name: bcrypt.hash(new_api_key),
            f"{api_name}_id": api_id,
            f"{api_name}_rand": secrets.token_urlsafe(500),
            f"{api_name}_jwt_secret": secrets.token_urlsafe(500)
        }
   
        if await cl_data_db.upload_db_data(id=f"{api_name}:dta:{api_id}", data=updated_api_data) > 0:
            link = cli.create_link(secret=new_api_key, ttl=int(os.environ.get('OTS_TTL')))

            html_snippet = f"""<div style="font-family: Arial, sans-serif; color: #111; line-height: 1.5;">
                        <p>Hello,</p>
                        <p><strong>umjiniti</strong> API key for user <strong>{usr_data_dict.get('unm')}</strong> has been reset.</p>
                        <p>You can retrieve the API key using the following one-time secret link. Note that this link will expire after a single use.</p>
                        <p>API Key Retrieval Link: <a href="{link}">{link}</a></p>
                        <p>Thank you,<br/>umjiniti Team</p>

                        </div>"""
            send_result = email_sender_handler.send_transactional_email(sender={'name': 'umjiniti Admin', 'email': os.environ.get('BREVO_SENDER_EMAIL')},
                                                                                 to=[{"name": usr_data_dict.get('unm'), "email": usr_data_dict.get('eml')}],
                                                                                 subject=f"umjiniti-core API Key Reset for {usr_data_dict.get('unm')}",
                                                                                 html_content=html_snippet
                                                                                 )

            logger.info(f"API key reset email send result: {send_result}")
            return
        else:
            return None
        
async def createapi(usr_data_dict: dict):
    api_id = util_obj.key_gen(size=10) 
    new_api_key = str(uuid.uuid4())
    api_name = os.environ.get('API_NAME')
    updated_api_data = {
            api_name: bcrypt.hash(new_api_key),
            f"{api_name}_id": api_id,
            f"{api_name}_rand": secrets.token_urlsafe(500),
            f"{api_name}_jwt_secret": secrets.token_urlsafe(500)
    }
        
    if await cl_data_db.upload_db_data(id=f"{api_name}:dta:{api_id}", data=updated_api_data) > 0:
        link = cli.create_link(secret=new_api_key, ttl=int(os.environ.get('OTS_TTL')))

        contact_data = {"LASTNAME": usr_data_dict.get('lname'),
                                "FIRSTNAME": usr_data_dict.get('fname'),
                                }
        new_contact_result = email_sender_handler.add_contact(email=usr_data_dict.get('eml'),
                    ext_id=usr_data_dict.get('db_id'), attributes=contact_data
        )

        logger.info(type(new_contact_result))
        logger.info(f"New contact creation result: {new_contact_result}")

        if not new_contact_result:
            logger.error(f"Failed to create contact in Brevo for user {usr_data_dict.get('unm')} with email {usr_data_dict.get('eml')}")
            return
                
        html_snippet = f"""<div style="font-family: Arial, sans-serif; color: #111; line-height: 1.5;">
                        <p>Hello,</p>
                        <p>A new <strong>umjiniti</strong> API key has been generated for user <strong>{usr_data_dict.get('unm')}</strong>.</p>
                        <p>You can retrieve the API key using the following one-time secret link. Note that this link will expire after a single use.</p>
                        <p>API Key Retrieval Link: <a href="{link}">{link}</a></p>
                        <p>Thank you,<br/>umjiniti Team</p>

                        </div>"""
        send_result = email_sender_handler.send_transactional_email(
            sender={'name': 'umjiniti Admin', 'email': os.environ.get('BREVO_SENDER_EMAIL')},
            to=[{"name": usr_data_dict.get('unm'), "email": usr_data_dict.get('eml')}],
            subject=f"New umjiniti-core API Key Generated for {usr_data_dict.get('unm')}",
            html_content=html_snippet
        )

        logger.info(type(send_result))
        logger.info(f"API key creation email send result: {send_result}")
        return None if not send_result else send_result       
    else:
        return None