import brevo_python
from brevo_python.rest import ApiException
import logging

logging.basicConfig(level=logging.INFO)

class EmailSenderHandler:
    def __init__(self, brevo_api_key: str):
        self.configuration = brevo_python.Configuration()
        self.configuration.api_key['api-key'] = brevo_api_key
        self.configuration.api_key['partner-key'] = brevo_api_key
        self.logger = logging.getLogger(__name__)

    def add_contact(self, email: str, ext_id:str, attributes: dict = None):
        api_instance = brevo_python.ContactsApi(brevo_python.ApiClient(self.configuration))
        create_contact = brevo_python.CreateContact(email=email, ext_id=ext_id, attributes=attributes)

        try:
            api_response = api_instance.create_contact(create_contact)
            self.logger.info(f"Contact added successfully: {api_response}")
            return api_response
        except ApiException as e:
            self.logger.exception(f"Exception when adding contact: {e}")
            return None
        finally:
            api_instance.api_client.rest_client.pool_manager.clear()
        
    def get_contact(self, user_id: str):  
        api_instance = brevo_python.ContactsApi(brevo_python.ApiClient(self.configuration))

        identifier = user_id
        identifier_type = 'ext_id'

        try:
            api_response = api_instance.get_contact_info(identifier, identifier_type=identifier_type)
            self.logger.info(f"Contact retrieved successfully: {api_response}")
            return api_response
        except ApiException as e:
            self.logger.exception(f"Exception when retrieving contact: {e}")
            return None
        finally:
            api_instance.api_client.rest_client.pool_manager.clear()
        
    def create_template(self, template_name: str, subject: str, html_content: str, sender: str):
        api_instance = brevo_python.TransactionalEmailsApi(brevo_python.ApiClient(self.configuration))
        create_template = brevo_python.CreateSmtpTemplate(
            template_name=template_name,
            sender=sender,
            subject=subject,
            html_content=html_content
        )

        try:
            api_response = api_instance.create_smtp_template(create_template)
            self.logger.info(f"Template created successfully: {api_response}")
            return api_response
        except ApiException as e:
            self.logger.exception(f"Exception when creating template: {e}")
            return None
        finally:
            api_instance.api_client.rest_client.pool_manager.clear()
        
    def retrieve_template(self, template_id: int):
        api_instance = brevo_python.TransactionalEmailsApi(brevo_python.ApiClient(self.configuration))

        try:
            api_response = api_instance.get_smtp_template(template_id)
            self.logger.info(f"Template retrieved successfully: {api_response}")
            return api_response
        except ApiException as e:
            self.logger.exception(f"Exception when retrieving template: {e}")
            return None
        
    def send_transactional_email(self, sender: str, to: list, subject: str, html_content: str):
        api_instance = brevo_python.TransactionalEmailsApi(brevo_python.ApiClient(self.configuration))
        send_smtp_email = brevo_python.SendSmtpEmail(
            sender=sender,
            to=to,
            subject=subject,
            html_content=html_content
        )

        try:
            api_response = api_instance.send_transac_email(send_smtp_email)
            
            self.logger.info(f"Transactional email sent successfully: {api_response}")
            return api_response
        
        except ApiException as e:
            self.logger.exception(f"Exception when sending transactional email: {e}")
            return None
        finally:
            api_instance.api_client.rest_client.pool_manager.clear()