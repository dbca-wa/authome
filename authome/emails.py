import re

from django.core.mail import EmailMessage


html_body_re = re.compile("^\s*<html(\s+|>)",re.IGNORECASE)
def send_email(email_from,to,subject,body,cc=None,bcc=None):
    to_addresses = lambda address:( address if isinstance(address,(list,tuple)) else [address] ) if address else None
    message = EmailMessage(
        subject=subject, 
        body=body, 
        from_email=email_from, 
        to=to_addresses(to), 
        cc=to_addresses(cc),
        bcc=to_addresses(bcc)
    )
    message.content_subtype = 'html' if html_body_re.search(body) else "text"
    ret = message.send()
    if not ret :
        raise Exception("Failed to send verification eamil to {}".format(to))
