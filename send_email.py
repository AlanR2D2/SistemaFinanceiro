# send_mail.py
import smtplib
from email.message import EmailMessage
import os
from dotenv import load_dotenv

load_dotenv()

EMAIL_ADDRESS = os.getenv("EMAIL")              # Seu email Gmail
EMAIL_APP_PASSWORD = os.getenv("SENHA_APP_GMAIL")  # Senha de app do Google

def send_email_error(body: str, subject: str = "Erro no Site Leads", to: str = "alangcchagas@gmail.com"):
    """
    Envia email de erro. Assunto default = 'Erro no Site Leads'.
    """
    try:
        msg = EmailMessage()
        msg['Subject'] = subject
        msg['From'] = EMAIL_ADDRESS
        msg['To'] = to
        msg.set_content(body)

        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
            smtp.login(EMAIL_ADDRESS, EMAIL_APP_PASSWORD)
            smtp.send_message(msg)
        print('E-mail enviado com sucesso!')
    except Exception as e:
        print(f"[ERRO] Falha ao enviar e-mail: {e}")
