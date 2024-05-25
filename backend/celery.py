#celery -A celery worker --loglevel=info
#celery -A main:cel_app worker -l INFO

#from app1.config import CELERY_BROKER_URL, CELERY_RESULT_BACKEND
#from celery import Celery
#app=Celery('tasks',broker='redis://127.0.0.1:6379/0',backend='redis://127.0.0.1:6379/0')
# celery.py
from celery import Celery

celery = Celery(
    'tasks',
    broker='redis://127.0.0.1:6379/1',
    include=["app1.tasks"]
)

if __name__ == '__main__':
    celery.start()
