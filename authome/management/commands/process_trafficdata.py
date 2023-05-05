
from django.core.management.base import BaseCommand

from authome.trafficdata import save2db

class Command(BaseCommand):
    help = "Persistent traffic data, create the required traffic report"

    def handle(self,*args,**options):
        save2db()
