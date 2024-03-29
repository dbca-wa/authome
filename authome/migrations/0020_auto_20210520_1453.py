# Generated by Django 3.1.6 on 2021-05-20 06:53

import django.contrib.auth.models
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('authome', '0019_auto_20210406_1517'),
    ]

    operations = [
        migrations.CreateModel(
            name='SystemUser',
            fields=[
            ],
            options={
                'verbose_name': 'System User',
                'verbose_name_plural': 'System Users',
                'proxy': True,
                'indexes': [],
                'constraints': [],
            },
            bases=('authome.user',),
            managers=[
                ('objects', django.contrib.auth.models.UserManager()),
            ],
        ),
        migrations.AddField(
            model_name='user',
            name='systemuser',
            field=models.BooleanField(default=False, editable=False),
        ),
    ]
