# Generated by Django 3.2.12 on 2023-02-07 06:31

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('authome', '0039_alter_debuglog_category'),
    ]

    operations = [
        migrations.AddField(
            model_name='identityprovider',
            name='secretkey_expireat',
            field=models.DateTimeField(null=True),
        ),
    ]
