# Generated by Django 2.2.16 on 2020-11-05 23:28

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('authome', '0003_usertoken_modified'),
    ]

    operations = [
        migrations.AlterField(
            model_name='userauthorization',
            name='user',
            field=models.EmailField(max_length=64),
        ),
    ]