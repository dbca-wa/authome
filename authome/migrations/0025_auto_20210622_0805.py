# Generated by Django 3.1.6 on 2021-06-22 00:05

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('authome', '0024_auto_20210621_0744'),
    ]

    operations = [
        migrations.AlterField(
            model_name='usergroup',
            name='groupid',
            field=models.SlugField(max_length=32),
        ),
    ]
