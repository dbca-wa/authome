# Generated by Django 3.2.12 on 2023-03-08 00:00

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('authome', '0040_identityprovider_secretkey_expireat'),
    ]

    operations = [
        migrations.AlterField(
            model_name='debuglog',
            name='category',
            field=models.PositiveSmallIntegerField(choices=[(10, 'Create cookie'), (11, 'Update cookie'), (12, 'Delete cookie'), (20, 'Upgrade session'), (21, 'Session already upgraded'), (22, 'Upgrade non-exist session'), (30, 'Migrate session'), (31, 'Session already migrated'), (32, 'Migrate non-exist session'), (40, 'Move session'), (41, 'Session already moved'), (42, 'Move non-exist session'), (50, 'Auth2 Cluster Not Available'), (101, 'Auth2 Interconnection Timeout'), (102, 'Authentication Too Slow'), (201, 'LB key not match'), (202, 'Domain not match'), (210, 'Session cookie hacked'), (200, 'Error')], default=10),
        ),
    ]
