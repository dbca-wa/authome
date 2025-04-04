# Generated by Django 4.2.16 on 2025-03-20 00:01

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('authome', '0049_trafficcontrol_exempt_groups_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='trafficcontrol',
            name='block',
            field=models.BooleanField(default=False, editable=False, help_text='If true, block the request until the running requests are less than the concurrency limit'),
        ),
        migrations.AlterField(
            model_name='debuglog',
            name='category',
            field=models.PositiveSmallIntegerField(choices=[(10, 'Create cookie'), (11, 'Update cookie'), (12, 'Delete cookie'), (20, 'Upgrade session'), (21, 'Session already upgraded'), (22, 'Upgrade non-exist session'), (30, 'Migrate session'), (31, 'Session already migrated'), (32, 'Migrate non-exist session'), (40, 'Move session'), (41, 'Session already moved'), (42, 'Move non-exist session'), (50, 'Auth2 Cluster Not Available'), (101, 'Auth2 Interconnection Timeout'), (102, 'Authentication Too Slow'), (201, 'LB key not match'), (202, 'Domain not match'), (210, 'Session cookie hacked'), (300, 'User Traffic Control'), (301, 'IP Traffic Control'), (302, 'Concurrency Traffic Control'), (399, 'Traffic Control Error'), (200, 'Error')], default=10),
        ),
        migrations.AlterField(
            model_name='trafficcontrol',
            name='exempt_groups',
            field=models.ManyToManyField(blank=True, to='authome.usergroup'),
        ),
    ]
