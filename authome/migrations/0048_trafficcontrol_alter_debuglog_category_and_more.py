# Generated by Django 4.2.16 on 2025-02-27 05:59

import authome.models.models
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('authome', '0047_alter_auth2cluster_options_and_more'),
    ]

    operations = [
        migrations.CreateModel(
            name='TrafficControl',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.SlugField(max_length=128, unique=True)),
                ('enabled', models.BooleanField(default=True, help_text='Enable/disable the traffic control')),
                ('active', models.BooleanField(default=False, editable=False)),
                ('est_processtime', models.PositiveIntegerField(default=0, help_text='The estimated processing time(milliseconds) used to calculate the concurrency requests')),
                ('buckettime', models.PositiveIntegerField(default=0, help_text='Declare the time period(milliseconds) of the bucket, the est_processtime and the total milliseconds of one day should be divided by this value.')),
                ('buckets', models.PositiveIntegerField(default=0, editable=False)),
                ('concurrency', models.PositiveIntegerField(default=0)),
                ('iplimit', models.PositiveIntegerField(default=0, help_text='The maximum requests per client ip which can be allowd in configure period')),
                ('iplimitperiod', models.PositiveIntegerField(default=0, help_text='The time period(seconds) configured for requests limit per client ip')),
                ('userlimit', models.PositiveIntegerField(default=0, help_text='The maximum requests per user which can be allowd in configure period')),
                ('userlimitperiod', models.PositiveIntegerField(default=0, help_text='The time period(seconds) configured for requests limit per user')),
                ('modified', models.DateTimeField(auto_now=True, db_index=True)),
                ('created', models.DateTimeField(auto_now_add=True)),
            ],
            options={
                'verbose_name_plural': '         Traffic Control',
            },
            bases=(authome.models.models.CacheableMixin, authome.models.models.DbObjectMixin, models.Model),
        ),
        migrations.AlterField(
            model_name='debuglog',
            name='category',
            field=models.PositiveSmallIntegerField(choices=[(10, 'Create cookie'), (11, 'Update cookie'), (12, 'Delete cookie'), (20, 'Upgrade session'), (21, 'Session already upgraded'), (22, 'Upgrade non-exist session'), (30, 'Migrate session'), (31, 'Session already migrated'), (32, 'Migrate non-exist session'), (40, 'Move session'), (41, 'Session already moved'), (42, 'Move non-exist session'), (50, 'Auth2 Cluster Not Available'), (101, 'Auth2 Interconnection Timeout'), (102, 'Authentication Too Slow'), (201, 'LB key not match'), (202, 'Domain not match'), (210, 'Session cookie hacked'), (300, 'User Traffic Control'), (301, 'IP Traffic Control'), (302, 'Concurrency Traffic Control'), (200, 'Error')], default=10),
        ),
        migrations.CreateModel(
            name='TrafficControlLocation',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('domain', models.CharField(max_length=128)),
                ('method', models.PositiveSmallIntegerField(choices=[(1, 'GET'), (2, 'POST'), (3, 'PUT'), (4, 'DELETE')])),
                ('location', models.CharField(max_length=256)),
                ('modified', models.DateTimeField(auto_now=True, db_index=True)),
                ('created', models.DateTimeField(auto_now_add=True)),
                ('tcontrol', models.ForeignKey(editable=False, on_delete=django.db.models.deletion.CASCADE, to='authome.trafficcontrol')),
            ],
            options={
                'verbose_name_plural': '{}Traffic Control Locations',
                'unique_together': {('domain', 'method', 'location')},
            },
            bases=(authome.models.models.DbObjectMixin, models.Model),
        ),
    ]
