# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='FileDB',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('filePath', models.CharField(max_length=100, verbose_name=b'File Path')),
                ('C0', models.CharField(max_length=1000, verbose_name=b'Public header C0')),
                ('C1', models.CharField(max_length=1000, verbose_name=b'Public header C1')),
                ('OC0', models.CharField(max_length=1000, verbose_name=b'Original Public header C0')),
                ('OC1', models.CharField(max_length=1000, verbose_name=b'Original Public header C1')),
                ('t', models.CharField(max_length=1000, verbose_name=b't for file')),
            ],
        ),
        migrations.CreateModel(
            name='FileShare',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('File', models.ForeignKey(verbose_name=b'File ID', to='crest.FileDB')),
            ],
        ),
        migrations.CreateModel(
            name='Recipient',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('km', models.CharField(default=None, max_length=1000, null=True, verbose_name=b'RSA_gi^gamma')),
            ],
        ),
        migrations.CreateModel(
            name='User',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('email', models.CharField(max_length=100, verbose_name=b'Email Id')),
                ('public_rsa', models.CharField(max_length=1000, verbose_name=b'RSA Public key')),
                ('secret_rsa', models.CharField(max_length=4090, verbose_name=b'RSA Secret key')),
                ('gamma', models.CharField(max_length=1000, null=True, verbose_name=b'User gamma')),
            ],
        ),
        migrations.AddField(
            model_name='recipient',
            name='owner',
            field=models.ForeignKey(related_name='owner', verbose_name=b'Owner', to='crest.User'),
        ),
        migrations.AddField(
            model_name='recipient',
            name='receiver',
            field=models.ForeignKey(related_name='receiver', verbose_name=b'Receiver', to='crest.User'),
        ),
        migrations.AddField(
            model_name='fileshare',
            name='owner',
            field=models.ForeignKey(related_name='crest_fileshare_related', verbose_name=b'Owner ID', to='crest.User'),
        ),
        migrations.AddField(
            model_name='fileshare',
            name='receiver',
            field=models.ForeignKey(verbose_name=b'Receiver ID', to='crest.User'),
        ),
        migrations.AddField(
            model_name='filedb',
            name='owner',
            field=models.ForeignKey(verbose_name=b'Owner ID', to='crest.User'),
        ),
        migrations.AlterUniqueTogether(
            name='recipient',
            unique_together=set([('owner', 'receiver')]),
        ),
        migrations.AlterUniqueTogether(
            name='fileshare',
            unique_together=set([('File', 'owner', 'receiver')]),
        ),
        migrations.AlterUniqueTogether(
            name='filedb',
            unique_together=set([('filePath', 'owner')]),
        ),
    ]
