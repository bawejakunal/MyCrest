# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('crest', '0002_filedb_t_new'),
    ]

    operations = [
        migrations.AddField(
            model_name='filedb',
            name='shared_url',
            field=models.CharField(max_length=1000, null=True, verbose_name=b'shared_url'),
        ),
    ]
