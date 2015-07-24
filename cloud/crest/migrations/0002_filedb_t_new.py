# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('crest', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='filedb',
            name='t_new',
            field=models.CharField(max_length=1000, null=True, verbose_name=b'new t for file'),
        ),
    ]
