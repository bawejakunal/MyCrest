from django.db import models

# Create your models here.
MAX_ELEMENT_LEN = 1000
MAX_ID_LEN = 100
MAX_RSA_PUB_KEY = 1000
MAX_RSA_SEC_KEY = 4090

#Table to store the user data for the use of computational cloud
class User(models.Model):
    email = models.CharField("Email Id", max_length=MAX_ID_LEN)
    public_rsa = models.CharField("RSA Public key", max_length=MAX_RSA_PUB_KEY)
    secret_rsa = models.CharField("RSA Secret key", max_length=MAX_RSA_SEC_KEY)
    gamma = models.CharField("User gamma",max_length=MAX_ELEMENT_LEN,null=True)
    # gi = models.CharField("Public key component gi", max_length=MAX_ELEMENT_LEN)

    def __unicode__(self):
        return unicode(self.email)

class Recipient(models.Model):
    owner = models.ForeignKey(User, related_name='owner', verbose_name="Owner", null=False, blank=False)
    receiver = models.ForeignKey(User, related_name='receiver', verbose_name="Receiver", null=False, blank=False)
    km = models.CharField("RSA_gi^gamma", max_length=MAX_ELEMENT_LEN, default=None, null=True)

    class Meta:
        unique_together = ('owner', 'receiver')

    def __unicode__(self):
        return unicode(unicode(self.owner) + " shared to " + unicode(self.receiver))

#This table contains the file encryption metada mentioned in section 5.2 in CREST paper
class FileDB(models.Model):
    filePath = models.CharField("File Path", max_length=MAX_ID_LEN)
    owner = models.ForeignKey(User, verbose_name="Owner ID", null=False, blank=False)
    
    C0 = models.CharField("Public header C0", max_length=MAX_ELEMENT_LEN)
    C1 = models.CharField("Public header C1", max_length=MAX_ELEMENT_LEN)
    OC0 = models.CharField("Original Public header C0", max_length=MAX_ELEMENT_LEN)
    OC1 = models.CharField("Original Public header C1", max_length=MAX_ELEMENT_LEN)
    t = models.CharField("t for file", max_length=MAX_ELEMENT_LEN);

    class Meta:
        unique_together = ('filePath', 'owner')

    def __unicode__(self):
        return unicode("File Path: ") + unicode(self.filePath)

#Table to store data of shared files
class FileShare(models.Model):
    File = models.ForeignKey(FileDB, verbose_name="File ID", null=False, blank=False)
    owner = models.ForeignKey(User, related_name="%(app_label)s_%(class)s_related", verbose_name="Owner ID", null=False, blank=False)
    receiver = models.ForeignKey(User, verbose_name="Receiver ID", null=False, blank=False)

    class Meta:
        unique_together = ('File','owner','receiver')