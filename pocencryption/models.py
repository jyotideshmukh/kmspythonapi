from django.db import models

# Create your models here.
class Datakeys(models.Model):
    data_key = models.BinaryField()
    country_id = models.CharField(max_length=2)
    pub_date = models.DateTimeField('date published')

    def __str__(self):
        return self.data_key
