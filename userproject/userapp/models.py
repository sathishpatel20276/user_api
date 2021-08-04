from django.db import models
from django.contrib.auth.models import AbstractUser

# Create your models here.
CHOICES = (('Registered','Registered'),('Activated','Activated'),
('Updated','Updated'),('Deleted','Deleted'))
class User(AbstractUser):
    '''user data table'''
    username = models.CharField(max_length=50,unique=True)
    email = models.EmailField(max_length=254,unique=True)
    password = models.CharField(max_length=250)
    age = models.IntegerField(default=0)
    phone_number = models.CharField(max_length=25,default=0)
    is_flag =models.CharField(max_length = 50, choices = CHOICES, default = 'Registered')
    is_active=models.BooleanField(default=True)

    def __str__(self):
        '''to show user object as a email'''
        return self.email
