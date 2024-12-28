from django.db import models

# Create your models here.

class Agente(models.Model):
    # title = models.CharField(max_length=250)
    # category = models.ManyToManyField(Category, related_name="blogs")
    # author = models.ForeignKey(get_user_model(), on_delete=models.CASCADE, related_name="blogs")
    # content = models.TextField()
    # created_at = models.DateTimeField(auto_now_add=True)
    # updated_at = models.DateTimeField(auto_now=True)
    name = models.CharField(max_length=250)
    os = models.CharField(max_length=250)

    def __str__(self):
        return self.name