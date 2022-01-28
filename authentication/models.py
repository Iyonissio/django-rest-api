from django.db import models
from helpers.models import TrackingModel
from django.contrib.auth.validators import UnicodeUsernameValidator
from django.contrib.auth.models import (
    PermissionsMixin, UserManager, AbstractBaseUser)
from django.utils.translation import gettext_lazy as _
from django.utils import timezone
import jwt
from datetime import datetime, timedelta


from django.conf import settings

class MyUserManager(UserManager):

    def _create_user(self, username, email, password, **extra_fields):
        """
        Crie e salve um usuário com o nome de usuário, e-mail e senha fornecidos.
        """
        if not username:
            raise ValueError('O nome de usuário fornecido deve ser definido')

        if not email:
            raise ValueError('O e-mail fornecido deve ser definido')

        email = self.normalize_email(email)
        username = self.model.normalize_username(username)
        user = self.model(username=username, email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_user(self, username, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', False)
        extra_fields.setdefault('is_superuser', False)
        return self._create_user(username, email, password, **extra_fields)

    def create_superuser(self, username, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')

        return self._create_user(username, email, password, **extra_fields)


class User(AbstractBaseUser, PermissionsMixin, TrackingModel):
    """
    Uma classe base abstrata que implementa um modelo de usuário completo com
    permissões compatíveis com administrador.

    Nome de usuário e senha são necessários. Outros campos são opcionais.
    """
    username_validator = UnicodeUsernameValidator()

    username = models.CharField(_('username'), max_length=150, unique=True, help_text=_(
        'Requeridos. 150 caracteres ou menos. Apenas letras, dígitos e @/./+/-/_.'),
        validators=[username_validator],
        error_messages={
            'unique': _("Um usuário com esse nome já existe."),
        },
    )
    email = models.EmailField(_('email address'), blank=False, unique=True)
    #Verificar permissoes etc/ metodos por melhorar
    is_staff = models.BooleanField(
        _('staff status'),
        default=False,
        help_text=_(
            'Designates whether the user can log into this admin site.'),
    )
    is_active = models.BooleanField(
        _('active'),
        default=True,
        help_text=_(
            'Designates whether this user should be treated as active. '
            'Unselect this instead of deleting accounts.'
        ),
    )
    date_joined = models.DateTimeField(_('date joined'), default=timezone.now)
    email_verified = models.BooleanField(
        _('email_verified'),
        default=False,
        help_text=_(
            'Designates whether this users email is verified. '

        ),
    )
    objects = MyUserManager()

    EMAIL_FIELD = 'email'
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']

    @property
    def token(self):
        token = jwt.encode(
            {'username': self.username, 'email': self.email,
                'exp': datetime.utcnow() + timedelta(hours=24)},
            settings.SECRET_KEY, algorithm='HS256')

        return token
