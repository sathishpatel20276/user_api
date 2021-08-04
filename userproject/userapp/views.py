import json
import logging
import six
from django.contrib.auth import get_user_model
from django.contrib.sites.shortcuts import get_current_site
from django.utils.encoding import force_bytes, force_text
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.auth import authenticate
from django.core.mail import EmailMessage
from django.urls import reverse
from django.db.models.query_utils import Q
from django.contrib.auth.models import  User, auth
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.hashers import make_password
from django.contrib.auth.decorators import login_required
from .models import User
from .tokens import account_activation_token,password_reset_token
from django.contrib.auth import authenticate
from django.views.decorators.csrf import csrf_exempt
from rest_framework.authtoken.models import Token
from rest_framework.decorators import  permission_classes
from rest_framework.permissions import AllowAny
from rest_framework_jwt.settings import api_settings
from django.contrib.auth.models import update_last_login


JWT_PAYLOAD_HANDLER = api_settings.JWT_PAYLOAD_HANDLER
JWT_ENCODE_HANDLER = api_settings.JWT_ENCODE_HANDLER

logger = logging.getLogger('django')

# Create your views here.
def userdata(request, pk=None):
    '''to get user data list ,to fetch data by id or all data'''
    logger.info("entered into userdata function")
    if request.method == 'GET':
        if pk is None:
            data=list(User.objects.values())
            if data == []:
                logger.info("you have'nt created any user")
                data="you have'nt created any user"
                return JsonResponse(data,safe = False,status=200)
            else:
                logger.info('user data ')
                return JsonResponse(data,safe = False,status=200)
        elif User.objects.filter(id=pk).exists():
            data = list(User.objects.filter(id=pk).values())
            logger.info('user data with id')
            return JsonResponse(data,safe = False,status=200)
        else:
            data="No data found or invalid id"
            logger.error('No data found or invalid id')
            return JsonResponse(data,safe = False,status=400)
    else:
        data="method not allowed"
        logger.error('method not allowed')
        return JsonResponse(data,safe = False,status=405)

@csrf_exempt
def register(request):
    '''to register into a application reqired fields are email(uinque),\
        username(unique),password,confirm passwrod, age,phone number and sends\
        email along with registartion active link'''
    logger.info("entered into registration function")
    if request.method == 'POST':
        # postman raw
        mydata =json.loads(request.body)
        email = mydata.get("email")
        username = mydata.get("username")
        password1 = mydata.get("password1")
        confirm_password = mydata.get("confirm_password")
        age = mydata.get("age")
        phone_number =  mydata.get("phone_number")
        #print(email,username,password1,confirm_password,age,phone_number)
        valid_email = None
        try:
            validate_email(email)
            valid_email = True
        except ValidationError as error:
            valid_email = False
        if not mydata:
            data="Expected json data was missing"
            logger.error('json data was missing empty data')
            return JsonResponse(data,safe=False,status=400)
        elif email is None:
            data="Expected email field was missing"
            logger.error('email field was missing')
            return JsonResponse(data,safe=False,status=400)
        elif  username is  None:
            data="Expected username field was missing"
            logger.error('username field was missing')
            return JsonResponse(data,safe=False,status=400)
        elif password1 is  None:
            data="Expected password field was missing"
            logger.error('password field was missing')
            return JsonResponse(data,safe=False,status=400)
        elif confirm_password is  None:
            data="Expected confirm_password field was missing"
            logger.error('confirm password field was missing')
            return JsonResponse(data,safe=False,status=400)
        elif age is None:
            data="Expected age field was missing"
            logger.error('age field was missing')
            return JsonResponse(data,safe=False,status=400)
        elif phone_number is  None:
            data="Expected phone_number field was missing"
            logger.error('phone number field was missing')
            return JsonResponse(data,safe=False,status=400)
        elif email in ("",False) or valid_email is not True :
            data="enter a valid email"
            logger.error('enter a valid email')
            return JsonResponse(data,safe=False,status=400)
        elif email.split('@')[1] not in ["gmail.com", "yahoo.com", "outlook.com",]:
            data="Please enter an Email Address with a valid domain"
            logger.error('Please enter an Email Address with a valid domain')
            return JsonResponse(data,safe=False,status=400)
        elif username in ("",False) :
            data="enter a valid username "
            logger.error('enter valid username')
            return JsonResponse(data,safe=False,status=400)
        elif age in ("",False) or type(age)==str or age not in range(18,131):
            data="enter a valid age "
            logger.error('enter valid age ')
            return JsonResponse(data,safe=False,status=400)
        elif len(str(phone_number)) !=13 or phone_number in ("",False) :
            data="enter a valid phone number  "
            logger.error('enter valid phone  number ')
            return JsonResponse(data,safe=False,status=400)
        elif phone_number[0:4] not in ["+916","+917","+918","+919"]:
            data="enter a valid indian phone number  "
            logger.error('enter a valid indian phone number ')
            return JsonResponse(data,safe=False,status=400)
        elif password1  in ("",False) or confirm_password in ("",False) or len(password1)<6:
            data="enter a valid password or password length should be above 6"
            logger.error('enter a valid password')
            return JsonResponse(data,safe=False,status=400)
        elif password1==confirm_password:
            if User.objects.filter(email=email).exists():
                data='Email already Taken'
                logger.warning('Email already Taken ')
                return JsonResponse(data,safe=False,status=400)
            elif User.objects.filter(username=username).exists():
                data='username already Taken'
                logger.warning('username already Taken ')
                return JsonResponse(data,safe=False,status=400)
            elif User.objects.filter(phone_number=phone_number).exists():
                data='phone number already Taken'
                logger.warning('phone number already Taken ')
                return JsonResponse(data,safe=False,status=400)
            else:
                try:
                    user = User(email=email, username=username,
                    password =password1,age=age,phone_number=phone_number)
                    user.password = make_password(password1)
                    user.is_active = False
                    user.save()
                    uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
                    domain = get_current_site(request).domain
                    link=reverse(
                        'activate',kwargs={
                        'uidb64':uidb64, 'token':account_activation_token.make_token(user)
                        }
                        )
                    mail_subject = 'Activate your blog account.'
                    activate_url= 'http://'+domain+link
                    message = 'Hi ' + user.username + 'Please use this link \
                    to verify your account\n' + activate_url
                    to_email = email
                    email = EmailMessage(
                                mail_subject, message, to=[to_email]
                    )
                    email.send(fail_silently=False)
                    
                    data = 'Please confirm your email address to complete the registration'
                    logger.info('Please confirm your email address to complete the registration')
                    return JsonResponse(data,safe=False,status=201)
                except Exception as error:
                    user.delete()
                    data = 'something went wrong unable to send a mail: {error}'
                    logger.critical('something went wrong unable to send a mail:\n %s',error)
                    return JsonResponse(data,safe=False,status=201)
        else:
            data='Password is Not Matching '
            logger.error('Password is Not Matching ')
            return JsonResponse(data,safe=False,status=400)
    else:
        data="method not allowed"
        logger.error("method not allowed")
        return JsonResponse(data,safe = False,status=405)

def activate(request, uidb64, token):
    '''To activate or to validate user registration  link and also \
        detated or decativated user account activation'''
    logger.info("entered into activation function")
    User = get_user_model()
    try:
        uid = force_text(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except(TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None
    if user is not None and account_activation_token.check_token(user, token):
        try:
            user.is_active = True
            user.is_flag = "Activated"
            user.save()
            data = "Account is activated"
            logger.info("Account is activated")
            return JsonResponse(data,safe=False,status=200)
        except Exception as error:
            data = "something went wrong:{error}"
            logger.error("something went wrong:%s",error)
            return JsonResponse(data,safe=False,status=400)
    else:
        data = "Activation link is invalid"
        logger.error("Activation link is invalid")
        return JsonResponse(data,safe=False,status=405)

@csrf_exempt
@permission_classes((AllowAny))
def login(request):
    '''To login in to application using email and password'''
    logger.info("entered into login function")
    if request.method == 'POST':
        mydata =json.loads(request.body)
        email = mydata.get('email')
        password = mydata.get('password')
        if not mydata:
            data="Expected json data was missing"
            logger.error("json data was missing")
            return JsonResponse(data,safe=False,status=400)
        elif email is None and password is not None :
            data="Expected email field was missing "
            logger.error("email field was missing")
            return JsonResponse(data,safe=False,status=400)
        elif email is not None and password is  None :
            data="Expected password field was missing "
            logger.error(" password field was missing")
            return JsonResponse(data,safe=False,status=400)
        elif email in ("",False):
            data="enter a valid email "
            logger.error("enter a valid email")
            return JsonResponse(data,safe=False,status=400)
        elif User.objects.filter(email=email).exists() :
            try:
                username= User.objects.get(email=email).username
                user = authenticate(username=username, password=password)
                is_active =  User.objects.get(email=email).is_active
                if is_active is False:
                    data = "Account is deleted, or  Deactivated .if you want to \
                        activate ur accout use this link 'http://127.0.0.1:8000/account_activate'"
                    logger.info("Account is deleted, or  Deactivated")
                    return JsonResponse(data,safe=False,status=400)
                elif user is not None:
                    auth.login(request, user)
                    try:
                        payload = JWT_PAYLOAD_HANDLER(user)
                        jwt_token = JWT_ENCODE_HANDLER(payload)
                        update_last_login(None, user)
                        data = f"welcome {username}"
                        logger.info("%s is loged in successfully",username)
                        #return JsonResponse(data,safe=False,status=200)
                        return JsonResponse({'token': jwt_token},safe=False,status=200)
                    except User.DoesNotExist:
                        data = "something went wrong"
                        logger.error("something went wrong")
                        return JsonResponse(data,safe=False,status=400)  
            
                else:
                    data = "Account doesn't exist, Please Sign Up"
                    logger.warning("Account doesn't exist, Please Sign Up")
                    return JsonResponse(data,safe=False,status=400)
            except Exception as error:
                data = "something went wrong:{error}"
                logger.error("something went wrong:%s",error)
                return JsonResponse(data,safe=False,status=400)
        else:
            data="Invalid email or Password"
            logger.warning("Invalid email or Password")
            return JsonResponse(data,safe = False,status=400)
    else:
        data="method not allowed"
        logger.error("method not allowed")
        return JsonResponse(data,safe = False,status=405)

@csrf_exempt
def logout(request):
    '''To log out from application'''
    logger.info("entered into logout function")
    if request.method == 'GET':
        auth.logout(request)
        data = "Successfully Logged Out"
        logger.info("Successfully Logged Out" )
        return JsonResponse(data,safe=False,status=200)
    else:
        data="method not allowed"
        logger.error("method not allowed")
        return JsonResponse(data,safe = False,status=405)

@csrf_exempt
#@login_required
def changepassword(request):
    '''To change existing user password '''
    logger.info("entered into change password function")
    if request.method == 'PUT':
        mydata =json.loads(request.body)
        current_user = request.user
        password =  mydata.get('old_password')
        new_password =  mydata.get('new_password')
        confirm_password =  mydata.get('confirm_password')
        username= User.objects.get(email=current_user).username
        user = User.objects.get(username = username)
        if not mydata:
            data="Expected json data was missing"
            logger.error("json data was missing")
            return JsonResponse(data,safe=False,status=400)
        elif password is None:
            data="Expected old password fiels  was missing"
            logger.error("old password fiels  was missing")
            return JsonResponse(data,safe=False,status=400)
        elif new_password is  None:
            data="Expected new password fiels  was missing"
            logger.error("new password fiels  was missing")
            return JsonResponse(data,safe=False,status=400)
        elif confirm_password is  None:
            data="Expected confirm password fiels  was missing"
            logger.error("confirm password fiels  was missing")
            return JsonResponse(data,safe=False,status=400)
        elif password in ("",False):
            data="enter a valid old password"
            logger.warning("enter a valid old password")
            return JsonResponse(data,safe=False,status=400)
        elif new_password in ("",False) or len(new_password)<5:
            data="enter a valid password"
            logger.warning("enter a valid password")
            return JsonResponse(data,safe=False,status=400)
        elif username:
            if  authenticate(request, username = username, password = password):
                if new_password == confirm_password:
                    try:
                        user.set_password(new_password)
                        user.is_flag = 'Updated'
                        user.save()
                        data = "Your Password is successfully changed!!!"
                        logger.info("%s Password is successfully changed!!!",username)
                        return JsonResponse(data,safe=False,status=200)
                    except Exception as error:
                        data = "something went wrong:{error}"
                        logger.error("something went wrong:%s",error)
                        return JsonResponse(data,safe=False,status=400)
                else:
                    data =  "New and confirm paddword do not match"
                    logger.warning("New and confirm paddword do not match")
                    return JsonResponse(data,safe=False,status=400)
            else:
                data = "invalid old password"
                logger.warning("invalid old password")
                return JsonResponse(data,safe=False,status=400)
        else:
            data = "There is an error!!!"
            logger.warning("There is an error!!!")
            return JsonResponse(data,safe=False,status=400)
    else:
        data = "Metod is not allowed"
        logger.error("Metod is not allowed")
        return JsonResponse(data,safe=False,status=405)

@csrf_exempt
def deluser(request, username):
    '''To delete or deactivate existing user'''
    logger.info("entered into delete user function")
    if request.method == 'DELETE':
        try:
            user = User.objects.get(username = username)
            if  user.is_active is not False:
                user.is_active = False
                user.is_flag = 'Deleted'
                user.save()
                data = "The user is deleted"
                logger.info("%s is deleted successfully",username)
                return JsonResponse(data,safe=False,status=200)
            else:
                data="User is already deleted"
                logger.warning("user is already deletd")
                return JsonResponse(data,safe=False,status=400)

        except Exception as error:
            data = "something went wrong {error}"
            logger.error("something went wrong %s",error)
            return JsonResponse(data,safe=False,status=400)
    else:
        data="method not allowed"
        logger.error("method not allowed" )
        return JsonResponse(data,safe = False,status=405)

@csrf_exempt
def resetpassword(request):
    '''To reset existing user password by sending reset password(forgot password) link in mail '''
    logger.info("entered into reset password function")
    if request.method == "POST":
        mydata =json.loads(request.body)
        email=mydata.get('email')
        valid_email = None
        try:
            validate_email(email)
            valid_email = True
        except ValidationError as error:
            valid_email = False
        if not mydata:
            data="Expected json data was missing"
            logger.error("json data was missing")
            return JsonResponse(data,safe=False,status=400)
        elif email in ("",False) or valid_email is not True :
            data="enter a valid email"
            logger.error("enter a valid email")
            return JsonResponse(data,safe=False,status=400)
        if email:
            try:
                is_active =  User.objects.get(email=email).is_active
                associated_users = User.objects.filter(Q(email=email))
                if is_active is False:
                    data = "your account is deactivated to activate your account \
                        use this link 'http://127.0.0.1:8000/account_activate'"
                    logger.warning("your account is deactivated to activate your \
                         account use this link 'http://127.0.0.1:8000/account_activate'")
                    return JsonResponse(data,safe=False,status=200)
                elif associated_users.exists():
                    for user in associated_users:
                        uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
                        domain = get_current_site(request).domain
                        link = reverse('activate1',kwargs={'uidb64':uidb64,
                             'token':password_reset_token.make_token(user)})
                        mail_subject = 'Reset your Password.'
                        activate_url= 'http://'+ domain + link
                        message = 'Hi ' + user.username + 'Please use this link \
                        to reset your password\n' + activate_url
                        to_email = email
                        email = EmailMessage(
                                    mail_subject, message, to=[to_email]
                        )
                        email.send(fail_silently=False)
                        data = 'Please confirm your email address to Reset your password'
                        logger.info('hi %s Please confirm your email address \
                        to Reset your password',email)
                        return JsonResponse(data,safe=False,status=200)
                else:
                    data = "Thare is no active user associated with this email"
                    logger.error("Thare is no active user associated with this email")
                    return JsonResponse(data,safe=False,status=400)
            except Exception as error:
                data = "something went wrong:{error}"
                logger.error("something went wrong:%s",error)
                return JsonResponse(data,safe=False,status=400)
        else:
            data = "Email is not valid"
            logger.warning("Email is not valid" )
            return JsonResponse(data,safe=False,status=400)
    else:
        data = "method is not valid"
        logger.error("method is not valid" )
        return JsonResponse(data,safe=False,status=405)

@csrf_exempt
def activate1(request, uidb64, token):
    '''To activate or validate the reset password (forgot password) link \
         and updating password set by the valid user'''
    logger.info("entered into reset password activation function")
    User = get_user_model()
    try:
        uid = force_text(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except(TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None
    if user is not None and password_reset_token.check_token(user, token):
        if request.method ==  "PUT":
            mydata =json.loads(request.body)
            new_password=mydata.get('new_password')
            confirm_password=mydata.get('confirm_password')
            if not mydata:
                data="Expected json data was missing"
                logger.error(" json data was missing")
                return JsonResponse(data,safe=False,status=400)
            elif new_password is None and confirm_password is not None:
                data="Expected new password fiels  was missing"
                logger.error(" new password fiels  was missing")
                return JsonResponse(data,safe=False,status=400)
            elif new_password is not None and confirm_password is None:
                data="Expected confirm password fiels  was missing"
                logger.error("confirm password fiels  was missing")
                return JsonResponse(data,safe=False,status=400)
            elif new_password in ("",False) or len(new_password)<5:
                data="enter a valid password"
                logger.warning("enter a valid password")
                return JsonResponse(data,safe=False,status=400)
            elif new_password is not None:
                if new_password == confirm_password:
                    try:
                        user.is_active = True
                        user.set_password(new_password)
                        user.save()
                        data = "Password is changed"
                        logger.info("%s Password is changed",user)
                        return JsonResponse(data,safe=False,status=200)
                    except Exception as error:
                        data = "something went wrong:{error}"
                        logger.error("something went wrong:%s",error)
                        return JsonResponse(data,safe=False,status=400)
                else:
                    data= 'The passwords do not match'
                    logger.warning('The passwords do not match')
                    return JsonResponse(data,safe=False,status=400)
            else:
                data = "Password is improper!!!"
                logger.error("Password is improper!!!")
                return JsonResponse(data,safe=False,status=400)
        else:
            data = "method is not valid"
            logger.error("method is not valid" )
            return JsonResponse(data,safe=False,status=405)
    else:
        data = "There is a problem occur."
        logger.warning("There is a problem occur.")
        return JsonResponse(data,safe=False,status=405)

@csrf_exempt
def account_activate(request):
    '''To activate the account of deactivated or delated user who are existed \
        in the user table by sending activaion link in mail'''
    logger.info("entered into delayed user acount activation function")
    if request.method == "POST":
        mydata =json.loads(request.body)
        email=mydata.get('email')
        valid_email = None
        try:
            validate_email(email)
            valid_email = True
        except ValidationError as error:
            valid_email = False
        if not mydata:
            data="Expected json data was missing"
            logger.error("json data was missing")
            return JsonResponse(data,safe=False,status=400)
        elif email in ("",False) or valid_email is not True :
            data="enter a valid email"
            logger.error("enter a valid email")
            return JsonResponse(data,safe=False,status=400)
        elif User.objects.filter(email=email).exists():
            is_active =  User.objects.get(email=email).is_active
            if is_active is True:
                data = "Account is already in active"
                logger.warning("Account is already in active")
                return JsonResponse(data,safe=False,status=400)
            else:
                try:
                    associated_users = User.objects.filter(Q(email=email))
                    if associated_users.exists():
                        for user in associated_users:
                            uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
                            domain = get_current_site(request).domain
                            link=reverse(
                                'activate',kwargs={
                                'uidb64':uidb64, 'token':account_activation_token.make_token(user)
                                }
                                )
                            mail_subject = 'Activate your blog account.'
                            activate_url= 'http://'+domain+link
                            message = 'Hi ' + user.username + 'Please use this link \
                            to verify your account\n' + activate_url
                            to_email = email
                            email = EmailMessage(
                                        mail_subject, message, to=[to_email]
                            )
                            email.send(fail_silently=False)
                            data = 'Please confirm your email address to complete the \
                                 reactivating of your account'
                            logger.info('%s Please confirm your email address to complete \
                                 the reactivating of your account',email)
                            return JsonResponse(data,safe=False,status=200)
                    else:
                        data = "Reset Password link is not valid"
                        logger.error("Reset Password link is not valid")
                        return JsonResponse(data,safe=False,status=400)
                except Exception as error:
                    data = "something went wrong:{error}"
                    logger.error("something went wrong:%s",error)
                    return JsonResponse(data,safe=False,status=400)
        else:
            data="enter a valid email"
            logger.warning("enter a valid email")
            return JsonResponse(data,safe=False,status=400)
    else:
        data = "method not allowed"
        logger.error("method not allowed")
        return JsonResponse(data,safe=False,status=405)

