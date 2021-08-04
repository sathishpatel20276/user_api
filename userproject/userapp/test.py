#from userapp.models import User
from django.test import TestCase,Client
#from django.urls import reverse
#import json
client = Client()

class SignUpPageTests(TestCase):
    def setUp(self):
        pass
    def test_create_valid_userdata(self):
        response = client.get(
            path='/userdata/',
            content_type='application/json')
        self.assertEqual(response.status_code, 200)
    def test_create_valid_userdata_byid(self):
        response = client.get(
            path='/userdata/30000',
            content_type='application/json')
        self.assertEqual(response.status_code, 400)
    def test_create_invalid_userdata(self):
        response = client.post(
            path='/userdata/',
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 405)
# class SignUpPageTests(TestCase):
#     def setUp(self):
#         self.valid_payload = {
#         'email' :'sathishpatel415@gmail.com',
#         'password' : 'sathish123',
#         }
#         self.invalid_payload = {
#         'email' :'',
#         'password' : 'anil123',
#         }
#     def test_create_valid_employee(self):
#         response = client.post(
#             path='/login',
#             data=json.dumps(self.valid_payload),
#             content_type='application/json')
#         self.assertEqual(response.status_code, 200)
#     def test_create_invalid_employee(self):
#         response = client.post(
#             path='/login',
#             data=json.dumps(self.invalid_payload),
#             content_type='application/json'
#         )
#         self.assertEqual(response.status_code, 400)
# class SignUpPageTests(TestCase):
#     def setUp(self):
#         self.valid_payload = {
#         'email' :'anilkumar123@gmail.com',
#         'username' : 'anil123',
#         'password1' : 'anil123',
#         'confirm_password' : 'anil123',
#         'age' : '22',
#         'phone_number' : '+919708515616'
#         }
#         self.invalid_payload = {
#         'email' :'',
#         'username' : 'anil123',
#         'password1' : 'anil123',
#         'confirm_password' : 'anil123',
#         'age' : '22',
#         'phone_number' : '+919708515616'
#         }
#     def test_create_valid_employee(self):
#         response = client.post(
#             path='/register',
#             data=json.dumps(self.valid_payload),
#             content_type='application/json')
#         self.assertEqual(response.status_code, 201)
#     def test_create_invalid_employee(self):
#         response = client.post(
#             path='/register',
#             data=json.dumps(self.invalid_payload),
#             content_type='application/json'
#         )
#         self.assertEqual(response.status_code, 400)



# email = mydata.get("email")
#         username = mydata.get("username")
#         password1 = mydata.get("password1")
#         confirm_password = mydata.get("confirm_password")
#         age = mydata.get("age")
#         phone_number =  mydata.get("phone_number")
    # def test_signup_url1(self):
    #     response = self.client.post("127.0.0.1:8000/register")
    #     self.assertEqual(response.status_code, 404)
    # def test_signup_page_view_name(self):
    #     response = self.client.post(Reversible('http://127.0.0.1:8000/register'))
    #     self.assertEqual(response.status_code, 200)
    # def test_signup_form(self):
    #     response = self.client.post(Reversible('http://127.0.0.1:8000/register'), data={
    #         'email': self.email,
    #         'username': self.username,
    #         'age': self.age,
    #         'email': self.email,
    #         'password': self.password1,
    #         'phone_number': self.phone_number
           
    #     })
    #     self.assertEqual(response.status_code, 200)
    #     users = User.objects.all()
    #     self.assertEqual(users.count(), 1)
