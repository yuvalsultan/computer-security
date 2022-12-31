import unittest
from main import app
import requests
from datetime import date



class FlaskTestCase(unittest.TestCase):

    url_json_movies='https://itunes.apple.com/us/rss/topmovies/limit=25/json'
    r=requests.get(url_json_movies)
    info=r.json()
    
    #1 Ensure that flask was set up correctly
    def test_index(self):
        tester=app.test_client(self)
        response=tester.get('/login', content_type='html/text')
        self.assertEqual(response.status_code,200)

    #2 Ensure that the login page loads correctly 
    def test_login_page_loads(self):
        tester=app.test_client(self)
        response=tester.get('/login', content_type='html/text')
        self.assertTrue(b'Login' in response.data)

    #3 Ensure login behaves correctly when given correct details
    def test_correct_login(self):
        tester=app.test_client(self)
        response=tester.post('/login', data=dict(email='yuval.sultan@gmail.com',password='Yy12345'),follow_redirects=True)
        self.assertIn(b'Welcome to your account', response.data)
    
    #4 Ensure login behaves correctly when given incorrect email
    def test_incorrect_email(self):
        tester=app.test_client(self)
        response=tester.post('/login', data=dict(email='wrong',password='wrong'),follow_redirects=True)
        self.assertIn(b'Email does not exist.', response.data)

    #5 Ensure login behaves correctly when given incorrect password
    def test_incorrect_pass(self):
        tester=app.test_client(self)
        response=tester.post('/login', data=dict(email='yuval.sultan@gmail.com',password='wrong'),follow_redirects=True)
        self.assertIn(b'Incorrect password, try again.', response.data)

    #6 Ensure logout behaves correctly
    def test_logout(self):
        tester=app.test_client(self)
        tester.post('/login',data=dict(email='yuval.sultan@gmail.com',password='Yy12345'),follow_redirects=True)
        response=tester.get('/logout',follow_redirects=True)
        self.assertIn(b'Login', response.data)

    #7 Ensure that the main page requires login
    def test_main_route_requires_login(self):
        tester=app.test_client(self)
        response=tester.get('/',follow_redirects=True)
        self.assertIn(b'Please log in to access this page.', response.data)

    #8 Ensure that api request loads correctly
    def test_api_request(self):
        self.assertEqual(self.r.status_code,200)

    #9 Ensure that url link is updated for current year
    def test_url_UpDated(self):
        url_date=self.info['feed']['updated']['label'][0:4]
        curr_year=date.today().year
        self.assertEqual(str(curr_year),url_date)

    #10 Ensure that url link does contain 25 movies 
    def test_url_movie_number(self):
        num_of_movies=len(self.info['feed']['entry'])
        self.assertEqual(num_of_movies,25)


        

        
if __name__ == '__main__':
    unittest.main()