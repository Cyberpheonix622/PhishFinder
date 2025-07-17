import requests
import time

API_URL = "http://localhost:5000/api/predict"

def test_url(url):
    try:
        response = requests.post(API_URL, json={"url": url}, timeout=5)
        result = response.json()
        print(f"URL: {url}")
        print("Response:", result)
        print("-" * 60)
    except Exception as e:
        print(f"Error testing {url}: {str(e)}")

if __name__ == "__main__":
    test_urls = [
        "https://www.google.com",
        "https://paypal.com-login.verify-user876342.com",
        "http://192.168.1.1/secure/banking",
        "https://amazon.com-giftcard.ru",
        "https://www.microsoft.com",
        "http://login.ebay-accountupdate.com",
        "https://legit-bank.com",
        "https://paypal.secure-login.com"
    ]
    
    for url in test_urls:
        test_url(url)
        time.sleep(0.5)