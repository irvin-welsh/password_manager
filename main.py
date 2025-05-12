import random, string, json, os

storage = {}
account_name = input(str('Type your account URL: '))

length = int(input('How many symbols you want in your password? Enter only digits... '))
random_string = ''.join(random.choices(string.ascii_letters + string.digits + string.punctuation, k=length))

storage = {
    'account' : {
        'account name' : account_name,
        'password' : random_string
    }
}

if os.path.exists('passwords.json') and os.path.getsize('passwords.json') > 0:
    with open('passwords.json', 'r+', encoding='utf-8') as f:
        data = json.load(f)
        if isinstance(data, list):
            data.append(storage)
        else:
            data = [data, storage]
        f.seek(0)
        json.dump(data, f, indent=4, ensure_ascii=False)
        f.truncate()
else:
    with open('passwords.json', 'w', encoding='utf-8') as f:
        json.dump([storage], f, indent=4, ensure_ascii=False)
