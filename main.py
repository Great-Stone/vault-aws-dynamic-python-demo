import sys, os
import threading
import requests
import time

import boto3
from botocore.config import Config

def read_secret_id(): # Secret ID 읽기
  vault_secret_id_file = 'secret_id.txt'

  try:
    f = open(vault_secret_id_file, 'r')
  except:
    sys.stderr.write('No file: %s\n' % vault_secret_id_file)
    exit(1)

  while True:
    line = f.readline()
    if not line: break
    secret_id = line
  f.close()

  if secret_id == '':
    sys.stderr.write('secret_id empty\n')
    exit(1)
  
  return secret_id

def set_aws_key(secret_id):
  # Vault 정보
  vault_api = 'http://localhost:8200/v1'
  vault_namespace = 'admin'
  role_id = '6afc8ca9-8af2-9fa7-5848-74cb1ce12513'

  # Vault Login via AppRole
  approle_data = {'role_id': role_id, 'secret_id': secret_id}
  if vault_namespace == '':
    headers = {}
  else:
    headers = {'X-Vault-Namespace': vault_namespace}

  login_response = requests.post(f'{vault_api}/auth/approle/login', headers=headers, data=approle_data)

  if login_response.status_code != 200:
    sys.stderr.write('login fail\n')
    exit(1)

  vault_token = login_response.json()['auth']['client_token']
  headers={'X-Vault-Namespace': vault_namespace, 'X-Vault-Token': vault_token}

  # Get AWS Access Key
  aws_key_ttl = 0
  lease_data = {'lease_id': ''}
  aws_key_ttl_min = 50
  while True:
    if aws_key_ttl < aws_key_ttl_min:
      aws_key_response = requests.get(f'{vault_api}/aws/creds/my-role', headers=headers)
      # print(aws_key_response.json())

      lease_id = aws_key_response.json()['lease_id']
      access_key = aws_key_response.json()['data']['access_key']
      secret_key = aws_key_response.json()['data']['secret_key']
      lease_data = {'lease_id': lease_id}

      os.environ["AWS_ACCESS_KEY_ID"] = access_key
      os.environ["AWS_SECRET_ACCESS_KEY"] = secret_key
    
    lease_response = requests.post(f'{vault_api}/sys/leases/lookup', headers=headers, data=lease_data)
    aws_key_ttl = int(lease_response.json()['data']['ttl'])
    print(f'aws_key_ttl: {aws_key_ttl}', flush=True)
    time.sleep(2)

def check_aws_instances():
  ACCESS_KEY = ''

  while True:
    if ACCESS_KEY is not os.environ.get('AWS_ACCESS_KEY_ID'):
      ACCESS_KEY = os.environ.get('AWS_ACCESS_KEY_ID')
      SECRET_KEY = os.environ.get('AWS_SECRET_ACCESS_KEY')
      print(f'Changed env AWS_ACCESS_KEY_ID={ACCESS_KEY}')
      print(f'Changed env AWS_SECRET_ACCESS_KEY={SECRET_KEY}')

    my_session = boto3.session.Session(
      region_name = 'ap-northeast-2',
      aws_access_key_id = ACCESS_KEY,
      aws_secret_access_key = SECRET_KEY,
      aws_session_token = None, 
      profile_name = 'default')

    print(f'Available services count : {len(my_session.get_available_services())}')
    time.sleep(1)

if __name__ == '__main__':
  secret_id = read_secret_id()

  t = threading.Thread(target=set_aws_key, args=(secret_id,))
  t.start()

  while os.environ.get('AWS_ACCESS_KEY_ID') is None or os.environ.get('AWS_SECRET_ACCESS_KEY') is None:
    time.sleep(1)

  check_aws_instances()