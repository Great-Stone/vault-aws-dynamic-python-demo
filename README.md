# AWS Cloud Credential 적용 코드 샘플 -  Python

> Vault 1.11.4
> AWS 기준  
> Python 3.9
> Windows/Mac  

## 1. Vault 실행

- `-dev` : 개발 모드로 실행
- `-dev-root-token-id` : 루트 토큰 지정
- 실행 파일은 `bin` 디렉토리에 다운로드 및 압축 해제
- 다운로드는 <https://releases.hashicorp.com/vault/1.11.4/> 에서 해당하는 OS와 CPU아키텍처에 해당하는 파일

### Windows

```powershell
bin/vault.exe server -dev -dev-root-token-id=root
```

### Mac

```bash
bin/vault server -dev -dev-root-token-id=root
```

## 2. Vault CLI를 위한 환경변수 선언

- 서버를 실행한 창과 다른 창에서 실행

### Windows

```powershell
PowerShell:
  $env:VAULT_ADDR="http://127.0.0.1:8200"
  $env:VAULT_TOKEN="root"
cmd.exe:
  set VAULT_ADDR=http://127.0.0.1:8200
  set VAULT_TOKEN=root
```

### Mac

```bash
export VAULT_ADDR=http://127.0.0.1:8200
export VAULT_TOKEN=root
```

### 확인 방법

```bash
$ vault status
Key             Value
---             -----
Seal Type       shamir
Initialized     true
Sealed          false
Total Shares    1
Threshold       1
Version         1.11.4
Build Date      2022-09-23T06:01:14Z
Storage Type    inmem
Cluster Name    vault-cluster-1e38de83
Cluster ID      24cda801-dfc8-37b1-2da0-945a3f159b6a
HA Enabled      false
```

## 3. AWS에서 Vault가 사용할 정책 생성 

1. https://console.aws.amazon.com/iam/에서 IAM 콘솔을 엽니다.
2. 탐색 메뉴에서 **정책**를 선택합니다.
3. **정책 생성**을 버튼을 클릭합니다.
4. `JSON` 탭에 다음의 정책을 입력합니다.
  - 아래 JSON에 `<account_id>`에 해당 Account의 아이디 숫자 입력
  ```json
  {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Action": [
          "iam:AttachUserPolicy",
          "iam:CreateAccessKey",
          "iam:CreateUser",
          "iam:DeleteAccessKey",
          "iam:DeleteUser",
          "iam:DeleteUserPolicy",
          "iam:DetachUserPolicy",
          "iam:GetUser",
          "iam:ListAccessKeys",
          "iam:ListAttachedUserPolicies",
          "iam:ListGroupsForUser",
          "iam:ListUserPolicies",
          "iam:PutUserPolicy",
          "iam:AddUserToGroup",
          "iam:RemoveUserFromGroup"
        ],
        "Resource": ["arn:aws:iam::<account_id>:user/vault-*"]
      },
      {
        "Effect": "Allow",
        "Action": [
          "iam:AddUserToGroup",
          "iam:RemoveUserFromGroup",
          "iam:GetGroup"
        ],
        "Resource": ["arn:aws:iam::<account_id>:group/*"]
      }
    ]
  }
  ```
  - **다음: 태크**, **다음: 검토** 버튼을 클릭
6. **정책 생성**에서 다음과 같이 설정하고 정책을 생성을 완료 합니다.
  - 이름 : vault-root

## 4. AWS에서 Vault가 사용할 Key 생성

테라폼으로 AWS를 프로비저닝하기 위해서 가입된 계정의 API를 위한 자격증명 정보가 필요합니다. AWS의 계정 액세스 키 ID(Access Key ID)와 보안 액세스 키(Secret Access Key)를 받는 가이드에 따라 아래의 과정을 참고하여 테라폼에서 사용할 자격증명을 취득합니다.

> AWS 계정 및 액세스 키 : https://docs.aws.amazon.com/ko_kr/powershell/latest/userguide/pstools-appendix-sign-up.html

1. https://console.aws.amazon.com/iam/에서 IAM 콘솔을 엽니다.
2. 탐색 메뉴에서 **사용자**를 선택합니다.
3. [**사용자 추가**]을 버튼을 클릭합니다.
4. **사용자 추가**항목에서 다음을 입력합니다.
  - 사용자 이름 : vault-root
  - AWS 자격 증명 유형 선택 : 액세스 키 방식에 체크
5. **권한 설정**에서 **기존 정책 직접 연결**을 선택하고 `vault-root` 를 검색하여 체크하고 [**다음: 태그**] 버튼으로 진행합니다.
6. [**다음: 검토**] 버튼으로 진행합니다.
7. [**사용자 만들기**] 버튼으로 진행합니다.
8. 생성된 사용자의 **요약**에서 **보안 자격 증명** 탭으로 이동합니다.
9. [**액세스 키 생성**] 버튼을 클릭합니다.
10. 새 액세스 키를 보려면 [**Show**]를 선택합니다. 자격 증명은 다음과 같을 것입니다.
   - 액세스 키 ID: `AKIAIOSFODNN7EXAMPLE`
   - 보안 액세스 키: `wJalrXUt******************XAMPLEKEY`
11. 키 페어 파일을 다운로드하려면 [**Download .csv file**]을 선택합니다. 안전한 위치에 키와 함께 .csv 파일을 저장합니다.

## 5. AWS Secret Engine 활성화

해당 작업은 UI에서도 진행 가능합니다.

### aws 엔진 활성화

```bash
vault secrets enable aws
```

### aws root account 설정

```bash
vault write aws/config/root access_key=AKIAIOSFODNN7EXAMPLE secret_key=wJalrXUt******************XAMPLEKEY region=ap-northeast-2
```

## aws root key rotation

Vault에 등록한 Root 엑세스 키를 사람이 알수 없도록 회전 시킵니다.

```bash
$ vault write -f aws/config/rotate-root
Key           Value
---           -----
access_key    AKIA3ALIVABCDG5XC8H4
```


## 6. AWS Secret Role 생성

Vault에서 관리하는 AWS 엑세스 키를 구성합니다.
해당 작업은 UI에서도 진행 가능합니다.

생성할 엑세스 키의 권한을 정의하는 `policy.json` 파일을 생성합니다.
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:*"
      ],
      "Resource": "*"
    }
  ]
}
```

생성한 정책 파일로 `iam_user` 방식의 role을 생성합니다.

```bash
vault write aws/roles/my-role credential_type=iam_user policy_document=policy.json
```

발급은 다음과 같이 수행합니다.

```bash
$ vault read aws/creds/my-role
Key                Value
---                -----
lease_id           aws/creds/my-role/f3e92392-7d9c-09c8-c921-575d62fe80d8
lease_duration     768h
lease_renewable    true
access_key         AKIAIOSFODNN7EXAMPLE
secret_key         wJalrXUt******************XAMPLEKEY
security_token     <nil>
```

발급된 엑세스 키 유효시간을 확인합니다.

```bash
$ vault lease lookup aws/creds/my-role/f3e92392-7d9c-09c8-c921-575d62fe80d8
Key             Value
---             -----
expire_time     2022-10-07T06:19:07.986297118Z
id              aws/creds/my-role/yBRGG4uHur4ExQ6X5RJT4Qa3.B4qAX
issue_time      2022-10-07T06:18:07.986296888Z
last_renewal    <nil>
renewable       true
ttl             33s
```

## 7. AppRole 구성

애플리케이션이 사용할 AppRole 인증 및 정책을 구성합니다.
UI에서 적용 가능합니다.

### Vault 정책 생성

Vault 정책 파일 `aws-my-role-policy.hcl`을 다음과 같이 생성합니다. 정책에 구성되는 내용은 다음과 같습니다. :
- AWS 엔진의 특정 Role에서 키생성
- Lease 조회

```hcl
path "aws/creds/my-role" {
  capabilities = ["read"]
}

path "sys/lease" {
  capabilities = ["read"]
}
```

정책을 다음과 같이 적용합니다.
```bash
vault policy write aws-my-role-policy aws-my-role-policy.hcl
```

정책 테스트를 위한 임시 토큰을 발급합니다.

```bash
$ vault token create -policy=aws-my-role-policy
Key                  Value
---                  -----
token                hvs.CAESIBY******************************Q_NqgAQ
token_accessor       jDg8sm9brQENMuNefiT76Ble.B4qAX
token_duration       1h
token_renewable      true
token_policies       ["aws-my-role-policy" "default"]
identity_policies    []
policies             ["aws-my-role-policy" "default"]
```

테스트를 위해 새창에서 다음과 같이 환경 변수를 구성합니다.

- 서버를 실행한 창과 다른 창에서 실행
- `VAULT_TOKEN`에 발급한 토큰 값을 입력

**Windows**
```powershell
PowerShell:
  $env:VAULT_ADDR="http://127.0.0.1:8200"
  $env:VAULT_TOKEN="hvs.CAESIBYyvDO******************************NqgAQ"
cmd.exe:
  set VAULT_ADDR=http://127.0.0.1:8200
  set VAULT_TOKEN=hvs.CAESIBYyv******************************qgAQ
```

**Mac**
```bash
export VAULT_ADDR=http://127.0.0.1:8200
export VAULT_TOKEN=hvs.CAESIBYyvDOaW_X*******************************_NqgAQ
```

**테스트**
```bash
# 성공
$ vault read aws/creds/my-role
$ vault lease lookup <lease_id>

# 실패
$ vault secrets list
```

### AppRole 생성

AppRole 인증 메소드를 활성화 합니다.

```bash
vault auth enable approle
```

AppRole에서 애플리케이션이 사용할 Role을 정의합니다.

- secret_id_ttl : secret_id 수명
- secret_id_num_uses : secret_id 사용 횟수
- token_policies : 부여된 Vault 정책

```bash
vault write auth/approle/role/python-app-role secret_id_ttl=10m secret_id_num_uses=3 token_period=0 token_policies=aws-my-role-policy
```

테스트를 위해 다음과 같이 수행합니다.
```
# role_id 획득
vault read auth/approle/role/python-app-role/role-id

# secret_id 획득
vault write -f auth/approle/role/python-app-role/secret-id

# Vault login (token 획득)
# secret_id_num_uses에서 지정된 횟수만큼만 로그인 되는지 확인
# secret_id_ttl에서 지정된 수명 만큼 로그인 되는지 확인
vault write -field=token auth/approle/login role_id=<role_id> secret_id=<secret_id>
```

발급된 토큰을 환경변수로 지정하여 aws 엑세스 키 획득되는지 확인합니다.

## 8. Test APP

- Python 으로 작성되었습니다.
- 코드 내의 다음 정보는 Vault 정보로 수정되어야 합니다.
  - vault_api
  - vault_namespace : enterprise에서 만 사용
  - role_id
  - X-Vault-Namespace : 해당 헤더는 enterprise에서 만 사용
- AWS 엑세스 키를 획득하는 과정은 다음과 같습니다.
  1. AppRole의 role_id는 코드상에 기록
  2. 발급 받은 secret_id를 `secret_id.txt`에 저장
    ```bash
    vault write -f -field=secret_id auth/approle/role/python-app-role/secret-id > ./secret_id.txt
    ```
  3. 코드에서는 `secret_id.txt`의 값을 읽음
  4. 코드에서 Vault에 AppRole 방식으로 로그인
  5. 로그인으로 획득한 Token을 코드 변수로 보관
  6. Token을 사용하여 AWS 엑세스 키와 Lease 정보 획득
  7. Lease를 조회하여 지정된 시간 이하인 경우 다시 AWS 엑세스 키 요청

### 필요 라이브러리 설치

```bash
pip install boto3
pip install requests
```

### 실행

```bash
python main.py
```

### 출력 예시
- aws_key_ttl : AWS Key lease의 남은 시간
- Changed env ... : 변경 시 Key 값
- Available services count : AWS Key로 조회한 정보 값 (끊김 없이 이어져야 함)

```
aws_key_ttl: 59
Changed env AWS_ACCESS_KEY_ID=AKIAU3NXDWRUKQKKER5M
Changed env AWS_SECRET_ACCESS_KEY=ag5irWH******************************yD3nUMm
Available services count : 316
Available services count : 316
aws_key_ttl: 57
Available services count : 316
Available services count : 316
aws_key_ttl: 54
Available services count : 316
Available services count : 316
Available services count : 316
aws_key_ttl: 52
Available services count : 316
Available services count : 316
aws_key_ttl: 50
Available services count : 316
Available services count : 316
aws_key_ttl: 48
Available services count : 316
Available services count : 316
Available services count : 316
Available services count : 316
Available services count : 316
aws_key_ttl: 59
Changed env AWS_ACCESS_KEY_ID=AKIAU3NXDWRUGHAW32TK
Changed env AWS_SECRET_ACCESS_KEY=2ApuxM******************************q3zAwlsf
Available services count : 316
Available services count : 316
aws_key_ttl: 57
Available services count : 316
Available services count : 316
```

### 코드 붙임

```python
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
```