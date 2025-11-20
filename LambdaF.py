{\rtf1\ansi\ansicpg1252\cocoartf2867
\cocoatextscaling0\cocoaplatform0{\fonttbl\f0\fnil\fcharset0 Menlo-Regular;\f1\fnil\fcharset0 AppleColorEmoji;}
{\colortbl;\red255\green255\blue255;\red157\green0\blue210;\red255\green255\blue255;\red45\green45\blue45;
\red0\green0\blue0;\red144\green1\blue18;\red0\green0\blue255;\red101\green76\blue29;\red0\green0\blue109;
\red32\green108\blue135;\red19\green118\blue70;\red15\green112\blue1;}
{\*\expandedcolortbl;;\cssrgb\c68627\c0\c85882;\cssrgb\c100000\c100000\c100000;\cssrgb\c23137\c23137\c23137;
\cssrgb\c0\c0\c0;\cssrgb\c63922\c8235\c8235;\cssrgb\c0\c0\c100000;\cssrgb\c47451\c36863\c14902;\cssrgb\c0\c6275\c50196;
\cssrgb\c14902\c49804\c60000;\cssrgb\c3529\c52549\c34510;\cssrgb\c0\c50196\c0;}
\margl1440\margr1440\vieww37860\viewh17400\viewkind0
\deftab720
\pard\pardeftab720\partightenfactor0

\f0\fs24 \cf2 \cb3 \expnd0\expndtw0\kerning0
import\cf4  boto3\cb1 \
\cf2 \cb3 import\cf4  json\cb1 \
\cf2 \cb3 import\cf4  os\cb1 \
\
\cb3 s3_client = boto3.client(\cf6 "s3"\cf4 )\cb1 \
\cb3 ec2 = boto3.client(\cf6 "ec2"\cf4 )\cb1 \
\cb3 sns = boto3.client(\cf6 "sns"\cf4 )\cb1 \
\
\cb3 EVIDENCE_BUCKET = os.environ[\cf6 "EVIDENCE_BUCKET"\cf4 ]\cb1 \
\cb3 SNS_TOPIC_ARN = os.environ[\cf6 "SNS_TOPIC_ARN"\cf4 ]\cb1 \
\
\
\pard\pardeftab720\partightenfactor0
\cf7 \cb3 def\cf4  \cf8 send_sns\cf4 (\cf9 message\cf4 ):\cb1 \
\pard\pardeftab720\partightenfactor0
\cf4 \cb3     \cf6 """Send formatted SNS alert."""\cf4 \cb1 \
\cb3     sns.publish(\cb1 \
\cb3         \cf9 TopicArn\cf4 =SNS_TOPIC_ARN,\cb1 \
\cb3         \cf9 Subject\cf4 =\cf6 "AWS Auto-Remediation Alert"\cf4 ,\cb1 \
\cb3         \cf9 Message\cf4 =message\cb1 \
\cb3     )\cb1 \
\
\
\pard\pardeftab720\partightenfactor0
\cf7 \cb3 def\cf4  \cf8 delete_bucket_if_exists\cf4 (\cf9 bucket_name\cf4 ):\cb1 \
\pard\pardeftab720\partightenfactor0
\cf4 \cb3     \cf6 """Delete bucket only if it exists to avoid NoSuchBucket errors."""\cf4 \cb1 \
\cb3     \cf2 try\cf4 :\cb1 \
\cb3         s3_client.head_bucket(\cf9 Bucket\cf4 =bucket_name)\cb1 \
\cb3     \cf2 except\cf4  \cf10 Exception\cf4 :\cb1 \
\cb3         \cf8 print\cf4 (\cf7 f\cf6 "[INFO] Bucket \cf7 \{\cf4 bucket_name\cf7 \}\cf6  does not exist, skipping deletion."\cf4 )\cb1 \
\cb3         \cf2 return\cf4  \cf7 False\cf4 \cb1 \
\
\cb3     \cf2 try\cf4 :\cb1 \
\cb3         \cf8 print\cf4 (\cf7 f\cf6 "[ACTION] Deleting bucket \cf7 \{\cf4 bucket_name\cf7 \}\cf6  ..."\cf4 )\cb1 \
\cb3         s3_client.delete_bucket(\cf9 Bucket\cf4 =bucket_name)\cb1 \
\cb3         send_sns(\cf7 f\cf6 "Bucket '\cf7 \{\cf4 bucket_name\cf7 \}\cf6 ' deleted as part of auto-remediation."\cf4 )\cb1 \
\cb3         \cf2 return\cf4  \cf7 True\cf4 \cb1 \
\cb3     \cf2 except\cf4  \cf10 Exception\cf4  \cf2 as\cf4  e:\cb1 \
\cb3         \cf8 print\cf4 (\cf7 f\cf6 "[ERROR] Unable to delete bucket \cf7 \{\cf4 bucket_name\cf7 \}\cf6 : \cf7 \{\cf10 str\cf4 (e)\cf7 \}\cf6 "\cf4 )\cb1 \
\cb3         \cf2 return\cf4  \cf7 False\cf4 \cb1 \
\
\
\pard\pardeftab720\partightenfactor0
\cf7 \cb3 def\cf4  \cf8 remediate_security_group\cf4 (\cf9 sg_id\cf4 ):\cb1 \
\pard\pardeftab720\partightenfactor0
\cf4 \cb3     \cf6 """Remove insecure 0.0.0.0/0 SSH rule from SG."""\cf4 \cb1 \
\cb3     \cf2 try\cf4 :\cb1 \
\cb3         sg = ec2.describe_security_groups(\cf9 GroupIds\cf4 =[sg_id])[\cf6 "SecurityGroups"\cf4 ][\cf11 0\cf4 ]\cb1 \
\
\cb3         insecure_permissions = []\cb1 \
\
\cb3         \cf2 for\cf4  perm \cf2 in\cf4  sg.get(\cf6 "IpPermissions"\cf4 , []):\cb1 \
\cb3             \cf2 if\cf4  (\cb1 \
\cb3                 perm.get(\cf6 "IpProtocol"\cf4 ) == \cf6 "tcp"\cf4 \cb1 \
\cb3                 \cf7 and\cf4  perm.get(\cf6 "FromPort"\cf4 ) == \cf11 22\cf4 \cb1 \
\cb3                 \cf7 and\cf4  perm.get(\cf6 "ToPort"\cf4 ) == \cf11 22\cf4 \cb1 \
\cb3             ):\cb1 \
\cb3                 \cf2 for\cf4  ip_range \cf2 in\cf4  perm.get(\cf6 "IpRanges"\cf4 , []):\cb1 \
\cb3                     \cf2 if\cf4  ip_range.get(\cf6 "CidrIp"\cf4 ) == \cf6 "0.0.0.0/0"\cf4 :\cb1 \
\cb3                         insecure_permissions.append(\cb1 \
\cb3                             \{\cb1 \
\cb3                                 \cf6 "IpProtocol"\cf4 : \cf6 "tcp"\cf4 ,\cb1 \
\cb3                                 \cf6 "FromPort"\cf4 : \cf11 22\cf4 ,\cb1 \
\cb3                                 \cf6 "ToPort"\cf4 : \cf11 22\cf4 ,\cb1 \
\cb3                                 \cf6 "IpRanges"\cf4 : [\{\cf6 "CidrIp"\cf4 : \cf6 "0.0.0.0/0"\cf4 \}],\cb1 \
\cb3                             \}\cb1 \
\cb3                         )\cb1 \
\
\cb3         \cf2 if\cf4  insecure_permissions:\cb1 \
\cb3             \cf8 print\cf4 (\cf7 f\cf6 "[ACTION] Removing insecure SSH rule from SG \cf7 \{\cf4 sg_id\cf7 \}\cf6 "\cf4 )\cb1 \
\
\cb3             ec2.revoke_security_group_ingress(\cb1 \
\cb3                 \cf9 GroupId\cf4 =sg_id,\cb1 \
\cb3                 \cf9 IpPermissions\cf4 =insecure_permissions\cb1 \
\cb3             )\cb1 \
\
\cb3             send_sns(\cb1 \
\cb3                 \cf7 f\cf6 "Insecure SSH rule (22/0.0.0.0/0) removed from SG '\cf7 \{\cf4 sg_id\cf7 \}\cf6 '."\cf4 \cb1 \
\cb3             )\cb1 \
\cb3             \cf2 return\cf4  \cf7 True\cf4 \cb1 \
\
\cb3         \cf8 print\cf4 (\cf7 f\cf6 "[INFO] No insecure SSH rule found in SG \cf7 \{\cf4 sg_id\cf7 \}\cf6 ."\cf4 )\cb1 \
\cb3         \cf2 return\cf4  \cf7 False\cf4 \cb1 \
\
\cb3     \cf2 except\cf4  \cf10 Exception\cf4  \cf2 as\cf4  e:\cb1 \
\cb3         \cf8 print\cf4 (\cf7 f\cf6 "[ERROR] Failed to remediate SG \cf7 \{\cf4 sg_id\cf7 \}\cf6 : \cf7 \{\cf10 str\cf4 (e)\cf7 \}\cf6 "\cf4 )\cb1 \
\cb3         \cf2 return\cf4  \cf7 False\cf4 \cb1 \
\
\
\pard\pardeftab720\partightenfactor0
\cf7 \cb3 def\cf4  \cf8 lambda_handler\cf4 (\cf9 event\cf4 , \cf9 context\cf4 ):\cb1 \
\pard\pardeftab720\partightenfactor0
\cf4 \cb3     \cf8 print\cf4 (\cf6 "Received event:"\cf4 )\cb1 \
\cb3     \cf8 print\cf4 (json.dumps(event, \cf9 indent\cf4 =\cf11 4\cf4 ))\cb1 \
\
\cb3     \cf12 # Detect bucket creation events\cf4 \cb1 \
\cb3     detail = event.get(\cf6 "detail"\cf4 , \{\})\cb1 \
\cb3     event_name = detail.get(\cf6 "eventName"\cf4 , \cf6 ""\cf4 )\cb1 \
\cb3     params = detail.get(\cf6 "requestParameters"\cf4 , \{\})\cb1 \
\
\cb3     \cf12 # 
\f1 1\uc0\u65039 \u8419 
\f0  Handle S3 CreateBucket remediation\cf4 \cb1 \
\cb3     \cf2 if\cf4  event_name == \cf6 "CreateBucket"\cf4 :\cb1 \
\cb3         bucket_name = params.get(\cf6 "bucketName"\cf4 )\cb1 \
\
\cb3         \cf8 print\cf4 (\cf7 f\cf6 "[INFO] Detected CreateBucket event: \cf7 \{\cf4 bucket_name\cf7 \}\cf6 "\cf4 )\cb1 \
\
\cb3         \cf2 if\cf4  bucket_name:\cb1 \
\cb3             delete_bucket_if_exists(bucket_name)\cb1 \
\
\cb3     \cf12 # 
\f1 2\uc0\u65039 \u8419 
\f0  Handle Security Group ingress authorization\cf4 \cb1 \
\cb3     \cf2 if\cf4  event_name == \cf6 "AuthorizeSecurityGroupIngress"\cf4 :\cb1 \
\cb3         sg_id = params.get(\cf6 "groupId"\cf4 )\cb1 \
\
\cb3         \cf8 print\cf4 (\cf7 f\cf6 "[INFO] Detected SG ingress modification on: \cf7 \{\cf4 sg_id\cf7 \}\cf6 "\cf4 )\cb1 \
\
\cb3         \cf2 if\cf4  sg_id:\cb1 \
\cb3             remediate_security_group(sg_id)\cb1 \
\
\cb3     \cf8 print\cf4 (\cf6 "[INFO] Lambda execution finished."\cf4 )\cb1 \
\cb3     \cf2 return\cf4  \{\cf6 "status"\cf4 : \cf6 "ok"\cf4 \}\cb1 \
\
}
