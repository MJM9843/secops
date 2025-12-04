# File: backend/app/api/services/cis_service.py

import boto3
from botocore.exceptions import ClientError
from typing import Dict, List, Tuple
from datetime import datetime

class CISBenchmarkService:
    """Service for CIS Benchmark compliance checking and remediation"""
    
    def __init__(self, role_arn: str):
        self.role_arn = role_arn
        self._credentials = None
        self._assume_role()
    
    def _assume_role(self):
        """Assume the IAM role"""
        sts_client = boto3.client('sts')
        response = sts_client.assume_role(
            RoleArn=self.role_arn,
            RoleSessionName='SecOpsCISSession',
            DurationSeconds=3600
        )
        self._credentials = response['Credentials']
    
    def _get_client(self, service_name: str, region: str):
        """Get boto3 client with assumed credentials"""
        return boto3.client(
            service_name,
            region_name=region,
            aws_access_key_id=self._credentials['AccessKeyId'],
            aws_secret_access_key=self._credentials['SecretAccessKey'],
            aws_session_token=self._credentials['SessionToken']
        )
    
    # EC2 Checks
    def check_ec2_iam_role(self, region: str) -> Tuple[int, int, List[Dict]]:
        """Check if EC2 instances use IAM roles"""
        try:
            ec2 = self._get_client('ec2', region)
            response = ec2.describe_instances()
            
            total = 0
            passed = 0
            failed_resources = []
            
            for reservation in response['Reservations']:
                for instance in reservation['Instances']:
                    if instance['State']['Name'] != 'terminated':
                        total += 1
                        if 'IamInstanceProfile' in instance:
                            passed += 1
                        else:
                            failed_resources.append({
                                'resource_id': instance['InstanceId'],
                                'resource_type': 'EC2 Instance',
                                'reason': 'No IAM role attached',
                                'region': region
                            })
            
            return passed, total - passed, failed_resources
        except Exception as e:
            return 0, 0, []
    
    def check_ebs_default_encryption(self, region: str) -> Tuple[int, int, List[Dict]]:
        """Check if EBS default encryption is enabled"""
        try:
            ec2 = self._get_client('ec2', region)
            response = ec2.get_ebs_encryption_by_default()
            
            if response['EbsEncryptionByDefault']:
                return 1, 0, []
            else:
                return 0, 1, [{
                    'resource_id': f'account-{region}',
                    'resource_type': 'Account Setting',
                    'reason': 'EBS default encryption not enabled',
                    'region': region
                }]
        except Exception:
            return 0, 1, []
    
    def check_ec2_untagged_instances(self, region: str) -> Tuple[int, int, List[Dict]]:
        """Check for EC2 instances without any tags"""
        try:
            ec2 = self._get_client('ec2', region)
            response = ec2.describe_instances(
                Filters=[
                    {
                        'Name': 'instance-state-name',
                        'Values': ['running', 'stopped']
                    }
                ]
            )
            
            total = 0
            passed = 0
            failed_resources = []
            
            for reservation in response['Reservations']:
                for instance in reservation['Instances']:
                    total += 1
                    instance_id = instance['InstanceId']
                    tags = instance.get('Tags', [])
                    
                    if len(tags) == 0:
                        failed_resources.append({
                            'resource_id': instance_id,
                            'resource_type': 'EC2 Instance',
                            'reason': 'No tags attached to instance',
                            'region': region
                        })
                    else:
                        passed += 1
            
            return passed, total - passed, failed_resources
        except Exception as e:
            return 0, 0, []
    
    # S3 Checks
    def check_s3_encryption(self, region: str) -> Tuple[int, int, List[Dict]]:
        """Check if S3 buckets have encryption enabled"""
        try:
            s3 = self._get_client('s3', 'us-east-1')
            buckets_response = s3.list_buckets()
            
            total = len(buckets_response['Buckets'])
            passed = 0
            failed_resources = []
            
            for bucket in buckets_response['Buckets']:
                bucket_name = bucket['Name']
                try:
                    s3.get_bucket_encryption(Bucket=bucket_name)
                    passed += 1
                except ClientError as e:
                    if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                        failed_resources.append({
                            'resource_id': bucket_name,
                            'resource_type': 'S3 Bucket',
                            'reason': 'Encryption not configured',
                            'region': 'us-east-1'
                        })
            
            return passed, total - passed, failed_resources
        except Exception:
            return 0, 0, []
    
    def check_s3_block_public_access(self, region: str) -> Tuple[int, int, List[Dict]]:
        """Check if S3 buckets have block public access enabled"""
        try:
            s3 = self._get_client('s3', 'us-east-1')
            buckets_response = s3.list_buckets()
            
            total = len(buckets_response['Buckets'])
            passed = 0
            failed_resources = []
            
            for bucket in buckets_response['Buckets']:
                bucket_name = bucket['Name']
                try:
                    response = s3.get_public_access_block(Bucket=bucket_name)
                    config = response['PublicAccessBlockConfiguration']
                    
                    if (config.get('BlockPublicAcls') and 
                        config.get('IgnorePublicAcls') and
                        config.get('BlockPublicPolicy') and
                        config.get('RestrictPublicBuckets')):
                        passed += 1
                    else:
                        failed_resources.append({
                            'resource_id': bucket_name,
                            'resource_type': 'S3 Bucket',
                            'reason': 'Block public access not fully enabled',
                            'region': 'us-east-1'
                        })
                except ClientError:
                    failed_resources.append({
                        'resource_id': bucket_name,
                        'resource_type': 'S3 Bucket',
                        'reason': 'No public access block configuration',
                        'region': 'us-east-1'
                    })
            
            return passed, total - passed, failed_resources
        except Exception:
            return 0, 0, []
    
    def check_s3_public_acl(self, region: str) -> Tuple[int, int, List[Dict]]:
        """Check if S3 buckets are public via ACL"""
        try:
            s3 = self._get_client('s3', 'us-east-1')
            buckets_response = s3.list_buckets()
            
            total = len(buckets_response['Buckets'])
            passed = 0
            failed_resources = []
            
            for bucket in buckets_response['Buckets']:
                bucket_name = bucket['Name']
                try:
                    acl = s3.get_bucket_acl(Bucket=bucket_name)
                    is_public = False
                    
                    for grant in acl['Grants']:
                        grantee = grant.get('Grantee', {})
                        if grantee.get('Type') == 'Group' and 'AllUsers' in grantee.get('URI', ''):
                            is_public = True
                            break
                    
                    if not is_public:
                        passed += 1
                    else:
                        failed_resources.append({
                            'resource_id': bucket_name,
                            'resource_type': 'S3 Bucket',
                            'reason': 'Bucket is public via ACL',
                            'region': 'us-east-1'
                        })
                except Exception:
                    passed += 1
            
            return passed, total - passed, failed_resources
        except Exception:
            return 0, 0, []
    
    # Snapshot Checks
    def check_snapshot_encryption(self, region: str) -> Tuple[int, int, List[Dict]]:
        """Check if EBS snapshots are encrypted"""
        try:
            ec2 = self._get_client('ec2', region)
            response = ec2.describe_snapshots(OwnerIds=['self'])
            
            total = len(response['Snapshots'])
            passed = 0
            failed_resources = []
            
            for snapshot in response['Snapshots']:
                if snapshot['Encrypted']:
                    passed += 1
                else:
                    failed_resources.append({
                        'resource_id': snapshot['SnapshotId'],
                        'resource_type': 'EBS Snapshot',
                        'reason': 'Snapshot not encrypted',
                        'region': region
                    })
            
            return passed, total - passed, failed_resources
        except Exception as e:
            return 0, 0, []
    
    def check_snapshot_public(self, region: str) -> Tuple[int, int, List[Dict]]:
        """Check if snapshots are public"""
        try:
            ec2 = self._get_client('ec2', region)
            response = ec2.describe_snapshots(OwnerIds=['self'])
            
            total = len(response['Snapshots'])
            passed = 0
            failed_resources = []
            
            for snapshot in response['Snapshots']:
                try:
                    perms = ec2.describe_snapshot_attribute(
                        SnapshotId=snapshot['SnapshotId'],
                        Attribute='createVolumePermission'
                    )
                    
                    is_public = False
                    for perm in perms.get('CreateVolumePermissions', []):
                        if perm.get('Group') == 'all':
                            is_public = True
                            break
                    
                    if not is_public:
                        passed += 1
                    else:
                        failed_resources.append({
                            'resource_id': snapshot['SnapshotId'],
                            'resource_type': 'EBS Snapshot',
                            'reason': 'Snapshot is public',
                            'region': region
                        })
                except Exception:
                    passed += 1
            
            return passed, total - passed, failed_resources
        except Exception as e:
            return 0, 0, []
    
    # Security Group Checks
    def check_sg_ssh_open(self, region: str) -> Tuple[int, int, List[Dict]]:
        """Check if SSH is open to 0.0.0.0/0"""
        try:
            ec2 = self._get_client('ec2', region)
            response = ec2.describe_security_groups()
            
            total = len(response['SecurityGroups'])
            passed = 0
            failed_resources = []
            
            for sg in response['SecurityGroups']:
                has_open_ssh = False
                
                for rule in sg.get('IpPermissions', []):
                    if rule.get('IpProtocol') == 'tcp' and rule.get('FromPort') == 22:
                        for ip_range in rule.get('IpRanges', []):
                            if ip_range.get('CidrIp') == '0.0.0.0/0':
                                has_open_ssh = True
                                break
                
                if not has_open_ssh:
                    passed += 1
                else:
                    failed_resources.append({
                        'resource_id': sg['GroupId'],
                        'resource_type': 'Security Group',
                        'reason': 'SSH open to 0.0.0.0/0',
                        'region': region
                    })
            
            return passed, total - passed, failed_resources
        except Exception as e:
            return 0, 0, []
    
    def check_sg_outbound_unrestricted(self, region: str) -> Tuple[int, int, List[Dict]]:
        """Check if outbound traffic is unrestricted"""
        try:
            ec2 = self._get_client('ec2', region)
            response = ec2.describe_security_groups()
            
            total = len(response['SecurityGroups'])
            passed = 0
            failed_resources = []
            
            for sg in response['SecurityGroups']:
                is_unrestricted = False
                
                for rule in sg.get('IpPermissionsEgress', []):
                    if rule.get('IpProtocol') == '-1':
                        for ip_range in rule.get('IpRanges', []):
                            if ip_range.get('CidrIp') == '0.0.0.0/0':
                                is_unrestricted = True
                                break
                
                if not is_unrestricted:
                    passed += 1
                else:
                    failed_resources.append({
                        'resource_id': sg['GroupId'],
                        'resource_type': 'Security Group',
                        'reason': 'Unrestricted outbound traffic',
                        'region': region
                    })
            
            return passed, total - passed, failed_resources
        except Exception as e:
            return 0, 0, []
    
    # IAM Checks
    def check_iam_root_mfa(self, region: str) -> Tuple[int, int, List[Dict]]:
        """Check if root account has MFA enabled"""
        try:
            iam = self._get_client('iam', 'us-east-1')
            response = iam.get_account_summary()
            
            account_mfa_enabled = response['SummaryMap'].get('AccountMFAEnabled', 0)
            
            if account_mfa_enabled:
                return 1, 0, []
            else:
                return 0, 1, [{
                    'resource_id': 'root-account',
                    'resource_type': 'IAM Root Account',
                    'reason': 'MFA not enabled for root',
                    'region': 'global'
                }]
        except Exception:
            return 0, 1, []
    
    def check_iam_access_analyzer(self, region: str) -> Tuple[int, int, List[Dict]]:
        """Check if IAM Access Analyzer is enabled"""
        try:
            analyzer = self._get_client('accessanalyzer', region)
            response = analyzer.list_analyzers()
            
            if len(response['analyzers']) > 0:
                return 1, 0, []
            else:
                return 0, 1, [{
                    'resource_id': f'account-{region}',
                    'resource_type': 'IAM Access Analyzer',
                    'reason': 'Access Analyzer not enabled',
                    'region': region
                }]
        except Exception:
            return 0, 1, []
    
    # RDS Checks
    def check_rds_encryption(self, region: str) -> Tuple[int, int, List[Dict]]:
        """Check if RDS instances are encrypted"""
        try:
            rds = self._get_client('rds', region)
            response = rds.describe_db_instances()
            
            total = len(response['DBInstances'])
            passed = 0
            failed_resources = []
            
            for db in response['DBInstances']:
                if db.get('StorageEncrypted', False):
                    passed += 1
                else:
                    failed_resources.append({
                        'resource_id': db['DBInstanceIdentifier'],
                        'resource_type': 'RDS Instance',
                        'reason': 'Storage not encrypted',
                        'region': region
                    })
            
            return passed, total - passed, failed_resources
        except Exception:
            return 0, 0, []
    
    def check_rds_public_access(self, region: str) -> Tuple[int, int, List[Dict]]:
        """Check if RDS instances have public access disabled"""
        try:
            rds = self._get_client('rds', region)
            response = rds.describe_db_instances()
            
            total = len(response['DBInstances'])
            passed = 0
            failed_resources = []
            
            for db in response['DBInstances']:
                if not db.get('PubliclyAccessible', False):
                    passed += 1
                else:
                    failed_resources.append({
                        'resource_id': db['DBInstanceIdentifier'],
                        'resource_type': 'RDS Instance',
                        'reason': 'Publicly accessible',
                        'region': region
                    })
            
            return passed, total - passed, failed_resources
        except Exception:
            return 0, 0, []
    
    def check_rds_deletion_protection(self, region: str) -> Tuple[int, int, List[Dict]]:
        """Check if RDS instances have deletion protection enabled"""
        try:
            rds = self._get_client('rds', region)
            response = rds.describe_db_instances()
            
            total = len(response['DBInstances'])
            passed = 0
            failed_resources = []
            
            for db in response['DBInstances']:
                if db.get('DeletionProtection', False):
                    passed += 1
                else:
                    failed_resources.append({
                        'resource_id': db['DBInstanceIdentifier'],
                        'resource_type': 'RDS Instance',
                        'reason': 'Deletion protection not enabled',
                        'region': region
                    })
            
            return passed, total - passed, failed_resources
        except Exception:
            return 0, 0, []
    
    # AMI Checks
    def check_ami_not_public(self, region: str) -> Tuple[int, int, List[Dict]]:
        """Check if AMI images are not public"""
        try:
            ec2 = self._get_client('ec2', region)
            response = ec2.describe_images(Owners=['self'])
            
            total = len(response['Images'])
            passed = 0
            failed_resources = []
            
            for image in response['Images']:
                if not image.get('Public', False):
                    passed += 1
                else:
                    failed_resources.append({
                        'resource_id': image['ImageId'],
                        'resource_type': 'AMI',
                        'reason': 'AMI is public',
                        'region': region
                    })
            
            return passed, total - passed, failed_resources
        except Exception:
            return 0, 0, []
    
    # Volume Checks
    def check_volume_encryption(self, region: str) -> Tuple[int, int, List[Dict]]:
        """Check if all EBS volumes are encrypted"""
        try:
            ec2 = self._get_client('ec2', region)
            response = ec2.describe_volumes()
            
            total = len(response['Volumes'])
            passed = 0
            failed_resources = []
            
            for volume in response['Volumes']:
                if volume.get('Encrypted', False):
                    passed += 1
                else:
                    failed_resources.append({
                        'resource_id': volume['VolumeId'],
                        'resource_type': 'EBS Volume',
                        'reason': 'Volume not encrypted',
                        'region': region
                    })
            
            return passed, total - passed, failed_resources
        except Exception:
            return 0, 0, []
    
    def check_volume_orphaned(self, region: str) -> Tuple[int, int, List[Dict]]:
        """Check for orphaned (unattached) volumes"""
        try:
            ec2 = self._get_client('ec2', region)
            response = ec2.describe_volumes()
            
            total = len(response['Volumes'])
            passed = 0
            failed_resources = []
            
            for volume in response['Volumes']:
                if len(volume.get('Attachments', [])) > 0:
                    passed += 1
                else:
                    failed_resources.append({
                        'resource_id': volume['VolumeId'],
                        'resource_type': 'EBS Volume',
                        'reason': 'Volume is orphaned (not attached)',
                        'region': region
                    })
            
            return passed, total - passed, failed_resources
        except Exception:
            return 0, 0, []
    
    # Elastic IP Checks
    def check_eip_attached(self, region: str) -> Tuple[int, int, List[Dict]]:
        """Check if Elastic IPs are attached"""
        try:
            ec2 = self._get_client('ec2', region)
            response = ec2.describe_addresses()
            
            total = len(response['Addresses'])
            passed = 0
            failed_resources = []
            
            for address in response['Addresses']:
                if 'InstanceId' in address or 'NetworkInterfaceId' in address:
                    passed += 1
                else:
                    failed_resources.append({
                        'resource_id': address.get('AllocationId', address.get('PublicIp')),
                        'resource_type': 'Elastic IP',
                        'reason': 'EIP not attached',
                        'region': region
                    })
            
            return passed, total - passed, failed_resources
        except Exception:
            return 0, 0, []
