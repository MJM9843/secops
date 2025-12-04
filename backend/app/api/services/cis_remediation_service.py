# File: backend/app/api/services/cis_remediation_service.py

import boto3
from botocore.exceptions import ClientError
from typing import Dict, List, Tuple
from datetime import datetime

class CISRemediationService:
    """Service for applying CIS Benchmark remediations"""
    
    def __init__(self, role_arn: str):
        self.role_arn = role_arn
        self._credentials = None
        self._assume_role()
    
    def _assume_role(self):
        """Assume the IAM role"""
        sts_client = boto3.client('sts')
        response = sts_client.assume_role(
            RoleArn=self.role_arn,
            RoleSessionName='SecOpsCISRemediationSession',
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
    
    def remediate_ebs_default_encryption(self, region: str) -> Dict:
        """Enable EBS default encryption for a region"""
        try:
            ec2 = self._get_client('ec2', region)
            
            current_status = ec2.get_ebs_encryption_by_default()
            
            if current_status['EbsEncryptionByDefault']:
                return {
                    'success': True,
                    'message': f'EBS encryption already enabled in {region}',
                    'already_compliant': True
                }
            
            ec2.enable_ebs_encryption_by_default()
            
            return {
                'success': True,
                'message': f'Successfully enabled EBS default encryption in {region}',
                'already_compliant': False,
                'timestamp': datetime.utcnow().isoformat()
            }
            
        except ClientError as e:
            return {
                'success': False,
                'message': f'Failed to enable EBS encryption: {str(e)}',
                'error': str(e)
            }
    
    def remediate_s3_encryption(self, bucket_name: str) -> Dict:
        """Enable encryption for S3 bucket"""
        try:
            s3 = self._get_client('s3', 'us-east-1')
            
            s3.put_bucket_encryption(
                Bucket=bucket_name,
                ServerSideEncryptionConfiguration={
                    'Rules': [
                        {
                            'ApplyServerSideEncryptionByDefault': {
                                'SSEAlgorithm': 'AES256'
                            },
                            'BucketKeyEnabled': True
                        }
                    ]
                }
            )
            
            return {
                'success': True,
                'message': f'Successfully enabled encryption for bucket {bucket_name}',
                'timestamp': datetime.utcnow().isoformat()
            }
            
        except ClientError as e:
            return {
                'success': False,
                'message': f'Failed to enable S3 encryption: {str(e)}',
                'error': str(e)
            }
    
    def remediate_s3_block_public_access(self, bucket_name: str) -> Dict:
        """Enable S3 Block Public Access for a bucket"""
        try:
            s3 = self._get_client('s3', 'us-east-1')
            
            s3.put_public_access_block(
                Bucket=bucket_name,
                PublicAccessBlockConfiguration={
                    'BlockPublicAcls': True,
                    'IgnorePublicAcls': True,
                    'BlockPublicPolicy': True,
                    'RestrictPublicBuckets': True
                }
            )
            
            return {
                'success': True,
                'message': f'Successfully enabled Block Public Access for bucket {bucket_name}',
                'timestamp': datetime.utcnow().isoformat()
            }
            
        except ClientError as e:
            return {
                'success': False,
                'message': f'Failed to enable Block Public Access: {str(e)}',
                'error': str(e)
            }
    
    def remediate_s3_public_acl(self, bucket_name: str) -> Dict:
        """Make S3 bucket private by removing public ACLs"""
        try:
            s3 = self._get_client('s3', 'us-east-1')
            
            s3.put_bucket_acl(
                Bucket=bucket_name,
                ACL='private'
            )
            
            return {
                'success': True,
                'message': f'Successfully made bucket {bucket_name} private',
                'timestamp': datetime.utcnow().isoformat()
            }
            
        except ClientError as e:
            return {
                'success': False,
                'message': f'Failed to update bucket ACL: {str(e)}',
                'error': str(e)
            }
    
    def remediate_snapshot_public(self, snapshot_id: str, region: str) -> Dict:
        """Make EBS snapshot private"""
        try:
            ec2 = self._get_client('ec2', region)
            
            try:
                snapshots = ec2.describe_snapshots(SnapshotIds=[snapshot_id])
                if not snapshots['Snapshots']:
                    return {
                        'success': False,
                        'message': f'Snapshot {snapshot_id} not found'
                    }
            except ClientError as e:
                if 'InvalidSnapshot.NotFound' in str(e):
                    return {
                        'success': False,
                        'message': f'Snapshot {snapshot_id} does not exist'
                    }
                raise
            
            try:
                perms = ec2.describe_snapshot_attribute(
                    SnapshotId=snapshot_id,
                    Attribute='createVolumePermission'
                )
                
                create_volume_perms = perms.get('CreateVolumePermissions', [])
                is_public = any(perm.get('Group') == 'all' for perm in create_volume_perms)
                
                if not is_public:
                    return {
                        'success': True,
                        'message': f'Snapshot {snapshot_id} is already private',
                        'already_compliant': True
                    }
                
                ec2.modify_snapshot_attribute(
                    SnapshotId=snapshot_id,
                    Attribute='createVolumePermission',
                    OperationType='remove',
                    GroupNames=['all']
                )
                
                return {
                    'success': True,
                    'message': f'Successfully made snapshot {snapshot_id} private',
                    'timestamp': datetime.utcnow().isoformat()
                }
                
            except ClientError as e:
                if e.response['Error']['Code'] == 'InvalidPermission.NotFound':
                    return {
                        'success': True,
                        'message': f'Snapshot {snapshot_id} is already private (no public permissions found)',
                        'already_compliant': True
                    }
                raise
                
        except ClientError as e:
            return {
                'success': False,
                'message': f'Failed to update snapshot permissions: {str(e)}',
                'error': str(e)
            }
        except Exception as e:
            return {
                'success': False,
                'message': f'Unexpected error: {str(e)}',
                'error': str(e)
            }
    
    def remediate_rds_public_access(self, db_instance_id: str, region: str) -> Dict:
        """Disable public accessibility for RDS instance"""
        try:
            rds = self._get_client('rds', region)
            
            rds.modify_db_instance(
                DBInstanceIdentifier=db_instance_id,
                PubliclyAccessible=False,
                ApplyImmediately=True
            )
            
            return {
                'success': True,
                'message': f'Successfully disabled public access for RDS instance {db_instance_id}',
                'note': 'Change will be applied immediately or at next maintenance window',
                'timestamp': datetime.utcnow().isoformat()
            }
            
        except ClientError as e:
            return {
                'success': False,
                'message': f'Failed to update RDS instance: {str(e)}',
                'error': str(e)
            }
    
    def remediate_rds_deletion_protection(self, db_instance_id: str, region: str) -> Dict:
        """Enable deletion protection for RDS instance"""
        try:
            rds = self._get_client('rds', region)
            
            rds.modify_db_instance(
                DBInstanceIdentifier=db_instance_id,
                DeletionProtection=True,
                ApplyImmediately=True
            )
            
            return {
                'success': True,
                'message': f'Successfully enabled deletion protection for RDS instance {db_instance_id}',
                'timestamp': datetime.utcnow().isoformat()
            }
            
        except ClientError as e:
            return {
                'success': False,
                'message': f'Failed to update RDS instance: {str(e)}',
                'error': str(e)
            }
    
    def remediate_ami_not_public(self, ami_id: str, region: str) -> Dict:
        """Make AMI private"""
        try:
            ec2 = self._get_client('ec2', region)
            
            ec2.modify_image_attribute(
                ImageId=ami_id,
                LaunchPermission={
                    'Remove': [{'Group': 'all'}]
                }
            )
            
            return {
                'success': True,
                'message': f'Successfully made AMI {ami_id} private',
                'timestamp': datetime.utcnow().isoformat()
            }
            
        except ClientError as e:
            return {
                'success': False,
                'message': f'Failed to update AMI permissions: {str(e)}',
                'error': str(e)
            }
    
    def remediate_eip_attached(self, allocation_id: str, region: str) -> Dict:
        """Release unattached Elastic IP"""
        try:
            ec2 = self._get_client('ec2', region)
            
            ec2.release_address(AllocationId=allocation_id)
            
            return {
                'success': True,
                'message': f'Successfully released unattached Elastic IP {allocation_id}',
                'timestamp': datetime.utcnow().isoformat()
            }
            
        except ClientError as e:
            return {
                'success': False,
                'message': f'Failed to release Elastic IP: {str(e)}',
                'error': str(e)
            }
    
    def remediate_iam_access_analyzer(self, region: str) -> Dict:
        """Create IAM Access Analyzer"""
        try:
            analyzer = self._get_client('accessanalyzer', region)
            
            analyzer.create_analyzer(
                analyzerName=f'SecOpsAnalyzer-{region}',
                type='ACCOUNT'
            )
            
            return {
                'success': True,
                'message': f'Successfully created IAM Access Analyzer in {region}',
                'timestamp': datetime.utcnow().isoformat()
            }
            
        except ClientError as e:
            if e.response['Error']['Code'] == 'ConflictException':
                return {
                    'success': True,
                    'message': f'IAM Access Analyzer already exists in {region}',
                    'already_compliant': True
                }
            return {
                'success': False,
                'message': f'Failed to create IAM Access Analyzer: {str(e)}',
                'error': str(e)
            }
    
    def remediate_sg_ssh_open(self, security_group_id: str, region: str) -> Dict:
        """Remove SSH access from 0.0.0.0/0 in security group"""
        try:
            ec2 = self._get_client('ec2', region)
            
            response = ec2.describe_security_groups(GroupIds=[security_group_id])
            
            if not response['SecurityGroups']:
                return {
                    'success': False,
                    'message': f'Security group {security_group_id} not found'
                }
            
            sg = response['SecurityGroups'][0]
            rules_removed = 0
            
            for rule in sg.get('IpPermissions', []):
                protocol = rule.get('IpProtocol')
                from_port = rule.get('FromPort')
                to_port = rule.get('ToPort')
                
                if protocol == 'tcp' and from_port == 22 and to_port == 22:
                    for ip_range in rule.get('IpRanges', []):
                        if ip_range.get('CidrIp') == '0.0.0.0/0':
                            try:
                                ec2.revoke_security_group_ingress(
                                    GroupId=security_group_id,
                                    IpPermissions=[{
                                        'IpProtocol': 'tcp',
                                        'FromPort': 22,
                                        'ToPort': 22,
                                        'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                                    }]
                                )
                                rules_removed += 1
                                break
                            except ClientError as e:
                                if 'InvalidPermission.NotFound' not in str(e):
                                    raise
                
                elif protocol == '-1':
                    for ip_range in rule.get('IpRanges', []):
                        if ip_range.get('CidrIp') == '0.0.0.0/0':
                            return {
                                'success': False,
                                'message': f'Security group {security_group_id} has \"all traffic\" rule for 0.0.0.0/0. Please review manually.'
                            }
            
            if rules_removed == 0:
                return {
                    'success': True,
                    'message': f'No open SSH rules found in {security_group_id}',
                    'already_compliant': True
                }
            
            return {
                'success': True,
                'message': f'Successfully removed SSH access from 0.0.0.0/0 in {security_group_id}',
                'timestamp': datetime.utcnow().isoformat()
            }
        
        except ClientError as e:
            return {
                'success': False,
                'message': f'Failed to update security group: {str(e)}',
                'error': str(e)
            }
        except Exception as e:
            return {
                'success': False,
                'message': f'Unexpected error: {str(e)}',
                'error': str(e)
            }

    def remediate_ec2_untagged_instances(self, instance_id: str, region: str) -> Dict:
        """Delete untagged EC2 instances"""
        try:
            ec2 = self._get_client('ec2', region)
            
            try:
                response = ec2.describe_instances(InstanceIds=[instance_id])
                
                if not response['Reservations']:
                    return {
                        'success': False,
                        'message': f'Instance {instance_id} not found'
                    }
                
                instance = response['Reservations'][0]['Instances'][0]
                tags = instance.get('Tags', [])
                state = instance['State']['Name']
                
                if len(tags) > 0:
                    return {
                        'success': True,
                        'message': f'Instance {instance_id} already has tags',
                        'already_compliant': True
                    }
                
                if state == 'terminated':
                    return {
                        'success': True,
                        'message': f'Instance {instance_id} is already terminated',
                        'already_compliant': True
                    }
                
                ec2.terminate_instances(InstanceIds=[instance_id])
                
                return {
                    'success': True,
                    'message': f'Successfully terminated untagged instance {instance_id}',
                    'timestamp': datetime.utcnow().isoformat()
                }
                
            except ClientError as e:
                if 'InvalidInstanceID.NotFound' in str(e):
                    return {
                        'success': False,
                        'message': f'Instance {instance_id} does not exist'
                    }
                raise
                
        except ClientError as e:
            return {
                'success': False,
                'message': f'Failed to terminate instance: {str(e)}',
                'error': str(e)
            }
        except Exception as e:
            return {
                'success': False,
                'message': f'Unexpected error: {str(e)}',
                'error': str(e)
            }
